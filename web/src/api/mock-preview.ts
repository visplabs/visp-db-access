// Write previews for the mock API. The server runs the write and rolls it
// back; the mock makes up plausible rows from the statement instead, with the
// same shape, the same masking rules and the same texts.
import type {
  Cluster,
  Policy,
  Preview,
  RowSample,
  StatementKind,
} from './types';
import { demoSchema, uuid } from './fixtures';

/** Rows shown in a preview at most, before and after. */
const SAMPLE_ROWS = 20;
const HIDDEN = '••••••';
export const MYSQL_REASON =
  'Writes on MySQL are not previewed. The approval is bound to nothing.';
const NOTE_COUNT_ONLY =
  'This statement is previewed by its row count only: it is not a single plain INSERT, UPDATE or DELETE.';
const NOTE_RETURNING =
  'The new values are not shown: the statement has its own RETURNING clause.';
const NOTE_HIDDEN =
  'Some new values are not shown: they are protected, or computed from a protected column or another query.';

/** Functions that PostgreSQL itself defines; any other call is the database's own. */
const BUILT_IN = new Set([
  'now',
  'lower',
  'upper',
  'trim',
  'coalesce',
  'nullif',
  'greatest',
  'least',
  'length',
  'concat',
  'round',
  'abs',
  'current_timestamp',
  'gen_random_uuid',
  'jsonb_set',
  'to_jsonb',
]);
const KEYWORDS = new Set(['in', 'values', 'exists', 'any', 'all', 'into']);

/** Strip comments, and blank out string literals so that the code can be searched. */
const code = (sql: string) =>
  sql
    .replace(/--[^\n]*|\/\*[\s\S]*?\*\//g, ' ')
    .replace(/'(?:''|[^'])*'/g, (token) => `'${' '.repeat(token.length - 2)}'`);

/** The database's own functions a statement calls, as `name(argument types)`. */
export function databaseFunctions(sql: string): string[] {
  const found = new Set<string>();
  for (const match of code(sql).matchAll(/\b([a-z_][\w.]*)\s*\(/gi)) {
    const name = (match[1] ?? '').toLowerCase();
    const bare = name.split('.').pop() ?? name;
    if (BUILT_IN.has(bare) || KEYWORDS.has(bare)) continue;
    if (isTable(bare)) continue;
    found.add(`${bare}(numeric)`);
  }
  return [...found];
}

type ColumnInfo = { name: string; type: string };
const tables = new Map<string, ColumnInfo[]>(
  demoSchema.schemas.flatMap((schema) =>
    schema.tables.map(
      (table) =>
        [
          table.name,
          table.columns.map((column) => ({
            name: column.name,
            type: column.data_type,
          })),
        ] as const,
    ),
  ),
);
const isTable = (name: string) => tables.has(name);

/** A policy pattern (`email`, `*.password*`, `users.ssn`) against a column. */
function protectedColumn(patterns: string[], table: string, column: string) {
  const glob = (pattern: string, text: string) =>
    new RegExp(
      `^${pattern
        .toLowerCase()
        .split('*')
        .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
        .join('.*')}$`,
    ).test(text.toLowerCase());
  return patterns.some((pattern) =>
    pattern.includes('.')
      ? glob(pattern, `${table}.${column}`)
      : glob(pattern, column),
  );
}

const names = [
  'Maya Patel',
  'Oliver Davis',
  'Sofia Torres',
  'Noah Williams',
  'Ava Thompson',
  'Liam Chen',
];
/** A made-up value of a column, the same for the same row. */
function value(column: ColumnInfo, row: number, key: unknown): unknown {
  if (column.name === 'id') return key ?? uuid(2000 + row);
  if (column.name === 'name') return names[row % names.length];
  if (column.name === 'email') return `user${row + 1}@example.com`;
  if (column.name === 'status') return row % 3 === 2 ? 'paused' : 'active';
  if (column.name === 'user_id') return uuid(2000 + row);
  if (column.name === 'total') return Number((24.5 + row * 7.25).toFixed(2));
  if (column.type === 'jsonb') return { plan: row % 2 ? 'pro' : 'team' };
  if (/timestamp/.test(column.type))
    return new Date(Date.UTC(2026, 9, 1 + row, 9, 30)).toISOString();
  if (column.type === 'numeric') return 100 + row;
  return `value ${row + 1}`;
}

/** A literal as the database would return it; undefined when it is not one. */
function literal(text: string): { value: unknown } | undefined {
  const trimmed = text.trim();
  if (/^'(?:''|[^'])*'$/.test(trimmed))
    return { value: trimmed.slice(1, -1).replace(/''/g, "'") };
  if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) return { value: Number(trimmed) };
  if (/^null$/i.test(trimmed)) return { value: null };
  if (/^(true|false)$/i.test(trimmed))
    return { value: trimmed.toLowerCase() === 'true' };
  if (/^(now\(\)|current_timestamp)$/i.test(trimmed))
    return { value: new Date().toISOString() };
  return undefined;
}

/** A column name as PostgreSQL stores it: unquoted folds to lower case. */
function columnName(text: string): string {
  const name = text.trim();
  return /^".*"$/.test(name) ? name.slice(1, -1) : name.toLowerCase();
}

/** Split on top-level commas, outside quotes and parentheses. */
function split(text: string): string[] {
  const parts: string[] = [];
  let depth = 0,
    quoted = false,
    start = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (c === "'") quoted = !quoted;
    else if (!quoted && c === '(') depth += 1;
    else if (!quoted && c === ')') depth -= 1;
    else if (!quoted && depth === 0 && c === ',') {
      parts.push(text.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(text.slice(start));
  return parts.map((part) => part.trim()).filter(Boolean);
}

/** The keys a condition names: `id = 42` or `id IN (a, b)`. */
function keys(where: string): unknown[] | undefined {
  const single = /\bid\s*=\s*('(?:''|[^'])*'|-?\d+)/i.exec(where);
  if (single) return [literal(single[1] ?? '')?.value];
  const list = /\bid\s+in\s*\(([^)]*)\)/i.exec(where);
  if (list)
    return split(list[1] ?? '').map((item) => literal(item)?.value ?? item);
  return undefined;
}

function sample(
  table: string,
  columns: ColumnInfo[],
  rows: unknown[][],
  total: number,
  patterns: string[],
  alsoHidden: (column: string) => boolean = () => false,
): RowSample {
  const hidden = columns
    .filter(
      (column) =>
        protectedColumn(patterns, table, column.name) ||
        alsoHidden(column.name),
    )
    .map((column) => column.name);
  return {
    columns: columns.map((column) => column.name),
    hidden,
    masked: columns
      .filter((column) => protectedColumn(patterns, table, column.name))
      .map((column) => column.name),
    rows: rows
      .slice(0, SAMPLE_ROWS)
      .map((row) =>
        row.map((cell, index) =>
          hidden.includes(columns[index]?.name ?? '') ? HIDDEN : cell,
        ),
      ),
    total,
  };
}

/**
 * The preview of a write. `rows` sets how many rows a statement without a
 * key in its condition changes (the server counts them; the mock picks).
 */
export function previewWrite(
  sql: string,
  cluster: Cluster,
  policy: Policy,
  rows = 3,
): Preview {
  if (cluster.engine !== 'postgres')
    return { supported: false, reason: MYSQL_REASON, notes: [] };
  const text = sql.trim().replace(/;\s*$/, '');
  const searchable = code(text);
  const kind = (
    /^\s*(insert|update|delete)\b/i.exec(searchable)?.[1] ?? ''
  ).toLowerCase() as StatementKind | '';
  const plain = kind && !/;|\bon\s+conflict\b|\bonly\b/i.test(searchable);
  // Its own RETURNING leaves no sample of the new rows; a note says why.
  const returning = /\breturning\b/i.test(searchable);
  if (!plain)
    return {
      supported: true,
      affected_rows: rows,
      bound_to: 'count',
      notes: [NOTE_COUNT_ONLY],
    };
  const patterns = policy.masked_columns;
  if (kind === 'insert') {
    const match =
      /^insert\s+into\s+([\w."]+)\s*(?:\(([^)]*)\))?\s*values\s*([\s\S]*?)(?:\s+returning\s+[\s\S]*)?$/i.exec(
        text,
      );
    const table = (match?.[1] ?? '').split('.').pop()?.replace(/"/g, '') ?? '';
    const known = tables.get(table) ?? [];
    const named = match?.[2]
      ? split(match[2])
          .map(columnName)
          .map(
            (name) =>
              known.find((column) => column.name === name) ?? {
                name,
                type: 'text',
              },
          )
      : known;
    const tuples = match?.[3]
      ? (match[3].match(/\((?:'(?:''|[^'])*'|[^()'])*\)/g) ?? [])
      : [];
    const opaque = new Set<string>();
    // Without a column list the server does not know which value goes where,
    // so every new value is hidden.
    if (!match?.[2]) named.forEach((column) => opaque.add(column.name));
    const written = tuples.map((tuple) =>
      split(tuple.slice(1, -1)).map((item, index) => {
        const parsed = literal(item);
        if (!parsed) opaque.add(named[index]?.name ?? '');
        return parsed ? parsed.value : null;
      }),
    );
    const after = sample(
      table,
      named,
      written,
      written.length || rows,
      patterns,
      (column) => opaque.has(column),
    );
    return {
      supported: true,
      kind: 'insert',
      target: table,
      affected_rows: written.length || rows,
      ...(returning ? {} : { after }),
      bound_to: 'count',
      ...(match?.[2] ? { written: named.map((column) => column.name) } : {}),
      notes: returning
        ? [NOTE_RETURNING]
        : after.hidden.length
          ? [NOTE_HIDDEN]
          : [],
    };
  }
  const match =
    kind === 'update'
      ? /^update\s+([\w."]+)(?:\s+(?:as\s+)?\w+)?\s+set\s+([\s\S]*?)(?:\s+where\s+([\s\S]*?))?(?:\s+returning\s+[\s\S]*)?$/i.exec(
          text,
        )
      : /^delete\s+from\s+([\w."]+)(?:\s+(?:as\s+)?\w+)?(?:\s+where\s+([\s\S]*?))?(?:\s+returning\s+[\s\S]*)?$/i.exec(
          text,
        );
  const table = (match?.[1] ?? '').split('.').pop()?.replace(/"/g, '') ?? '';
  const where = (kind === 'update' ? match?.[3] : match?.[2]) ?? '';
  const columns = tables.get(table) ?? [{ name: 'id', type: 'bigint' }];
  const ids = keys(where);
  const count = ids?.length ?? rows;
  const current = Array.from({ length: count }, (_, row) =>
    columns.map((column) => value(column, row, ids?.[row])),
  );
  const before = sample(table, columns, current, count, patterns);
  if (kind === 'delete')
    return {
      supported: true,
      kind: 'delete',
      target: table,
      affected_rows: count,
      before,
      bound_to: 'rows',
      notes: [],
    };
  // A new value is shown when it is written out, or copied from a column of
  // the target that is not protected; anything else hides it.
  const assigned = split(match?.[2] ?? '').map((item) => {
    const [name = '', ...rest] = item.split('=');
    return [columnName(name), rest.join('=').trim()] as const;
  });
  const opaque = new Set<string>();
  const changed = current.map((row) =>
    row.map((cell, index) => {
      const column = columns[index]?.name ?? '';
      const assignment = assigned.find(([name]) => name === column);
      if (!assignment) return cell;
      const parsed = literal(assignment[1]);
      if (parsed) return parsed.value;
      const source = columns.findIndex((c) => c.name === assignment[1]);
      if (
        source >= 0 &&
        !protectedColumn(patterns, table, columns[source]?.name ?? '')
      )
        return row[source];
      opaque.add(column);
      return null;
    }),
  );
  const after = sample(table, columns, changed, count, patterns, (column) =>
    opaque.has(column),
  );
  return {
    supported: true,
    kind: 'update',
    target: table,
    affected_rows: count,
    before,
    ...(returning ? {} : { after }),
    bound_to: 'rows',
    written: assigned.map(([name]) => name),
    notes: returning
      ? [NOTE_RETURNING]
      : after.hidden.length
        ? [NOTE_HIDDEN]
        : [],
  };
}
