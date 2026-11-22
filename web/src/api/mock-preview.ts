// Write previews for the mock API. The server runs the write and rolls it
// back; the mock makes up plausible rows from the statement instead, with the
// same shape, the same masking rules and the same texts.
import type { Cluster, Policy, Preview, RowSample } from './types';
import { demoSchema, uuid } from './fixtures';

/** Rows shown in a preview at most, before and after. */
const SAMPLE_ROWS = 20;
const HIDDEN = '••••••';
export const MYSQL_REASON =
  'Writes on MySQL are not previewed, so this review cannot show which rows will change. If approved, the statement runs exactly as written, on the rows that match when it runs.';
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

/** The database's own functions a statement calls, as `name(argument types)`. */
export function databaseFunctions(sql: string): string[] {
  const found = new Set<string>();
  const tokens = tokenize(sql);
  tokens.forEach((token, index) => {
    if (token.kind !== 'word' || tokens[index + 1]?.text !== '(') return;
    const bare = token.text.split('.').pop() ?? token.text;
    if (BUILT_IN.has(bare) || KEYWORDS.has(bare) || isTable(bare)) return;
    found.add(`${bare}(numeric)`);
  });
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
  // `*` matches any run of characters: the pieces between stars must appear
  // in order, the first at the start and the last at the end.
  const glob = (pattern: string, text: string) => {
    const pieces = pattern.toLowerCase().split('*');
    const subject = text.toLowerCase();
    const head = pieces[0] ?? '',
      tail = pieces.length > 1 ? (pieces.at(-1) ?? '') : '';
    if (pieces.length === 1) return subject === head;
    if (!subject.startsWith(head) || !subject.endsWith(tail)) return false;
    if (head.length + tail.length > subject.length) return false;
    let at = head.length;
    const limit = subject.length - tail.length;
    for (const piece of pieces.slice(1, -1)) {
      const found = subject.indexOf(piece, at);
      if (found < 0 || found + piece.length > limit) return false;
      at = found + piece.length;
    }
    return true;
  };
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
  const tokens = tokenize(text);
  const [first, second, third] = tokens;
  if (!first) return undefined;
  if (tokens.length === 1 && first.kind === 'string')
    return { value: first.text };
  const number =
    tokens.length === 1
      ? first
      : tokens.length === 2 && first.text === '-'
        ? second
        : undefined;
  if (number?.kind === 'number' && /^\d+(\.\d+)?$/.test(number.text))
    return { value: Number(number.text) * (number === first ? 1 : -1) };
  if (tokens.length === 1 && first.kind === 'word') {
    if (first.text === 'null') return { value: null };
    if (first.text === 'true' || first.text === 'false')
      return { value: first.text === 'true' };
    if (first.text === 'current_timestamp')
      return { value: new Date().toISOString() };
  }
  if (
    tokens.length === 3 &&
    first.kind === 'word' &&
    first.text === 'now' &&
    second?.text === '(' &&
    third?.text === ')'
  )
    return { value: new Date().toISOString() };
  return undefined;
}

/** A column name as PostgreSQL stores it: unquoted folds to lower case. */
function columnName(text: string): string {
  const name = text.trim();
  return name.length > 1 && name.startsWith('"') && name.endsWith('"')
    ? name.slice(1, -1)
    : name.toLowerCase();
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
  const tokens = tokenize(where);
  const at = tokens.findIndex(
    (token) =>
      token.kind === 'word' &&
      (token.text === 'id' || token.text.endsWith('.id')) &&
      token.depth === 0,
  );
  if (at < 0) return undefined;
  const next = tokens[at + 1],
    after = tokens[at + 2];
  if (next?.text === '=' && after) {
    if (after.kind === 'string') return [after.text];
    if (after.kind === 'number') return [Number(after.text)];
    return undefined;
  }
  if (next?.kind === 'word' && next.text === 'in' && after?.text === '(') {
    const close = closing(tokens, at + 2);
    if (close < 0) return undefined;
    return tokens
      .slice(at + 3, close)
      .filter((token) => token.kind === 'string' || token.kind === 'number')
      .map((token) =>
        token.kind === 'number' ? Number(token.text) : token.text,
      );
  }
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

type Token = {
  kind: 'word' | 'quoted' | 'string' | 'number' | 'punct';
  /** Lower case for a word; the name for a quoted identifier. */
  text: string;
  start: number;
  end: number;
  /** Parentheses around it. */
  depth: number;
};
const isWordStart = (c: string) => /[A-Za-z_]/.test(c);
const isWordPart = (c: string) => /[\w.$]/.test(c);
const isDigit = (c: string) => c >= '0' && c <= '9';
/**
 * The tokens of a statement, in one pass over it: words, quoted names,
 * string literals, numbers and single punctuation characters. Comments and
 * white space are skipped. A plain scanner, so no input can make it slow.
 */
export function tokenize(sql: string): Token[] {
  const tokens: Token[] = [];
  let depth = 0,
    i = 0;
  const push = (kind: Token['kind'], text: string, start: number) =>
    tokens.push({ kind, text, start, end: i, depth });
  while (i < sql.length) {
    const c = sql.charAt(i);
    const start = i;
    if (/\s/.test(c)) {
      i += 1;
    } else if (c === '-' && sql.charAt(i + 1) === '-') {
      const line = sql.indexOf('\n', i);
      i = line < 0 ? sql.length : line + 1;
    } else if (c === '/' && sql.charAt(i + 1) === '*') {
      const close = sql.indexOf('*/', i + 2);
      i = close < 0 ? sql.length : close + 2;
    } else if (c === "'" || c === '"') {
      // A quote ends a literal unless it is doubled.
      i += 1;
      while (i < sql.length) {
        if (sql.charAt(i) === c && sql.charAt(i + 1) === c) i += 2;
        else if (sql.charAt(i) === c) break;
        else i += 1;
      }
      i = Math.min(i + 1, sql.length);
      const inner = sql.slice(start + 1, i - 1).replaceAll(c + c, c);
      push(c === "'" ? 'string' : 'quoted', inner, start);
    } else if (isWordStart(c)) {
      while (i < sql.length && isWordPart(sql.charAt(i))) i += 1;
      push('word', sql.slice(start, i).toLowerCase(), start);
    } else if (isDigit(c)) {
      while (
        i < sql.length &&
        (isDigit(sql.charAt(i)) || sql.charAt(i) === '.')
      )
        i += 1;
      push('number', sql.slice(start, i), start);
    } else {
      i += 1;
      if (c === ')') depth = Math.max(0, depth - 1);
      push('punct', c, start);
      if (c === '(') depth += 1;
    }
  }
  return tokens;
}

/** The `)` that closes the `(` at `open`, scanning forward from it; -1 when
 * it is not closed. Each parenthesis is passed over once. */
function closing(tokens: Token[], open: number): number {
  const depth = tokens[open]?.depth ?? 0;
  for (let index = open + 1; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token?.kind === 'punct' && token.text === ')' && token.depth === depth)
      return index;
  }
  return -1;
}

/** A write split into its clauses, as text of the statement. */
export type WriteParts = {
  kind: 'insert' | 'update' | 'delete';
  table: string;
  /** INSERT: the column list, without its parentheses. */
  columns?: string;
  /** INSERT: each tuple of VALUES, without its parentheses. */
  tuples: string[];
  /** UPDATE: the assignments after SET. */
  set?: string;
  where?: string;
  returning: boolean;
  /** Not one plain statement: several, ON CONFLICT or ONLY. */
  plain: boolean;
};
/**
 * Read the clauses of an INSERT, UPDATE or DELETE from its tokens, or null
 * for anything else. Keywords count only outside parentheses.
 */
export function parseWrite(sql: string): WriteParts | null {
  const tokens = tokenize(sql);
  const first = tokens[0];
  if (first?.kind !== 'word') return null;
  if (
    first.text !== 'insert' &&
    first.text !== 'update' &&
    first.text !== 'delete'
  )
    return null;
  const kind = first.text;
  const top = (index: number, ...words: string[]) => {
    const token = tokens[index];
    return (
      !!token &&
      token.depth === 0 &&
      token.kind === 'word' &&
      words.includes(token.text)
    );
  };
  const find = (from: number, ...words: string[]) => {
    for (let index = from; index < tokens.length; index += 1)
      if (top(index, ...words)) return index;
    return -1;
  };
  const slice = (from: number, to: number) => {
    const head = tokens[from],
      tail = tokens[to - 1];
    return from < to && head && tail
      ? sql.slice(head.start, tail.end).trim()
      : '';
  };
  // A single trailing `;` ends the statement; it is not part of a clause.
  const last = tokens.at(-1);
  const end =
    last?.kind === 'punct' && last.text === ';'
      ? tokens.length - 1
      : tokens.length;
  const returningAt = find(1, 'returning');
  const stop = returningAt < 0 ? end : returningAt;
  const plain = !tokens.some(
    (token, index) =>
      (token.kind === 'punct' &&
        token.text === ';' &&
        index < tokens.length - 1) ||
      (top(index, 'on') && top(index + 1, 'conflict')) ||
      top(index, 'only'),
  );
  const name = (index: number) => {
    const token = tokens[index];
    if (!token || (token.kind !== 'word' && token.kind !== 'quoted')) return '';
    return token.text.split('.').pop() ?? '';
  };
  const parts: WriteParts = {
    kind,
    table: '',
    tuples: [],
    returning: returningAt >= 0,
    plain,
  };
  if (kind === 'insert') {
    if (!top(1, 'into')) return parts;
    parts.table = name(2);
    let index = 3;
    if (tokens[index]?.text === '(' && tokens[index]?.kind === 'punct') {
      const close = closing(tokens, index);
      if (close < 0) return parts;
      parts.columns = slice(index + 1, close);
      index = close + 1;
    }
    if (!top(index, 'values')) return parts;
    // Each tuple: from an opening parenthesis at the top to its close.
    for (let at = index + 1; at < stop; at += 1) {
      const token = tokens[at];
      if (token?.kind !== 'punct' || token.text !== '(' || token.depth !== 0)
        continue;
      const close = closing(tokens, at);
      if (close < 0 || close > stop) break;
      parts.tuples.push(slice(at + 1, close));
      at = close;
    }
    return parts;
  }
  let index = kind === 'delete' ? 2 : 1;
  if (kind === 'delete' && !top(1, 'from')) return parts;
  parts.table = name(index);
  index += 1;
  // An optional alias, with or without AS.
  if (top(index, 'as')) index += 2;
  else if (
    tokens[index]?.kind === 'word' &&
    !top(index, 'set', 'where', 'returning')
  )
    index += 1;
  const whereAt = find(index, 'where');
  const whereEnd = whereAt < 0 ? stop : whereAt;
  if (kind === 'update') {
    if (!top(index, 'set')) return parts;
    parts.set = slice(index + 1, whereEnd);
  }
  if (whereAt >= 0) parts.where = slice(whereAt + 1, stop);
  return parts;
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
  const parts = parseWrite(sql);
  const kind = parts?.kind;
  // Its own RETURNING leaves no sample of the new rows; a note says why.
  const returning = !!parts?.returning;
  if (!parts?.plain)
    return {
      supported: true,
      affected_rows: rows,
      bound_to: 'count',
      notes: [NOTE_COUNT_ONLY],
    };
  const patterns = policy.masked_columns;
  if (kind === 'insert') {
    const table = parts.table;
    const known = tables.get(table) ?? [];
    const named = parts.columns
      ? split(parts.columns)
          .map(columnName)
          .map(
            (name) =>
              known.find((column) => column.name === name) ?? {
                name,
                type: 'text',
              },
          )
      : known;
    const tuples = parts.tuples;
    const opaque = new Set<string>();
    // Without a column list the server does not know which value goes where,
    // so every new value is hidden.
    if (!parts.columns) named.forEach((column) => opaque.add(column.name));
    const written = tuples.map((tuple) =>
      split(tuple).map((item, index) => {
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
      ...(parts.columns ? { written: named.map((column) => column.name) } : {}),
      notes: returning
        ? [NOTE_RETURNING]
        : after.hidden.length
          ? [NOTE_HIDDEN]
          : [],
    };
  }
  const table = parts.table;
  const where = parts.where ?? '';
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
  const assigned = split(parts.set ?? '').map((item) => {
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
