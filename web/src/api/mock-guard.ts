import type {
  AccessLevel,
  Analysis,
  Fix,
  Issue,
  Policy,
  Preflight,
  StatementKind,
  Suggestion,
} from './types';
/** Deliberately conservative demo classifier; the backend AST guard is authoritative. */
export function analyzeDemo(sql: string, policy: Policy): Analysis {
  const clean = sql
    .replace(/'(?:''|\\.|[^'\\])*'|--[^\n]*|\/\*[\s\S]*?\*\//g, (token) =>
      token.startsWith("'") ? token : ' ',
    )
    .trim();
  const code = clean.replace(
    /'(?:''|\\.|[^'\\])*'|"(?:""|[^"])*"|`(?:``|[^`])*`/g,
    (token) => ' '.repeat(token.length),
  );
  const leading = code.split(/\s+/)[0]?.toLowerCase() ?? 'other';
  const kinds: StatementKind[] = [
    'select',
    'explain',
    'show',
    'insert',
    'update',
    'delete',
    'merge',
  ];
  const kind: StatementKind = kinds.includes(leading as StatementKind)
    ? (leading as StatementKind)
    : /^(create|alter|drop|truncate)/i.test(code)
      ? 'ddl'
      : leading === 'with'
        ? 'select'
        : 'other';
  const write =
    /\b(insert|update|delete|merge|create|alter|drop|truncate)\b/i.test(code);
  const has_where = /\bwhere\b/i.test(code),
    has_limit = /\blimit\s+\d+/i.test(code);
  const limit = /\blimit\s+(\d+)/i.exec(code);
  const issues: Issue[] = [];
  const tables = Array.from(
    clean.matchAll(/\b(?:from|join|update|into)\s+([\w."`]+)/gi),
    (match) => match[1] ?? '',
  );
  if (!clean)
    issues.push({
      severity: 'block',
      code: 'empty_sql',
      message: 'Enter a SQL statement to analyze.',
    });
  if (/\b(pg_sleep|sleep|benchmark)\s*\(/i.test(code))
    issues.push({
      severity: 'block',
      code: 'blocked_function',
      message: 'Long-running sleep functions are blocked.',
    });
  if (/\b(update|delete)\b/i.test(code) && !has_where)
    issues.push({
      severity: 'block',
      code: 'missing_where',
      message: 'UPDATE and DELETE require a WHERE clause.',
    });
  const several = code.replace(/;\s*$/, '').includes(';');
  if (several)
    issues.push({
      severity: 'block',
      code: 'multiple_statements',
      message:
        'The gateway executes exactly one statement at a time. Submit each statement separately.',
    });
  else if (/^with\b/i.test(code) && write)
    issues.push({
      severity: 'block',
      code: 'complex_demo_sql',
      message:
        'The demo blocks writable CTE queries. The server uses a full SQL parser.',
    });
  if (
    policy.blocked_tables.some((pattern) =>
      tables.some((table) =>
        table.replaceAll('"', '').startsWith(pattern.replace('*', '')),
      ),
    )
  )
    issues.push({
      severity: 'block',
      code: 'blocked_table',
      message: 'A referenced table is blocked by policy.',
    });
  if (kind === 'other')
    issues.push({
      severity: 'block',
      code: 'unsupported_demo_sql',
      message: 'This statement is not supported by the demo classifier.',
    });
  if (kind === 'ddl' && !policy.allow_ddl)
    issues.push({
      severity: 'block',
      code: 'ddl_disabled',
      message: 'DDL is disabled by this policy.',
    });
  if (write)
    issues.push({
      severity: 'warning',
      code: 'write_approval',
      message: 'A second person must review this write before execution.',
    });
  // A read that takes row locks: the guard asks for approval, as for a write.
  const locking =
    !write && kind === 'select' && /\bfor\s+(update|share)\b/i.test(code);
  if (locking)
    issues.push({
      severity: 'warning',
      code: 'locking_read',
      message:
        'This SELECT acquires row locks and may block other transactions. Approval is required; keep the query narrowly filtered.',
    });
  let rewritten = clean.replace(/;\s*$/, '');
  if (!write && !locking && kind === 'select') {
    if (limit) {
      rewritten =
        rewritten.slice(0, limit.index) +
        `LIMIT ${Math.min(Number(limit[1]), policy.max_rows + 1)}` +
        rewritten.slice(limit.index + limit[0].length);
    } else {
      rewritten += `\nLIMIT ${policy.max_rows + 1}`;
      issues.push({
        severity: 'info',
        code: 'limit_added',
        message: `Policy caps results at ${policy.max_rows.toLocaleString()} rows.`,
      });
    }
  }
  const verdict = issues.some((issue) => issue.severity === 'block')
    ? 'deny'
    : write || locking
      ? 'requires_approval'
      : 'allow';
  const risk =
    verdict === 'deny' ? 'critical' : write || locking ? 'high' : 'low';
  const suggestions: Suggestion[] = [];
  // Like the guard: when each statement would pass alone, the only block is
  // that there are several, and keeping the first one resolves it.
  if (several && issues.filter((i) => i.severity === 'block').length === 1) {
    const first = clean.slice(0, code.indexOf(';')).trim();
    const rest = clean.slice(code.indexOf(';') + 1);
    if (
      first &&
      analyzeDemo(first, policy).verdict !== 'deny' &&
      analyzeDemo(rest, policy).verdict !== 'deny'
    )
      suggestions.push({
        code: 'multiple_statements',
        message:
          'Only one statement runs at a time. Keep the first statement and run the others after it.',
        fix: {
          label: 'Keep the first statement',
          sql: first,
          action: 'replace',
        },
      });
  }
  if (verdict !== 'deny') {
    if (/^select\s+\*/i.test(code))
      suggestions.push({
        code: 'select_star',
        message:
          'SELECT * reads every column, including wide ones you may not need. List only the columns you use.',
      });
    if (/\blike\s+'%/i.test(clean))
      suggestions.push({
        code: 'leading_wildcard',
        message:
          'A LIKE pattern that starts with % cannot use a normal index and scans every row.',
      });
    if (
      kind === 'select' &&
      tables.length > 0 &&
      !has_where &&
      !has_limit &&
      !/\b(count|sum|avg|min|max)\s*\(/i.test(code) &&
      policy.max_rows > 100
    )
      suggestions.push({
        code: 'add_limit',
        message: `This reads the whole table without a filter. The gateway stops at ${policy.max_rows} rows, but a small LIMIT returns a sample faster.`,
        fix: {
          label: 'Add LIMIT 100',
          sql: `${clean.replace(/;\s*$/, '')}\nLIMIT 100`,
          action: 'replace',
        },
      });
  }
  return {
    suggestions,
    verdict,
    risk,
    rewritten_sql: verdict === 'deny' ? null : rewritten + ';',
    issues,
    statements: [
      { kind, sql, tables, functions: [], risk, issues, has_where, has_limit },
    ],
  };
}

const WHY_CAP = (rows: number) =>
  `the policy allows ${rows} rows, and one more row shows whether there are more`;
/** The mock of the server's lessons for a person: one next step per code. */
const LESSONS: Record<string, { stop: boolean; text: string }> = {
  empty_sql: {
    stop: false,
    text: "The SQL does not parse. Write one complete statement in this database's dialect.",
  },
  multiple_statements: {
    stop: false,
    text: 'Only one statement runs at a time. Keep one statement in the editor and run the others after it.',
  },
  blocked_function: {
    stop: false,
    text: 'A function in this statement is not allowed here. Remove it and use plain columns, filters and aggregates.',
  },
  missing_where: {
    stop: false,
    text: 'A write must name the rows it changes. Add a WHERE clause that selects only those rows.',
  },
  complex_demo_sql: {
    stop: false,
    text: 'This statement would change data while it looks like a read. Use a plain SELECT, or EXPLAIN without ANALYZE.',
  },
  unsupported_demo_sql: {
    stop: false,
    text: 'This kind of statement or clause does not run through the gateway. Use a plain statement without locking clauses, hints or special comments.',
  },
  blocked_table: {
    stop: true,
    text: "This database's policy blocks a table in this statement.",
  },
  ddl_disabled: {
    stop: true,
    text: "This database's policy does not allow this kind of change, for anyone.",
  },
};
/**
 * The pre-flight answer, as the server makes it from an analysis and the
 * caller's access level. The demo classifier does not know the level, so a
 * reader's write is refused here.
 */
export function preflightDemo(
  analysis: Analysis,
  level: AccessLevel | null,
  policy: Policy,
): Preflight {
  const [statement] = analysis.statements;
  const kind = statement?.kind;
  const effect = kind === 'ddl' ? 'changes the schema' : 'changes data';
  if (analysis.verdict === 'allow') {
    // The statement without its closing semicolon, so that the limit is last.
    let text = (statement?.sql ?? '').trimEnd();
    if (text.endsWith(';')) text = text.slice(0, -1).trimEnd();
    const written = /\blimit\s+(\d+)$/i.exec(text);
    const clause = `LIMIT ${policy.max_rows + 1}`;
    const lowered = written && Number(written[1]) > policy.max_rows;
    const added = kind === 'select' && !written;
    return {
      state: 'safe',
      action: 'run',
      label: 'Run',
      hint:
        policy.max_cost === null
          ? 'This statement only reads data.'
          : "This statement only reads data. Its cost is checked against this database's limit when it runs.",
      ...(added && {
        guard_change: {
          clause,
          text: `The guard adds ${clause}: ${WHY_CAP(policy.max_rows)}.`,
        },
      }),
      ...(lowered && {
        guard_change: {
          clause,
          replaces: `LIMIT ${written[1]}`,
          text: `The guard lowers LIMIT ${written[1]} to ${clause}: ${WHY_CAP(policy.max_rows)}.`,
        },
      }),
    };
  }
  const writeAccess =
    'A person with write access can ask for this change, or an administrator of this database can give you write access.';
  // A read that locks rows cannot be asked for: an approval is for a change.
  if (analysis.verdict === 'requires_approval' && kind === 'select')
    return {
      state: 'blocked',
      action: 'edit_sql',
      label: 'Edit the SQL',
      hint: 'This statement locks rows. Remove the locking clause (FOR UPDATE / FOR SHARE) to run it as a read.',
      code: 'locking_read',
    };
  if (analysis.verdict === 'requires_approval')
    return level === 'read' || !level
      ? {
          state: 'blocked',
          action: 'ask_admin',
          label: 'Ask for write access',
          hint: `This statement ${effect} and needs approval, and your read access does not let you ask for it. ${writeAccess}`,
          code: 'insufficient_access',
        }
      : {
          state: 'needs_approval',
          action: 'request_approval',
          label: 'Request approval',
          hint: `This statement ${effect}, so another person must approve it before it runs.`,
          code: 'approval_required',
        };
  const blocking = analysis.issues.filter((i) => i.severity === 'block');
  // The hardest stop decides, and among equals the first.
  const issue = blocking.find((i) => LESSONS[i.code]?.stop) ?? blocking[0];
  const lesson = issue ? LESSONS[issue.code] : undefined;
  const text = lesson?.text ?? issue?.message ?? 'The guard refused this.';
  if (lesson?.stop)
    return level === 'admin'
      ? {
          state: 'blocked',
          action: 'change_policy',
          label: 'Change the policy',
          hint: `${text} You administer this database: change its policy if this should run.`,
          code: issue?.code,
        }
      : {
          state: 'blocked',
          action: 'ask_admin',
          label: 'Ask an administrator',
          hint: `${text} Only an administrator of this database can change its policy.`,
          code: issue?.code,
        };
  // Only a suggestion that carries the code of the block is a fix for it.
  const repair = (analysis.suggestions ?? []).find(
    (suggestion): suggestion is Suggestion & { fix: Fix } =>
      !!suggestion.fix && suggestion.code === issue?.code,
  );
  return repair
    ? {
        state: 'blocked',
        action: 'apply_fix',
        label: repair.fix.label,
        hint: repair.message,
        code: issue?.code,
        fix: repair.fix,
      }
    : {
        state: 'blocked',
        action: 'edit_sql',
        label: 'Edit the SQL',
        hint: text,
        code: issue?.code,
      };
}

/** Split a projection list at top-level commas, outside quotes and brackets. */
function splitItems(list: string): string[] {
  const items: string[] = [];
  let depth = 0,
    quote = '',
    start = 0;
  for (let i = 0; i < list.length; i++) {
    const char = list[i];
    if (quote) {
      if (char === quote) quote = '';
    } else if (char === "'" || char === '"') quote = char;
    else if (char === '(') depth++;
    else if (char === ')') depth--;
    else if (char === ',' && depth === 0) {
      items.push(list.slice(start, i).trim());
      start = i + 1;
    }
  }
  items.push(list.slice(start).trim());
  return items;
}
function constantValue(expression: string): {
  value: unknown;
  type_name: string;
  name: string;
} {
  const text = expression.trim();
  const call = /^([a-z_][\w]*)\s*\(/i.exec(text)?.[1]?.toLowerCase();
  if (/^-?\d+$/.test(text))
    return { value: Number(text), type_name: 'int4', name: '?column?' };
  if (/^-?\d*\.\d+$/.test(text))
    return { value: Number(text), type_name: 'numeric', name: '?column?' };
  if (/^'(?:''|[^'])*'$/.test(text))
    return {
      value: text.slice(1, -1).replaceAll("''", "'"),
      type_name: 'text',
      name: '?column?',
    };
  if (/^(true|false)$/i.test(text))
    return { value: /^true$/i.test(text), type_name: 'bool', name: 'bool' };
  if (/^null$/i.test(text))
    return { value: null, type_name: 'text', name: '?column?' };
  if (call === 'now' || /^current_timestamp$/i.test(text))
    return {
      value: new Date().toISOString(),
      type_name: 'timestamptz',
      name: call ?? 'current_timestamp',
    };
  if (call === 'version')
    return {
      value: 'PostgreSQL 16.4 (visp demo)',
      type_name: 'text',
      name: 'version',
    };
  if (/^(current_user|user|session_user)$/i.test(text) || call === 'user')
    return {
      value: 'visp_reader',
      type_name: 'name',
      name: text.toLowerCase(),
    };
  return { value: text, type_name: 'text', name: call ?? '?column?' };
}
/** `expr AS name` or `expr AS "name"`: the last ` AS ` splits the item. */
function splitAlias(item: string): { value: string; name: string } | undefined {
  const last = [...item.matchAll(/\sas\s/gi)].at(-1);
  if (last?.index === undefined) return;
  const value = item.slice(0, last.index).trim();
  const rest = item.slice(last.index + last[0].length).trim();
  const quoted = rest.length > 1 && rest.startsWith('"') && rest.endsWith('"');
  const name = quoted ? rest.slice(1, -1) : rest;
  if (!value || !/^[\w ]+$/.test(name)) return;
  return { value, name };
}
/**
 * A SELECT that reads no table, such as `SELECT 1`, returns exactly one row
 * of its constant values in the demo, as a database would.
 */
export function constantSelect(sql: string):
  | {
      columns: { name: string; type_name: string; masked: boolean }[];
      row: unknown[];
    }
  | undefined {
  const clean = sql
    .replace(/--[^\n]*|\/\*[\s\S]*?\*\//g, ' ')
    .trim()
    .replace(/;\s*$/, '')
    .trim();
  if (!/^select\s/i.test(clean)) return;
  const list = clean.slice('select'.length).trim();
  if (!list) return;
  const body = list.replace(/'(?:''|[^'])*'/g, (token) =>
    ' '.repeat(token.length),
  );
  if (/\b(from|into|union|intersect|except|where)\b|;/i.test(body)) return;
  const items = splitItems(list);
  if (items.some((item) => !item || item === '*')) return;
  const parsed = items.map((item) => {
    const alias = splitAlias(item);
    const value = constantValue(alias?.value ?? item);
    return { ...value, name: alias?.name ?? value.name };
  });
  return {
    columns: parsed.map(({ name, type_name }) => ({
      name,
      type_name,
      masked: false,
    })),
    row: parsed.map(({ value }) => value),
  };
}
