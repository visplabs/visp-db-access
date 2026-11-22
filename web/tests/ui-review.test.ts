// Logic behind the fixes from the 2026-11-22 UI review.
import { describe, it, expect } from 'vitest';
import { analyzeDemo, constantSelect } from '../src/api/mock-guard';
import { defaultPolicy } from '../src/api/fixtures';
import { createMockTransport } from '../src/api/mock';
import { isApplePlatform, shortcutLabel } from '../src/lib/platform';
import { docHref, headings, parse, slug } from '../src/lib/markdown';

describe('demo constant SELECT (review item 02)', () => {
  it('returns one row with the value of SELECT 1', () => {
    expect(constantSelect('SELECT 1;')).toEqual({
      columns: [{ name: '?column?', type_name: 'int4', masked: false }],
      row: [1],
    });
  });
  it('keeps aliases, strings and several values', () => {
    const result = constantSelect("select 1 as one, 'it''s', true;");
    expect(result?.columns.map((c) => c.name)).toEqual([
      'one',
      '?column?',
      'bool',
    ]);
    expect(result?.row).toEqual([1, "it's", true]);
  });
  it('splits an alias at the last AS, outside a string', () => {
    expect(
      constantSelect(`select 'a as b', 2 AS "my col"`)?.columns.map(
        (c) => c.name,
      ),
    ).toEqual(['?column?', 'my col']);
    expect(constantSelect(`select 'a as b'`)?.row).toEqual(['a as b']);
  });
  it('leaves statements that read a table to the sample data', () => {
    expect(constantSelect('SELECT * FROM customers')).toBeUndefined();
    expect(constantSelect("SELECT 'from' FROM t")).toBeUndefined();
    expect(constantSelect('UPDATE t SET a = 1')).toBeUndefined();
  });
  it('a mock run of SELECT 1 is one real row; a table read is marked as sample data', async () => {
    const transport = createMockTransport({ delay: 0 });
    await transport('/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: 'admin@visp.dev',
        password: 'demo-password',
      }),
    });
    const clusters = (await transport('/clusters')) as {
      items: { id: string; name: string }[];
    };
    const id = clusters.items.find((c) => c.name === 'commerce-dev')?.id;
    const run = (sql: string) =>
      transport(`/clusters/${id}/query`, {
        method: 'POST',
        body: JSON.stringify({ sql }),
      }) as Promise<{ rows: unknown[][]; simulated?: boolean }>;
    const one = await run('SELECT 1;');
    expect(one.rows).toEqual([[1]]);
    expect(one.simulated).toBeFalsy();
    const sample = await run('SELECT id FROM customers LIMIT 5');
    expect(sample.simulated).toBe(true);
  });
});

describe('demo LIMIT suggestion (review item 06)', () => {
  const policy = defaultPolicy('development');
  it('does not suggest a LIMIT for a query that reads no table', () => {
    const codes = (sql: string) =>
      analyzeDemo(sql, policy).suggestions?.map((s) => s.code) ?? [];
    expect(codes('SELECT 1;')).not.toContain('add_limit');
    expect(codes('SELECT id FROM customers')).toContain('add_limit');
  });
});

describe('shortcut labels (review item 14)', () => {
  it('uses Ctrl on Linux and Windows and ⌘ on Apple systems', () => {
    expect(isApplePlatform({ platform: 'Linux x86_64' } as Navigator)).toBe(
      false,
    );
    expect(isApplePlatform({ platform: 'MacIntel' } as Navigator)).toBe(true);
    expect(
      isApplePlatform({
        platform: '',
        userAgentData: { platform: 'macOS' },
      } as unknown as Navigator),
    ).toBe(true);
    expect(shortcutLabel('K', false)).toBe('Ctrl K');
    expect(shortcutLabel('K', true)).toBe('⌘ K');
  });
});

describe('Markdown reader (review item 17)', () => {
  const blocks = parse(
    [
      '# Title',
      '',
      'Intro with `code` and a [link](security-model.md#audit).',
      '',
      '## Query API',
      '',
      '- one',
      '- two',
      '  - nested',
      '',
      '| A | B |',
      '|---|---|',
      '| 1 | 2 |',
      '',
      '```sh',
      '# not a heading',
      '```',
      '',
      '## Query API',
    ].join('\n'),
  );
  it('reads headings with unique anchors', () => {
    expect(headings(blocks)).toEqual([
      { level: 1, text: 'Title', id: 'title' },
      { level: 2, text: 'Query API', id: 'query-api' },
      { level: 2, text: 'Query API', id: 'query-api-1' },
    ]);
  });
  it('keeps code blocks verbatim and reads lists and tables', () => {
    expect(blocks.map((b) => b.kind)).toEqual([
      'heading',
      'paragraph',
      'heading',
      'list',
      'table',
      'code',
      'heading',
    ]);
    expect(blocks.find((b) => b.kind === 'code')).toMatchObject({
      lang: 'sh',
      text: '# not a heading',
    });
  });
  it('strips only a closing run of # after a space, and reads table rules', () => {
    const titles = headings(parse('## C#\n\n## Closed ##')).map((h) => h.text);
    expect(titles).toEqual(['C#', 'Closed']);
    const table = (rule: string) =>
      parse(`| A | B |\n${rule}\n| 1 | 2 |`)[0]?.kind;
    expect(table('|:--|--:|')).toBe('table');
    expect(table('--- | ---')).toBe('table');
    expect(table('| - | - |')).not.toBe('table');
  });
  it('sends sibling documents to the reader and keeps other links', () => {
    expect(docHref('security-model.md#audit')).toBe(
      '/help/security-model#audit',
    );
    expect(docHref('./API.md')).toBe('/help/api');
    expect(docHref('https://example.com/a.md')).toBe(
      'https://example.com/a.md',
    );
    expect(slug('The `audit` chain!')).toBe('the-audit-chain');
  });
});
