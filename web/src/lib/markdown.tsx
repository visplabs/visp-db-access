// A small Markdown reader for the console's own documents. It builds React
// elements (never HTML strings), so the text cannot inject markup. It covers
// what docs/*.md use: headings, paragraphs, lists, code blocks, tables,
// block quotes, rules, and inline code, emphasis and links.
import { Fragment, type ReactNode } from 'react';

export type Heading = { level: number; text: string; id: string };

/** A GitHub-style anchor for a heading: "Query API" becomes "query-api". */
export function slug(text: string): string {
  return text
    .toLowerCase()
    .replace(/[`*_]/g, '')
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .trim()
    .replace(/\s/g, '-');
}

/** Where a link in a document goes: sibling documents open in the reader. */
export function docHref(href: string): string {
  const match = /^(?:\.\/)?([a-z0-9-]+)\.md(#.*)?$/i.exec(href);
  if (match?.[1]) return `/help/${match[1].toLowerCase()}${match[2] ?? ''}`;
  return href;
}

const INLINE =
  /(`+)([\s\S]*?)\1|\*\*([^*]+)\*\*|__([^_]+)__|\*([^*\s][^*]*)\*|_([^_\s][^_]*)_|\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)|<(https?:\/\/[^>\s]+)>/g;

export function inline(text: string, key = 'i'): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0,
    n = 0;
  for (const match of text.matchAll(INLINE)) {
    const at = match.index ?? 0;
    if (at > last) out.push(text.slice(last, at));
    const id = `${key}-${n++}`;
    const [, , code, strong1, strong2, em1, em2, label, href, auto] = match;
    if (code !== undefined) out.push(<code key={id}>{code.trim()}</code>);
    else if (strong1 ?? strong2)
      out.push(
        <strong key={id}>{inline(strong1 ?? strong2 ?? '', id)}</strong>,
      );
    else if (em1 ?? em2)
      out.push(<em key={id}>{inline(em1 ?? em2 ?? '', id)}</em>);
    else if (label !== undefined && href !== undefined) {
      const target = docHref(href);
      const external = /^https?:/i.test(target);
      out.push(
        <a
          key={id}
          href={/^(https?:|\/|#)/i.test(target) ? target : '#'}
          {...(external ? { target: '_blank', rel: 'noreferrer' } : {})}
        >
          {inline(label, id)}
        </a>,
      );
    } else if (auto)
      out.push(
        <a key={id} href={auto} target="_blank" rel="noreferrer">
          {auto}
        </a>,
      );
    last = at + match[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

type Block =
  | { kind: 'heading'; level: number; text: string; id: string }
  | { kind: 'paragraph'; text: string }
  | { kind: 'code'; lang: string; text: string }
  | { kind: 'list'; ordered: boolean; items: string[][] }
  | { kind: 'table'; head: string[]; rows: string[][] }
  | { kind: 'quote'; lines: string[] }
  | { kind: 'rule' };

const LIST_ITEM = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;
const cells = (line: string) =>
  line
    .trim()
    .replace(/^\||\|$/g, '')
    .split(/(?<!\\)\|/)
    .map((cell) => cell.trim().replaceAll('\\|', '|'));

export function parse(source: string): Block[] {
  const lines = source.replace(/\r\n?/g, '\n').split('\n');
  const blocks: Block[] = [];
  const used = new Map<string, number>();
  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? '';
    if (!line.trim()) {
      i++;
      continue;
    }
    const fence = /^(\s*)(```+|~~~+)\s*([\w-]*)/.exec(line);
    if (fence) {
      const close = fence[2] ?? '```';
      const body: string[] = [];
      i++;
      while (i < lines.length && !(lines[i] ?? '').trim().startsWith(close))
        body.push(lines[i++] ?? '');
      i++;
      blocks.push({
        kind: 'code',
        lang: fence[3] ?? '',
        text: body.join('\n'),
      });
      continue;
    }
    const heading = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line);
    if (heading) {
      const text = heading[2] ?? '';
      const base = slug(text) || 'section';
      const count = used.get(base) ?? 0;
      used.set(base, count + 1);
      blocks.push({
        kind: 'heading',
        level: heading[1]?.length ?? 1,
        text,
        id: count ? `${base}-${count}` : base,
      });
      i++;
      continue;
    }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) {
      blocks.push({ kind: 'rule' });
      i++;
      continue;
    }
    if (
      line.includes('|') &&
      /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(
        lines[i + 1] ?? '',
      )
    ) {
      const head = cells(line);
      const rows: string[][] = [];
      i += 2;
      while (
        i < lines.length &&
        (lines[i] ?? '').includes('|') &&
        (lines[i] ?? '').trim()
      )
        rows.push(cells(lines[i++] ?? ''));
      blocks.push({ kind: 'table', head, rows });
      continue;
    }
    if (/^\s*>/.test(line)) {
      const quote: string[] = [];
      while (i < lines.length && /^\s*>/.test(lines[i] ?? ''))
        quote.push((lines[i++] ?? '').replace(/^\s*>\s?/, ''));
      blocks.push({ kind: 'quote', lines: quote });
      continue;
    }
    const item = LIST_ITEM.exec(line);
    if (item) {
      const ordered = /\d/.test(item[2] ?? '');
      const indent = item[1]?.length ?? 0;
      const items: string[][] = [];
      while (i < lines.length) {
        const current = lines[i] ?? '';
        const next = LIST_ITEM.exec(current);
        if (next && (next[1]?.length ?? 0) <= indent) {
          items.push([next[3] ?? '']);
          i++;
        } else if (current.trim() && /^\s+/.test(current) && items.length) {
          // A nested item or a continuation line belongs to the last item.
          items[items.length - 1]?.push(current.trim());
          i++;
        } else if (!current.trim() && LIST_ITEM.exec(lines[i + 1] ?? '')) {
          i++;
        } else break;
      }
      blocks.push({ kind: 'list', ordered, items });
      continue;
    }
    const paragraph: string[] = [];
    while (
      i < lines.length &&
      (lines[i] ?? '').trim() &&
      !/^(#{1,6}\s|\s*(```|~~~)|\s*>)/.test(lines[i] ?? '') &&
      !LIST_ITEM.test(lines[i] ?? '')
    )
      paragraph.push((lines[i++] ?? '').trim());
    blocks.push({ kind: 'paragraph', text: paragraph.join(' ') });
  }
  return blocks;
}

export function headings(blocks: Block[]): Heading[] {
  return blocks.flatMap((block) =>
    block.kind === 'heading'
      ? [{ level: block.level, text: block.text, id: block.id }]
      : [],
  );
}

function listItem(lines: string[], key: string): ReactNode {
  const [first = '', ...rest] = lines;
  const nested = rest.filter((line) => LIST_ITEM.test(line));
  const more = rest.filter((line) => !LIST_ITEM.test(line));
  return (
    <li key={key}>
      {inline([first, ...more].join(' '), key)}
      {nested.length > 0 && (
        <ul>
          {nested.map((line, n) =>
            listItem([LIST_ITEM.exec(line)?.[3] ?? line], `${key}-${n}`),
          )}
        </ul>
      )}
    </li>
  );
}

export function Markdown({ blocks }: { blocks: Block[] }) {
  return (
    <>
      {blocks.map((block, n) => {
        const key = `b${n}`;
        switch (block.kind) {
          case 'heading': {
            const Tag = `h${Math.min(block.level, 6)}` as 'h1';
            return (
              <Tag key={key} id={block.id}>
                {inline(block.text, key)}
              </Tag>
            );
          }
          case 'paragraph':
            return <p key={key}>{inline(block.text, key)}</p>;
          case 'code':
            return (
              <pre key={key} data-lang={block.lang || undefined}>
                <code>{block.text}</code>
              </pre>
            );
          case 'list': {
            const Tag = block.ordered ? 'ol' : 'ul';
            return (
              <Tag key={key}>
                {block.items.map((item, m) => listItem(item, `${key}-${m}`))}
              </Tag>
            );
          }
          case 'table':
            return (
              <div className="table-wrap" key={key} tabIndex={0}>
                <table>
                  <thead>
                    <tr>
                      {block.head.map((cell, m) => (
                        <th key={m}>{inline(cell, `${key}-h${m}`)}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {block.rows.map((row, r) => (
                      <tr key={r}>
                        {row.map((cell, m) => (
                          <td key={m}>{inline(cell, `${key}-${r}-${m}`)}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          case 'quote':
            return (
              <blockquote key={key}>
                {inline(block.lines.join(' '), key)}
              </blockquote>
            );
          case 'rule':
            return <hr key={key} />;
          default:
            return <Fragment key={key} />;
        }
      })}
    </>
  );
}
