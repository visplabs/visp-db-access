import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { format, resolveConfig } from 'prettier';
import {
  deadLinks,
  dropImages,
  linkedDocs,
  rewriteLinks,
} from './docs-links.mjs';

// Publish owned copies without changing the authoritative contract files.
// The console links to api.md and architecture.md; every sibling document they
// link to is published too (up to MAX_DOCS), and links that would be dead are
// turned into plain text.
const MAX_DOCS = 8;
const roots = ['API.md', 'ARCHITECTURE.md'];
const sources = new Map(); // published name -> source file name
const queue = [...roots];
const available = await readdir('../docs');
while (queue.length) {
  const source = queue.shift();
  const name = source.toLowerCase();
  if (sources.has(name) || sources.size >= MAX_DOCS) continue;
  sources.set(name, source);
  const content = await readFile(`../docs/${source}`, 'utf8');
  for (const linked of linkedDocs(content)) {
    const file = available.find((entry) => entry.toLowerCase() === linked);
    if (file) queue.push(file);
  }
}

const published = new Set(sources.keys());
await mkdir('public/docs', { recursive: true });
for (const [name, source] of sources) {
  const content = rewriteLinks(
    dropImages(await readFile(`../docs/${source}`, 'utf8')),
    published,
  );
  const dead = deadLinks(content, published);
  if (dead.length)
    throw new Error(
      `sync-docs: public/docs/${name} links to files that are not published: ${dead.join(', ')}`,
    );
  const path = `public/docs/${name}`;
  const formatted = await format(content, {
    ...(await resolveConfig(path)),
    filepath: path,
  });
  const existing = await readFile(path, 'utf8').catch(() => null);
  if (existing !== formatted) await writeFile(path, formatted);
}
