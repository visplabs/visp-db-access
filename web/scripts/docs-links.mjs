// Pure helpers that make the published copies of the docs link-safe.
const LINK = /(\]\()([^)\s]+)(\))/g;
const SCHEME = /^[a-z][a-z0-9+.-]*:/i;

// Split a link target into a published doc name and an optional anchor.
// Returns null for targets that are not relative links to a sibling .md file.
export function siblingDoc(target) {
  if (target.startsWith('#') || SCHEME.test(target)) return null;
  const hash = target.indexOf('#');
  const path = hash === -1 ? target : target.slice(0, hash);
  const anchor = hash === -1 ? '' : target.slice(hash);
  if (!/^[A-Za-z0-9_.-]+\.md$/.test(path)) return { name: null, anchor };
  return { name: path.toLowerCase(), anchor };
}

// Apply fn to the text outside fenced code blocks, line by line.
function mapOutsideFences(content, fn) {
  let fenced = false;
  return content
    .split('\n')
    .map((line) => {
      if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
      return fenced ? line : fn(line);
    })
    .join('\n');
}

// Relative sibling .md names (lower case) linked from the content.
export function linkedDocs(content) {
  const names = [];
  mapOutsideFences(content, (line) => {
    for (const match of line.matchAll(LINK)) {
      const doc = siblingDoc(match[2]);
      if (doc?.name && !names.includes(doc.name)) names.push(doc.name);
    }
    return line;
  });
  return names;
}

// Rewrite relative links: published siblings get their lower-case name (anchor
// kept); every other relative link becomes plain text (link text only).
export function rewriteLinks(content, published) {
  return mapOutsideFences(content, (line) =>
    line.replace(/(\[(?:[^\]]|\\\])*\])\(([^)\s]+)\)/g, (all, text, target) => {
      if (target.startsWith('#') || SCHEME.test(target)) return all;
      const doc = siblingDoc(target);
      if (doc?.name && published.has(doc.name))
        return `${text}(${doc.name}${doc.anchor})`;
      return text.slice(1, -1);
    }),
  );
}

// Relative link targets in the content that do not point to a published file.
export function deadLinks(content, published) {
  const dead = [];
  mapOutsideFences(content, (line) => {
    for (const match of line.matchAll(LINK)) {
      const target = match[2];
      if (target.startsWith('#') || SCHEME.test(target)) continue;
      const doc = siblingDoc(target);
      if (!doc?.name || !published.has(doc.name)) dead.push(target);
    }
    return line;
  });
  return dead;
}
