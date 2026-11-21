import { describe, expect, it } from 'vitest';
// @ts-expect-error plain ESM script without types
import { deadLinks, linkedDocs, rewriteLinks } from '../scripts/docs-links.mjs';

const published = new Set(['api.md', 'security-model.md']);

describe('published docs links', () => {
  it('lower-cases published sibling links and keeps anchors', () => {
    const out = rewriteLinks(
      'See [x](SECURITY-MODEL.md#audit) now.',
      published,
    );
    expect(out).toBe('See [x](security-model.md#audit) now.');
  });
  it('turns unpublished and outside-docs links into plain text', () => {
    const src = '[a](DEPLOYMENT.md#x) and [b](../deploy/x.json)';
    expect(rewriteLinks(src, published)).toBe('a and b');
  });
  it('leaves schemes and pure anchors alone', () => {
    const src = '[a](https://x.dev/y.md) [b](mailto:a@b.c) [c](#top)';
    expect(rewriteLinks(src, published)).toBe(src);
  });
  it('ignores fenced code', () => {
    const src = '```\n[a](FOO.md)\n```';
    expect(rewriteLinks(src, published)).toBe(src);
    expect(linkedDocs(src)).toEqual([]);
  });
  it('lists linked docs and detects dead links', () => {
    expect(linkedDocs('[a](API.md#x) [b](../x.md) [c](API.md)')).toEqual([
      'api.md',
    ]);
    expect(deadLinks('[a](api.md) [b](other.md)', published)).toEqual([
      'other.md',
    ]);
  });
});
