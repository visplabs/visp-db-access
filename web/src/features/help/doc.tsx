import { useEffect, useMemo } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft } from 'lucide-react';
import { BrandMark } from '../../components/ui/brand';
import { Empty, Skeleton } from '../../components/ui';
import { useMedia } from '../../lib/media';
import { headings, Markdown, parse } from '../../lib/markdown';

/** The documents the console publishes under /docs (see scripts/sync-docs.mjs). */
const NAME = /^[a-z0-9-]+$/;

/** A readable page for one of the console's Markdown documents. */
export function HelpDocument() {
  const { name = '' } = useParams();
  const narrow = useMedia('(max-width: 900px)');
  const valid = NAME.test(name);
  const doc = useQuery({
    queryKey: ['help', name],
    enabled: valid,
    queryFn: async ({ signal }) => {
      const response = await fetch(`/docs/${name}.md`, { signal });
      const type = response.headers.get('content-type') ?? '';
      // The single-page fallback answers unknown paths with HTML.
      if (!response.ok || type.includes('text/html'))
        throw new Error('not found');
      return response.text();
    },
    staleTime: Infinity,
    retry: false,
  });
  const blocks = useMemo(() => parse(doc.data ?? ''), [doc.data]);
  const contents = useMemo(
    () => headings(blocks).filter((h) => h.level === 2 || h.level === 3),
    [blocks],
  );
  const title = headings(blocks).find((h) => h.level === 1)?.text ?? name;
  useEffect(() => {
    document.title = `${title} — visp docs`;
  }, [title]);
  useEffect(() => {
    // Jump to the linked section once the document is on the page.
    const id = decodeURIComponent(location.hash.slice(1));
    if (doc.data && id) document.getElementById(id)?.scrollIntoView();
  }, [doc.data]);
  const links = (
    <ol>
      {contents.map((heading) => (
        <li key={heading.id} data-level={heading.level}>
          <a href={`#${heading.id}`}>{heading.text.replace(/`/g, '')}</a>
        </li>
      ))}
    </ol>
  );
  return (
    <div className="help-page">
      <header className="help-header">
        <Link to="/settings" className="help-back">
          <ArrowLeft size={16} />
          Back to the console
        </Link>
        <span className="help-brand">
          <BrandMark size={20} />
          visp docs
        </span>
      </header>
      {!valid || doc.isError ? (
        <main className="help-body">
          <Empty
            title="This document isn’t here"
            description="Check the address, or open the documents from Settings."
          />
        </main>
      ) : doc.isPending ? (
        <main className="help-body">
          <Skeleton />
        </main>
      ) : (
        <div className="help-layout">
          {contents.length > 1 && (
            <nav className="help-toc" aria-label="On this page">
              {narrow ? (
                <details>
                  <summary>On this page</summary>
                  {links}
                </details>
              ) : (
                <>
                  <strong>On this page</strong>
                  {links}
                </>
              )}
            </nav>
          )}
          <main className="help-body markdown">
            <Markdown blocks={blocks} />
          </main>
        </div>
      )}
    </div>
  );
}
