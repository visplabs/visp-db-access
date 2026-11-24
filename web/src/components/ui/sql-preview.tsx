import { sqlParts } from '../../lib/activity';

/** SQL with its keywords and strings marked. React text nodes keep it inert,
 * including strings that resemble HTML. Put it in a `pre` or a `code`. */
export function SqlText({ sql }: { sql: string }) {
  return (
    <>
      {sqlParts(sql).map((part, index) =>
        part.kind === 'plain' ? (
          part.text
        ) : (
          <span key={index} className={`sql-${part.kind}`}>
            {part.text}
          </span>
        ),
      )}
    </>
  );
}

/** One statement in a `code` element. */
export function SqlPreview({ sql }: { sql: string }) {
  return (
    <code>
      <SqlText sql={sql} />
    </code>
  );
}
