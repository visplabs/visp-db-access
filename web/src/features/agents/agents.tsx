import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, Navigate, useSearchParams } from 'react-router-dom';
import { Plus } from 'lucide-react';
import type { Agent, Cluster, NewAgentToken } from '../../api/types';
import { useAction, useAllPages, useResource } from '../../lib/query';
import {
  ActorBadge,
  Button,
  Confirm,
  EnvBadge,
  ErrorPanel,
  Field,
  Modal,
  Picker,
  Skeleton,
  VerdictChip,
} from '../../components/ui';
import { CloudLabel } from '../../components/ui/cluster-heading';
import { RelativeTime } from '../../components/ui/time';
import { formatTime } from '../../lib/utils';
import { useUser } from '../auth/session';
import { InlineTime, SessionList } from './sessions';
import { sessionPath } from './session-trail';
import {
  ClientSnippets,
  ConnectWizard,
  CopyResult,
  GateAnswers,
  useInlineCopy,
} from './connect';
import {
  activeTokens,
  agentState,
  agentStateText,
  lastActive,
  levelText,
  tokenState,
} from './facts';
import { PauseButton } from './pause';

/** The tools every agent gets at the agent door, in the order it uses them. */
const tools = [
  ['list_databases', 'see the databases it can reach'],
  ['search_schema', 'find tables and columns by name'],
  ['describe_table', 'see the columns of one table'],
  ['check_sql', 'ask the guard before a run'],
  ['run_query', 'run a guarded read'],
  ['fetch_rows', 'read more rows of a query it ran; nothing runs again'],
  ['propose_write', 'ask its owner for a write; nothing runs yet'],
  ['get_approval', 'see where its requests stand'],
  ['withdraw', 'take back a request that has not run'],
] as const;
/** What the level means, in a sentence after its name. */
const levelLine = {
  read: 'It can look, never change, and it cannot ask for a write.',
  write:
    'It reads, and may ask for a write. Nothing changes until a person approves it.',
} as const;
const agentPath = (id: string) => `/agents?agent=${encodeURIComponent(id)}`;

export function AgentsPage() {
  const user = useUser();
  // Every page: an administrator must be able to find and stop any agent.
  const agents = useAllPages<Agent>('/agents'),
    clusters = useResource<{ items: Cluster[] }>('/clusters');
  const [params, setParams] = useSearchParams();
  const names = useMemo(
    () => new Map(clusters.data?.items.map((c) => [c.id, c]) ?? []),
    [clusters.data],
  );
  // An old link to a session opens the session's own page.
  const legacy = params.get('session');
  if (legacy && params.get('agent'))
    return <Navigate replace to={sessionPath(params.get('agent')!, legacy)} />;
  const connect = () => setParams({ connect: '1' });
  // The wizard is a page of its own: `?connect`, so Back in the browser
  // returns to the list.
  if (params.has('connect'))
    return clusters.isPending || agents.isPending ? (
      <Skeleton />
    ) : clusters.error ? (
      <ErrorPanel
        error={clusters.error}
        retry={() => void clusters.refetch()}
      />
    ) : (
      <ConnectWizard
        user={user}
        clusters={clusters.data.items}
        ownNames={(agents.data?.items ?? [])
          .filter((agent) => agent.owner.id === user?.id)
          .map((agent) => agent.name)}
        onClose={(agent) => setParams(agent ? { agent } : {})}
      />
    );
  // One agent: a page of its own too, `?agent=`.
  const chosen = params.get('agent');
  if (chosen)
    return (
      <AgentPage
        key={chosen}
        id={chosen}
        clusters={names}
        allClusters={clusters.data?.items ?? []}
        onGone={() => setParams({})}
      />
    );
  return (
    <>
      <div className="page-heading agents-heading">
        <div>
          <h1>Agents</h1>
          <p>
            Agents act for a person. An agent can never do more than its owner.
          </p>
        </div>
        <Button variant="primary" onClick={connect}>
          <Plus size={16} aria-hidden="true" />
          Connect an agent
        </Button>
      </div>
      {agents.isPending ? (
        <Skeleton />
      ) : agents.error ? (
        <ErrorPanel error={agents.error} retry={() => void agents.refetch()} />
      ) : agents.data.items.length === 0 ? (
        <AgentsEmpty onConnect={connect} />
      ) : (
        <div className="agents-layout">
          <GateLegend />
          <div
            className="table-wrap agents-table"
            tabIndex={0}
            role="region"
            aria-label="Agents list"
          >
            <table aria-label="Agents" className="card-rows">
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Owner</th>
                  <th>Reach</th>
                  <th>Level</th>
                  <th>Tokens</th>
                  <th>Last active</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {agents.data.items.map((agent) => (
                  <AgentRow key={agent.id} agent={agent} clusters={names} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}

function Reach({
  agent,
  clusters,
}: {
  agent: Agent;
  clusters: Map<string, Cluster>;
}) {
  const first = clusters.get(agent.cluster_ids[0] ?? '');
  if (agent.cluster_ids.length !== 1)
    return <>{`${agent.cluster_ids.length} databases`}</>;
  return first ? (
    <span className="agent-reach-cell">
      <span className="identifier">{first.name}</span>
      <EnvBadge environment={first.environment} />
    </span>
  ) : (
    <>1 database</>
  );
}

function AgentStateText({ agent }: { agent: Agent }) {
  const state = agentState(agent);
  return (
    <span className="agent-state" data-state={state}>
      {agentStateText[state]}
    </span>
  );
}

/** A table row on a wide screen; on a narrow one the same row is a card
 * whose cells name themselves (`data-label`). */
function AgentRow({
  agent,
  clusters,
}: {
  agent: Agent;
  clusters: Map<string, Cluster>;
}) {
  const tokens = activeTokens(agent);
  const used = lastActive(agent);
  return (
    <tr>
      <td data-label="Agent" className="card-title">
        <Link
          className="agent-open"
          to={agentPath(agent.id)}
          aria-label={`Agent ${agent.name}`}
        >
          <ActorBadge kind="agent" name={agent.name} />
        </Link>
      </td>
      <td data-label="Owner">
        <ActorBadge kind="human" name={agent.owner.name} />
      </td>
      <td data-label="Reach">
        <Reach agent={agent} clusters={clusters} />
      </td>
      <td data-label="Level">{levelText[agent.max_level]}</td>
      <td data-label="Tokens">
        {tokens.count === 0 ? (
          <span className="muted">None active</span>
        ) : (
          <>
            {tokens.count} active
            {tokens.endsInDays !== undefined && tokens.endsInDays <= 7 && (
              <span className="agent-expiring">
                ,{' '}
                {tokens.endsInDays <= 1
                  ? 'ends today'
                  : `ends in ${tokens.endsInDays} days`}
              </span>
            )}
          </>
        )}
      </td>
      <td data-label="Last active">
        {used ? (
          <RelativeTime value={used} />
        ) : (
          <span className="muted">Not yet</span>
        )}
      </td>
      <td data-label="State">
        <AgentStateText agent={agent} />
      </td>
    </tr>
  );
}

/** What the gate answers every agent, in the four verdicts. */
function GateLegend() {
  return (
    <ul className="agents-gate" aria-label="What the gate answers every agent">
      <li>
        <VerdictChip verdict="allowed" />
        <span>Reads within its owner&apos;s access</span>
      </li>
      <li>
        <VerdictChip verdict="masked" />
        <span>Protected columns come back hidden</span>
      </li>
      <li>
        <VerdictChip verdict="held" />
        <span>Writes wait for a person</span>
      </li>
      <li>
        <VerdictChip verdict="blocked" />
        <span>Blocked tables are refused</span>
      </li>
    </ul>
  );
}

/** No agent yet: one action, the wizard, and what the gate will answer. */
function AgentsEmpty({ onConnect }: { onConnect: () => void }) {
  return (
    <section className="agents-empty" aria-labelledby="agents-empty-title">
      <div className="agents-empty-text">
        <h2 id="agents-empty-title">No agents yet</h2>
        <p>
          Connect Claude Code, Cursor or any MCP client in about a minute. It
          gets its own token and reads through the same guard as you.
        </p>
        <Button variant="primary" onClick={onConnect}>
          Connect an agent
        </Button>
      </div>
      <GateLegend />
    </section>
  );
}

function Crumbs({ name }: { name?: string }) {
  return (
    <nav className="trail-crumbs" aria-label="Breadcrumb">
      <ol>
        <li>
          <Link to="/agents">Agents</Link>
        </li>
        <li aria-current="page">{name ?? 'Agent'}</li>
      </ol>
    </nav>
  );
}

const isMissing = (error: unknown) => {
  const status = (error as { status?: number } | null)?.status;
  return status === 404 || status === 400;
};

/** One agent on a page of its own: who it is, what it can reach and how the
 * gate answers it, what it did, and the tokens it connects with. */
function AgentPage({
  id,
  clusters,
  allClusters,
  onGone,
}: {
  id: string;
  clusters: Map<string, Cluster>;
  allClusters: Cluster[];
  onGone: () => void;
}) {
  const user = useUser();
  const agent = useResource<Agent>(`/agents/${encodeURIComponent(id)}`);
  const [editing, setEditing] = useState(false);
  if (agent.error && isMissing(agent.error))
    return (
      <div className="agent-page">
        <Crumbs />
        <section className="empty trail-missing" aria-labelledby="agent-gone">
          <h1 id="agent-gone">Agent not found</h1>
          <p>
            It may have been deleted, or you may not be able to see it. An agent
            is listed for its owner and for administrators.
          </p>
          <Link className="button primary" to="/agents">
            Back to agents
          </Link>
        </section>
      </div>
    );
  if (agent.error && !agent.data)
    return (
      <ErrorPanel error={agent.error} retry={() => void agent.refetch()} />
    );
  if (agent.isPending) return <Skeleton />;
  const owner = agent.data.owner.id === user?.id;
  return (
    <>
      <AgentView
        agent={agent.data}
        owner={owner}
        clusters={clusters}
        onEdit={() => setEditing(true)}
        onGone={onGone}
      />
      <AgentForm
        key={editing ? 'open' : 'closed'}
        agent={agent.data}
        open={editing}
        clusters={allClusters}
        onClose={() => setEditing(false)}
        onSaved={() => setEditing(false)}
      />
    </>
  );
}

function AgentView({
  agent,
  owner,
  clusters,
  onEdit,
  onGone,
}: {
  agent: Agent;
  owner: boolean;
  clusters: Map<string, Cluster>;
  onEdit: () => void;
  onGone: () => void;
}) {
  const remove = useAction('Agent deleted');
  const title = useRef<HTMLHeadingElement>(null);
  // Opening an agent moves the reader to its page: the focus goes to its
  // heading, also for a keyboard user.
  useEffect(() => {
    title.current?.scrollIntoView({ block: 'nearest' });
    title.current?.focus({ preventScroll: true });
  }, []);
  const [deleting, setDeleting] = useState(false);
  const used = lastActive(agent);
  const state = agentState(agent);
  const reach = agent.cluster_ids.map((id) => ({
    id,
    cluster: clusters.get(id),
  }));
  const seen = reach.flatMap((item) => (item.cluster ? [item.cluster] : []));
  const path = `/agents/${encodeURIComponent(agent.id)}`;
  return (
    <section className="agent-page" aria-labelledby="agent-title">
      <Crumbs name={agent.name} />
      <header className="agent-head">
        <div className="agent-head-main">
          <h1
            id="agent-title"
            ref={title}
            tabIndex={-1}
            aria-label={`Agent ${agent.name}`}
            className="agent-title"
          >
            <ActorBadge kind="agent" name={agent.name} />
          </h1>
          <div className="agent-who">
            <span>
              for{' '}
              <ActorBadge
                kind="human"
                name={owner ? 'You' : agent.owner.name}
              />
            </span>
            <span className="agent-state" data-state={state}>
              {agentStateText[state]}
            </span>
            <span className="muted">
              {used ? (
                <>
                  Last call <InlineTime value={used} />
                </>
              ) : (
                'No call yet'
              )}
            </span>
          </div>
          {agent.description && (
            <p className="agent-description">{agent.description}</p>
          )}
        </div>
        <div className="agent-head-actions">
          {owner && <Button onClick={onEdit}>Edit</Button>}
          <PauseButton agent={agent} />
        </div>
      </header>
      {agent.paused && (
        <p className="agent-paused" role="status">
          This agent is paused. Its tokens are refused, and the queries it was
          running on this gateway were cancelled.
        </p>
      )}
      <div className="agent-grid">
        <section className="agent-card" aria-labelledby="agent-reach-title">
          <h2 id="agent-reach-title">What it can reach</h2>
          <p className="agent-level">
            <strong>{levelText[agent.max_level]}.</strong>{' '}
            {levelLine[agent.max_level]}
          </p>
          <ul className="agent-reach">
            {reach.map(({ id, cluster }) => (
              <li key={id}>
                {cluster ? (
                  <>
                    <strong className="identifier">{cluster.name}</strong>
                    <EnvBadge environment={cluster.environment} />
                    <CloudLabel cluster={cluster} />
                  </>
                ) : (
                  <span className="muted">A database you cannot see</span>
                )}
              </li>
            ))}
          </ul>
          <p className="muted agent-small">
            The agent reaches a database only while its owner can. When the
            owner loses access, the agent loses it on its next request.
          </p>
        </section>
        <section className="agent-card" aria-labelledby="agent-answers-title">
          <h2 id="agent-answers-title">
            How the gate answers{' '}
            <span className="identifier">{agent.name}</span>
          </h2>
          <GateAnswers
            level={agent.max_level}
            databases={seen}
            unseen={reach.length - seen.length}
            owner={owner ? undefined : agent.owner.name}
          />
        </section>
      </div>
      <section className="agent-section" aria-labelledby="agent-sessions-title">
        <div className="agent-section-head">
          <h2 id="agent-sessions-title">Sessions</h2>
          <p className="muted">
            What the agent did, call by call. A session is a run of calls of one
            token with no gap longer than 30 minutes. Steps keep the SQL, never
            the rows.
          </p>
        </div>
        <SessionList agent={agent} />
      </section>
      <Tokens agent={agent} owner={owner} path={path} />
      <div className="agent-grid">
        <section className="agent-card" aria-labelledby="agent-rails-title">
          <h2 id="agent-rails-title">Guardrails</h2>
          <dl className="agent-guardrails">
            <Guardrail title="Writes need a person" state="Always on">
              The agent cannot change data on its own. It can ask for a write,
              which opens a request for its owner. A person previews it, a
              person who is not the owner approves it, and a person runs it.
            </Guardrail>
            <Guardrail title="Protected columns" state="Always on">
              The gateway masks protected columns in every result. On a database
              that has an agent login, the database itself also refuses to read
              them.
            </Guardrail>
            <Guardrail title="Blocked tables" state="Always on">
              The guard refuses a query on a blocked table. On a database that
              has an agent login, the database itself also refuses.
            </Guardrail>
            <Guardrail
              title="Hourly budget"
              state={`${agent.hourly_query_budget.toLocaleString('en')} queries / hour`}
            >
              Each query counts, also a refused one. When the budget is used,
              the agent waits.
            </Guardrail>
            <Guardrail title="Rate limit" state="120 calls / min">
              The gateway refuses tool calls above this rate.
            </Guardrail>
            <Guardrail title="Loop breaker" state="5 refusals">
              After five refused queries in a row, the agent can run no query
              for up to ten minutes and is told to go back to its owner. Its
              other tools still work.
            </Guardrail>
            <Guardrail title="Task is required" state="Always on">
              Each call must say what it is for. The audit log keeps it.
            </Guardrail>
          </dl>
        </section>
        <section className="agent-card" aria-labelledby="agent-tools-title">
          <h2 id="agent-tools-title">Tools the agent gets</h2>
          <ul className="agent-tools">
            {tools.map(([name, purpose]) => (
              <li key={name}>
                <code>{name}</code>
                <span className="muted">{purpose}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
      <section className="agent-danger" aria-labelledby="agent-delete-title">
        <div>
          <h2 id="agent-delete-title">Delete this agent</h2>
          <p className="muted">
            Its tokens stop working at once, and its sessions go with it.
          </p>
        </div>
        <Button variant="danger" onClick={() => setDeleting(true)}>
          Delete
        </Button>
      </section>
      <Confirm
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete ${agent.name}?`}
        description="Its tokens stop working at once. Its sessions and steps are deleted with it. Its query history and the audit log stay."
        danger
        onConfirm={() =>
          remove.mutate(
            { path, method: 'DELETE' },
            { onSuccess: () => onGone() },
          )
        }
      />
    </section>
  );
}

/** The agent's tokens, newest first. A revoked token stays listed. After a
 * Revoke the focus moves to the next token that can still be revoked, or to
 * the heading of the list: never to the page. */
function Tokens({
  agent,
  owner,
  path,
}: {
  agent: Agent;
  owner: boolean;
  path: string;
}) {
  const revoke = useAction('Token revoked');
  const [minting, setMinting] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const revoked = useRef<string | null>(null);
  useEffect(() => {
    const id = revoked.current;
    const gone = agent.tokens.find((token) => token.id === id);
    if (!id || (gone && tokenState(gone) === 'Active')) return;
    revoked.current = null;
    const at = agent.tokens.findIndex((token) => token.id === id);
    const order = [
      ...agent.tokens.slice(at + 1),
      ...agent.tokens.slice(0, Math.max(at, 0)).reverse(),
    ];
    const next = order.find((token) => tokenState(token) === 'Active');
    const button = next
      ? list.current?.querySelector<HTMLButtonElement>(
          `[data-token="${next.id}"]`,
        )
      : null;
    (button ?? heading.current)?.focus();
  }, [agent.tokens]);
  return (
    <section className="agent-section" aria-labelledby="agent-tokens-title">
      <div className="agent-section-head agent-section-row">
        <div>
          <h2 id="agent-tokens-title" ref={heading} tabIndex={-1}>
            Tokens
          </h2>
          <p className="muted">
            A token is how a client connects. It acts with the owner&apos;s
            access to the agent&apos;s databases, and it never holds a database
            password.
          </p>
        </div>
        {owner && (
          <Button onClick={() => setMinting(true)}>Create token</Button>
        )}
      </div>
      {agent.tokens.length === 0 ? (
        <p className="muted">
          This agent has no token, so it cannot connect yet.
          {!owner && ' Only its owner can make one.'}
        </p>
      ) : (
        <div
          className="table-wrap agent-tokens"
          tabIndex={0}
          role="region"
          aria-label="Tokens list"
          ref={list}
        >
          <table aria-label="Tokens" className="card-rows">
            <thead>
              <tr>
                <th>Token</th>
                <th>State</th>
                <th>Made</th>
                <th>Expires</th>
                <th>Last used</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {agent.tokens.map((token) => {
                const state = tokenState(token);
                return (
                  <tr key={token.id} data-state={state.toLowerCase()}>
                    <td data-label="Token" className="card-title mono">
                      vda_agent_••••{token.hint}
                    </td>
                    <td data-label="State">
                      <span
                        className="agent-token-state"
                        data-state={state.toLowerCase()}
                      >
                        {state}
                        {state === 'Revoked' && token.revoked_at && (
                          <>
                            {' '}
                            <InlineTime value={token.revoked_at} />
                          </>
                        )}
                      </span>
                    </td>
                    <td data-label="Made">
                      <RelativeTime value={token.created_at} />
                    </td>
                    <td data-label="Expires">{formatTime(token.expires_at)}</td>
                    <td data-label="Last used">
                      {token.last_used_at ? (
                        <RelativeTime value={token.last_used_at} />
                      ) : (
                        <span className="muted">Not yet</span>
                      )}
                    </td>
                    <td className="card-actions">
                      {state === 'Active' && (
                        <Button
                          data-token={token.id}
                          aria-label={`Revoke token ending ${token.hint}`}
                          aria-disabled={revoke.isPending || undefined}
                          onClick={() => {
                            if (revoke.isPending) return;
                            revoked.current = token.id;
                            revoke.mutate({
                              path: `${path}/tokens/${token.id}`,
                              method: 'DELETE',
                            });
                          }}
                        >
                          Revoke
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {/* Mounted only while open: when it closes, the component that held
          the token is gone, and nothing in this one ever saw it. */}
      {minting && <TokenDialog path={path} onClose={() => setMinting(false)} />}
    </section>
  );
}

/** Creates a token and shows it one time. It owns the secret, and it is
 * unmounted when it closes, so the secret does not outlive the dialog. */
function TokenDialog({ path, onClose }: { path: string; onClose: () => void }) {
  // No toast: the dialog itself shows the token, and nothing may cover it.
  const mint = useAction<NewAgentToken>('');
  const { state: copied, copy } = useInlineCopy();
  const [days, setDays] = useState('30'),
    [fresh, setFresh] = useState<NewAgentToken | null>(null);
  // The one way to close. Not while the request is under way: a token made
  // after the dialog closed would be live and unseen.
  const close = () => {
    if (!mint.isPending) onClose();
  };
  return (
    <Modal
      open
      onOpenChange={(open) => {
        if (!open) close();
      }}
      wide={!!fresh}
      // While the token shows, only Done closes: a stray Escape or click
      // must not lose it.
      dismissible={!fresh}
      title={fresh ? 'Copy the token now' : 'Create a token'}
      description={
        fresh
          ? 'The token shows one time only. The agent never gets a database password.'
          : 'A token lets the agent act with your access to its databases.'
      }
    >
      {fresh ? (
        <>
          <ClientSnippets token={fresh.token} />
          <p className="muted">Expires {formatTime(fresh.expires_at)}.</p>
          <div className="dialog-actions">
            <CopyResult state={copied} />
            <Button onClick={() => void copy(fresh.token)}>Copy token</Button>
            <Button variant="primary" onClick={close}>
              Done
            </Button>
          </div>
        </>
      ) : (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            mint.mutate(
              {
                path: `${path}/tokens`,
                body: { expires_in_days: Number(days) },
              },
              { onSuccess: (token) => setFresh(token) },
            );
          }}
        >
          <Field label="Valid for" hint="1 to 90 days.">
            <Picker
              label="Valid for"
              value={days}
              onChange={setDays}
              options={[
                { value: '7', label: '7 days' },
                { value: '30', label: '30 days' },
                { value: '90', label: '90 days' },
              ]}
            />
          </Field>
          <div className="dialog-actions">
            <Button type="button" disabled={mint.isPending} onClick={close}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" disabled={mint.isPending}>
              Create token
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}

function Guardrail({
  title,
  state,
  children,
}: {
  title: string;
  state: string;
  children: string;
}) {
  return (
    <div className="agent-guardrail">
      <dt>
        {title}
        <span className="agent-guardrail-state">{state}</span>
      </dt>
      <dd className="muted">{children}</dd>
    </div>
  );
}

function AgentForm({
  agent,
  open,
  clusters,
  onClose,
  onSaved,
}: {
  agent: Agent;
  open: boolean;
  clusters: Cluster[];
  onClose: () => void;
  onSaved: (agent: Agent) => void;
}) {
  const save = useAction<Agent>('Agent saved');
  const [name, setName] = useState(agent.name),
    [description, setDescription] = useState(agent.description),
    [level, setLevel] = useState<string>(agent.max_level),
    [budget, setBudget] = useState(String(agent.hourly_query_budget)),
    [chosen, setChosen] = useState<string[]>(agent.cluster_ids);
  const reachable = clusters.filter((cluster) => cluster.my_access);
  // Databases that the agent has but the owner can no longer reach. They
  // cannot be kept when the list changes: the server refuses them.
  const lost = agent.cluster_ids.filter(
    (id) => !reachable.some((cluster) => cluster.id === id),
  );
  const kept = chosen.filter((id) => !lost.includes(id));
  const same = (a: string[], b: string[]) =>
    a.length === b.length &&
    [...a].sort((a, b) => a.localeCompare(b)).join() ===
      [...b].sort((a, b) => a.localeCompare(b)).join();
  const listChanged = !same(
    kept,
    agent.cluster_ids.filter((id) => !lost.includes(id)),
  );
  const changed =
    listChanged ||
    name.trim() !== agent.name ||
    description !== agent.description ||
    level !== agent.max_level ||
    Number(budget) !== agent.hourly_query_budget;
  const valid =
    changed &&
    name.trim().length > 0 &&
    // A list is needed when the list itself changes.
    (!listChanged || kept.length > 0) &&
    Number.isInteger(Number(budget)) &&
    Number(budget) >= 1 &&
    Number(budget) <= 100000;
  return (
    <Modal
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title={`Edit ${agent.name}`}
      description="The agent acts for you. It can reach only the databases you pick here, and only while you can reach them."
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate(
            {
              path: `/agents/${encodeURIComponent(agent.id)}`,
              method: 'PATCH',
              // An edit sends only what changed, so an untouched field can
              // never be refused.
              body: {
                ...(name.trim() !== agent.name && { name: name.trim() }),
                ...(description !== agent.description && { description }),
                ...(level !== agent.max_level && { max_level: level }),
                ...(listChanged && { cluster_ids: kept }),
                ...(Number(budget) !== agent.hourly_query_budget && {
                  hourly_query_budget: Number(budget),
                }),
              },
            },
            { onSuccess: onSaved },
          );
        }}
      >
        <Field label="Name">
          <input
            value={name}
            maxLength={100}
            onChange={(event) => setName(event.target.value)}
            required
          />
        </Field>
        <Field label="What it is for" hint="Optional.">
          <input
            value={description}
            maxLength={2000}
            onChange={(event) => setDescription(event.target.value)}
          />
        </Field>
        <Field
          label="Level"
          hint="An agent never writes on its own. With either choice, a statement that writes is refused and the agent is told to ask you."
        >
          <Picker
            label="Level"
            value={level}
            onChange={setLevel}
            options={[
              { value: 'read', label: levelText.read },
              { value: 'write', label: levelText.write },
            ]}
          />
        </Field>
        <fieldset className="agent-clusters">
          <legend>Databases it can reach</legend>
          {reachable.length === 0 ? (
            <p className="muted">You have access to no database yet.</p>
          ) : (
            reachable.map((cluster) => (
              <label key={cluster.id}>
                <input
                  type="checkbox"
                  checked={chosen.includes(cluster.id)}
                  onChange={(event) =>
                    setChosen(
                      event.target.checked
                        ? [...chosen, cluster.id]
                        : chosen.filter((id) => id !== cluster.id),
                    )
                  }
                />
                <span className="identifier">{cluster.name}</span>
                <EnvBadge environment={cluster.environment} />
              </label>
            ))
          )}
        </fieldset>
        {lost.length > 0 && (
          <p className="muted agent-lost">
            This agent also has {lost.length}{' '}
            {lost.length === 1 ? 'database' : 'databases'} that you cannot reach
            any more. It cannot use {lost.length === 1 ? 'it' : 'them'}, and{' '}
            {lost.length === 1 ? 'it is' : 'they are'} removed when you change
            the list above.
          </p>
        )}
        <Field
          label="Queries per hour"
          hint="1 to 100,000. Refused queries count too."
        >
          <input
            inputMode="numeric"
            value={budget}
            onChange={(event) => setBudget(event.target.value)}
          />
        </Field>
        <div className="dialog-actions">
          <Button type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            type="submit"
            disabled={!valid || save.isPending}
          >
            Save
          </Button>
        </div>
      </form>
    </Modal>
  );
}
