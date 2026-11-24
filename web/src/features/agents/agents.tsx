import { useEffect, useMemo, useRef, useState } from 'react';
import { Navigate, useSearchParams } from 'react-router-dom';
import { Bot } from 'lucide-react';
import type { Agent, Cluster, NewAgentToken } from '../../api/types';
import { useCopy } from '../../lib/clipboard';
import { useAction, useAllPages, useResource } from '../../lib/query';
import {
  Badge,
  Button,
  Confirm,
  Empty,
  ErrorPanel,
  Field,
  Modal,
  Picker,
  Skeleton,
} from '../../components/ui';
import { CloudLabel } from '../../components/ui/cluster-heading';
import { RelativeTime } from '../../components/ui/time';
import { formatTime } from '../../lib/utils';
import { useUser } from '../auth/session';
import { SessionList } from './sessions';
import { sessionPath } from './session-trail';

const levelText = {
  read: 'Read only',
  write: 'Read, and may ask for writes',
} as const;
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
const tokenState = (token: Agent['tokens'][number]) =>
  token.revoked_at
    ? 'Revoked'
    : new Date(token.expires_at).getTime() <= Date.now()
      ? 'Expired'
      : 'Active';
const liveTokens = (agent: Agent) =>
  agent.tokens.filter((token) => tokenState(token) === 'Active').length;

export function AgentsPage() {
  const user = useUser();
  // Every page: an administrator must be able to find and stop any agent.
  const agents = useAllPages<Agent>('/agents'),
    clusters = useResource<{ items: Cluster[] }>('/clusters');
  const [params, setParams] = useSearchParams();
  const [editing, setEditing] = useState<Agent | 'new' | null>(null);
  const selected = agents.data?.items.find((a) => a.id === params.get('agent'));
  const names = useMemo(
    () => new Map(clusters.data?.items.map((c) => [c.id, c]) ?? []),
    [clusters.data],
  );
  // An old link to a session opens the session's own page.
  const legacy = params.get('session');
  if (legacy && params.get('agent'))
    return <Navigate replace to={sessionPath(params.get('agent')!, legacy)} />;
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>Agents</h1>
          <p>Programs that query for a person.</p>
        </div>
        <Button variant="primary" onClick={() => setEditing('new')}>
          Connect an agent
        </Button>
      </div>
      <p className="agents-rule muted">
        Each agent has one owner. The owner answers for what the agent does. An
        agent can never do more than its owner can do at that moment.
      </p>
      {agents.isPending ? (
        <Skeleton />
      ) : agents.error ? (
        <ErrorPanel error={agents.error} retry={() => void agents.refetch()} />
      ) : agents.data.items.length === 0 ? (
        <Empty
          title="No agents yet"
          description="Connect a program, such as an AI assistant, so that it can read data through the same guard as you."
          action={
            <Button onClick={() => setEditing('new')}>Connect an agent</Button>
          }
        />
      ) : (
        <div className="agents-layout">
          <div
            className="table-wrap"
            tabIndex={0}
            role="region"
            aria-label="Agents list"
          >
            <table aria-label="Agents">
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Owner</th>
                  <th>Reach</th>
                  <th>Level</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {agents.data.items.map((agent) => (
                  <tr
                    key={agent.id}
                    className={agent.id === selected?.id ? 'selected' : ''}
                  >
                    <td>
                      <button
                        type="button"
                        className="link-button strong"
                        aria-current={
                          agent.id === selected?.id ? 'true' : undefined
                        }
                        onClick={() => setParams({ agent: agent.id })}
                      >
                        <Bot size={16} aria-hidden="true" />
                        {agent.name}
                      </button>
                    </td>
                    <td>{agent.owner.name}</td>
                    <td>
                      {agent.cluster_ids.length === 1
                        ? (names.get(agent.cluster_ids[0]!)?.name ??
                          '1 database')
                        : `${agent.cluster_ids.length} databases`}
                    </td>
                    <td>{levelText[agent.max_level]}</td>
                    <td>
                      <Badge tone={agent.paused ? 'warning' : 'neutral'}>
                        {agent.paused
                          ? 'Paused'
                          : liveTokens(agent) === 0
                            ? 'No token'
                            : 'Active'}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {selected && (
            <AgentDetail
              key={selected.id}
              agent={selected}
              owner={selected.owner.id === user?.id}
              clusters={names}
              onEdit={() => setEditing(selected)}
              onGone={() => setParams({})}
            />
          )}
        </div>
      )}
      <AgentForm
        key={editing === 'new' ? 'new' : (editing?.id ?? 'closed')}
        agent={editing === 'new' ? undefined : (editing ?? undefined)}
        open={editing !== null}
        clusters={clusters.data?.items ?? []}
        onClose={() => setEditing(null)}
        onSaved={(agent) => {
          setEditing(null);
          setParams({ agent: agent.id });
        }}
      />
    </>
  );
}

function AgentDetail({
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
  const pause = useAction<Agent>(
      agent.paused ? 'Agent resumed' : 'Agent paused',
    ),
    remove = useAction('Agent deleted'),
    revoke = useAction('Token revoked');
  const region = useRef<HTMLElement>(null);
  // The detail is below the list. Bring it into view and give it focus, so
  // that choosing an agent visibly does something, also with a keyboard.
  useEffect(() => {
    region.current?.scrollIntoView({ block: 'nearest' });
    region.current?.focus({ preventScroll: true });
  }, []);
  const [deleting, setDeleting] = useState(false),
    [minting, setMinting] = useState(false);
  const lastUsed = agent.tokens
    .map((token) => token.last_used_at)
    .filter((value): value is string => !!value)
    .sort((a, b) => a.localeCompare(b))
    .at(-1);
  const path = `/agents/${agent.id}`;
  return (
    <section
      className="agent-detail"
      aria-label={`Agent ${agent.name}`}
      ref={region}
      tabIndex={-1}
    >
      <header className="agent-detail-heading">
        <div>
          <h2>{agent.name}</h2>
          <p className="muted">
            Owner: {agent.owner.name}.{' '}
            {lastUsed ? (
              <>
                Token last used <RelativeTime value={lastUsed} />.
              </>
            ) : (
              'No token has been used yet.'
            )}
          </p>
          {agent.description && <p>{agent.description}</p>}
        </div>
        <div className="agent-actions">
          {owner && <Button onClick={onEdit}>Edit</Button>}
          <Button
            disabled={pause.isPending}
            onClick={() =>
              pause.mutate({
                path,
                method: 'PATCH',
                body: { paused: !agent.paused },
              })
            }
          >
            {agent.paused ? 'Resume agent' : 'Pause agent'}
          </Button>
          <Button variant="danger" onClick={() => setDeleting(true)}>
            Delete
          </Button>
        </div>
      </header>
      {agent.paused && (
        <p className="agent-paused" role="status">
          This agent is paused. Its tokens are refused, and the queries it was
          running on this gateway were cancelled.
        </p>
      )}
      <SessionList agent={agent} />
      <h3>What it can reach</h3>
      <ul className="agent-reach">
        {agent.cluster_ids.map((id) => {
          const cluster = clusters.get(id);
          return (
            <li key={id}>
              {cluster ? (
                <>
                  <strong className="identifier">{cluster.name}</strong>
                  <span className={`environment-word ${cluster.environment}`}>
                    {cluster.environment.charAt(0).toUpperCase() +
                      cluster.environment.slice(1)}
                  </span>
                  <CloudLabel cluster={cluster} />
                </>
              ) : (
                <span className="muted">A database you cannot see</span>
              )}
              <span className="agent-level">{levelText[agent.max_level]}</span>
            </li>
          );
        })}
      </ul>
      <p className="muted">
        The agent reaches a database only while its owner can. When the owner
        loses access, the agent loses it on its next request.
      </p>
      <h3>Guardrails</h3>
      <dl className="agent-guardrails">
        <Guardrail title="Writes need a person" state="Always on">
          The agent cannot change data on its own. It can ask for a write, which
          opens a request for its owner. A person previews it, a person who is
          not the owner approves it, and a person runs it.
        </Guardrail>
        <Guardrail title="Protected columns" state="Always on">
          The gateway masks protected columns in every result. On a database
          that has an agent login, the database itself also refuses to read
          them.
        </Guardrail>
        <Guardrail title="Blocked tables" state="Always on">
          The guard refuses a query on a blocked table. On a database that has
          an agent login, the database itself also refuses.
        </Guardrail>
        <Guardrail
          title="Hourly budget"
          state={`${agent.hourly_query_budget.toLocaleString('en')} queries / hour`}
        >
          Each query counts, also a refused one. When the budget is used, the
          agent waits.
        </Guardrail>
        <Guardrail title="Rate limit" state="120 calls / min">
          The gateway refuses tool calls above this rate.
        </Guardrail>
        <Guardrail title="Loop breaker" state="5 refusals">
          After five refused queries in a row, the agent can run no query for up
          to ten minutes and is told to go back to its owner. Its other tools
          still work.
        </Guardrail>
        <Guardrail title="Task is required" state="Always on">
          Each call must say what it is for. The audit log keeps it.
        </Guardrail>
      </dl>
      <div className="agent-section-heading">
        <h3>Tokens</h3>
        {owner && (
          <Button onClick={() => setMinting(true)}>Create token</Button>
        )}
      </div>
      {agent.tokens.length === 0 ? (
        <p className="muted">
          This agent has no token, so it cannot connect yet.
        </p>
      ) : (
        <div
          className="table-wrap"
          tabIndex={0}
          role="region"
          aria-label="Tokens list"
        >
          <table aria-label="Tokens">
            <thead>
              <tr>
                <th>Token</th>
                <th>State</th>
                <th>Expires</th>
                <th>Last used</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {agent.tokens.map((token) => (
                <tr key={token.id}>
                  <td className="mono">vda_agent_••••{token.hint}</td>
                  <td>{tokenState(token)}</td>
                  <td>{formatTime(token.expires_at)}</td>
                  <td>
                    {token.last_used_at ? (
                      <RelativeTime value={token.last_used_at} />
                    ) : (
                      'Never'
                    )}
                  </td>
                  <td>
                    {tokenState(token) === 'Active' && (
                      <Button
                        aria-label={`Revoke token ending ${token.hint}`}
                        disabled={revoke.isPending}
                        onClick={() =>
                          revoke.mutate({
                            path: `${path}/tokens/${token.id}`,
                            method: 'DELETE',
                          })
                        }
                      >
                        Revoke
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <h3>Tools the agent gets</h3>
      <ul className="agent-tools">
        {tools.map(([name, purpose]) => (
          <li key={name}>
            <code>{name}</code> <span className="muted">– {purpose}</span>
          </li>
        ))}
      </ul>
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
      {/* Mounted only while open: when it closes, the component that held
          the token is gone, and nothing in this one ever saw it. */}
      {minting && <TokenDialog path={path} onClose={() => setMinting(false)} />}
    </section>
  );
}

/** Creates a token and shows it one time. It owns the secret, and it is
 * unmounted when it closes, so the secret does not outlive the dialog. */
function TokenDialog({ path, onClose }: { path: string; onClose: () => void }) {
  const mint = useAction<NewAgentToken>('Token created');
  const copy = useCopy();
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
      title={fresh ? 'Copy the token now' : 'Create a token'}
      description={
        fresh
          ? 'The token shows one time only. The agent never gets a database password.'
          : 'A token lets the agent act with your access to its databases.'
      }
    >
      {fresh ? (
        <>
          <Field label="Connection">
            <textarea
              readOnly
              rows={14}
              className="mono"
              value={JSON.stringify(
                {
                  mcpServers: {
                    'database-gateway': {
                      type: 'http',
                      url: `${globalThis.location?.origin ?? ''}/api/v1/mcp`,
                      headers: { Authorization: `Bearer ${fresh.token}` },
                    },
                  },
                },
                null,
                2,
              )}
              onFocus={(event) => event.currentTarget.select()}
            />
          </Field>
          <p className="muted">Expires {formatTime(fresh.expires_at)}.</p>
          <div className="dialog-actions">
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
  agent?: Agent;
  open: boolean;
  clusters: Cluster[];
  onClose: () => void;
  onSaved: (agent: Agent) => void;
}) {
  const save = useAction<Agent>(agent ? 'Agent saved' : 'Agent connected');
  const [name, setName] = useState(agent?.name ?? ''),
    [description, setDescription] = useState(agent?.description ?? ''),
    [level, setLevel] = useState<string>(agent?.max_level ?? 'read'),
    [budget, setBudget] = useState(String(agent?.hourly_query_budget ?? 300)),
    [chosen, setChosen] = useState<string[]>(agent?.cluster_ids ?? []);
  const reachable = clusters.filter((cluster) => cluster.my_access);
  // Databases that the agent has but the owner can no longer reach. They
  // cannot be kept when the list changes: the server refuses them.
  const lost = (agent?.cluster_ids ?? []).filter(
    (id) => !reachable.some((cluster) => cluster.id === id),
  );
  const kept = chosen.filter((id) => !lost.includes(id));
  const same = (a: string[], b: string[]) =>
    a.length === b.length &&
    [...a].sort((a, b) => a.localeCompare(b)).join() ===
      [...b].sort((a, b) => a.localeCompare(b)).join();
  const listChanged =
    !agent ||
    !same(
      kept,
      agent.cluster_ids.filter((id) => !lost.includes(id)),
    );
  const changed =
    !agent ||
    listChanged ||
    name.trim() !== agent.name ||
    description !== agent.description ||
    level !== agent.max_level ||
    Number(budget) !== agent.hourly_query_budget;
  const valid =
    changed &&
    name.trim().length > 0 &&
    // A list is needed for a new agent, and when the list itself changes.
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
      title={agent ? `Edit ${agent.name}` : 'Connect an agent'}
      description="The agent acts for you. It can reach only the databases you pick here, and only while you can reach them."
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate(
            {
              path: agent ? `/agents/${agent.id}` : '/agents',
              method: agent ? 'PATCH' : 'POST',
              // An edit sends only what changed, so an untouched field can
              // never be refused.
              body: agent
                ? {
                    ...(name.trim() !== agent.name && { name: name.trim() }),
                    ...(description !== agent.description && { description }),
                    ...(level !== agent.max_level && { max_level: level }),
                    ...(listChanged && { cluster_ids: kept }),
                    ...(Number(budget) !== agent.hourly_query_budget && {
                      hourly_query_budget: Number(budget),
                    }),
                  }
                : {
                    name: name.trim(),
                    description,
                    max_level: level,
                    cluster_ids: kept,
                    hourly_query_budget: Number(budget),
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
                <span className={`environment-word ${cluster.environment}`}>
                  {cluster.environment.charAt(0).toUpperCase() +
                    cluster.environment.slice(1)}
                </span>
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
            {agent ? 'Save' : 'Connect agent'}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
