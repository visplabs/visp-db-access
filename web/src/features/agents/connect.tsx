// "Connect an agent": a page in four steps, from nothing to the agent's
// first guarded call. The agent and its token are made at step three; the
// token lives only in this component and is gone when the page closes.
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowLeft,
  Braces,
  Check,
  Copy,
  MousePointerClick,
  SquareTerminal,
} from 'lucide-react';
import type {
  Agent,
  AgentSession,
  AgentStep,
  AgentSteps,
  Cluster,
  NewAgentToken,
  Page,
  User,
} from '../../api/types';
import { request } from '../../api/client';
import { useCopy } from '../../lib/clipboard';
import { useAction } from '../../lib/query';
import { verdictOfStep } from '../../lib/verdict';
import { toolText } from '../../lib/sessions';
import { sessionPath } from './session-trail';
import { formatTime, message } from '../../lib/utils';
import {
  ActorBadge,
  Button,
  EnvBadge,
  Field,
  SegmentedControl,
  VerdictChip,
} from '../../components/ui';
import { RelativeTime } from '../../components/ui/time';

/** The name every MCP config printed by the console gives the gate. */
export const SERVER_NAME = 'visp-gate';
/** The agent door: `POST /api/v1/mcp` on the console's own origin. */
export const mcpUrl = () => `${globalThis.location?.origin ?? ''}/api/v1/mcp`;

export type Client = 'claude-code' | 'cursor' | 'other';
export const CLIENTS: {
  value: Client;
  name: string;
  line: string;
  Icon: typeof Braces;
}[] = [
  {
    value: 'claude-code',
    name: 'Claude Code',
    line: 'One command in your terminal adds the gate.',
    Icon: SquareTerminal,
  },
  {
    value: 'cursor',
    name: 'Cursor',
    line: 'A few lines in .cursor/mcp.json.',
    Icon: MousePointerClick,
  },
  {
    value: 'other',
    name: 'Other MCP client',
    line: 'JSON that most MCP clients read.',
    Icon: Braces,
  },
];

/** What to paste into a client: a command or a config file holding the
 * token. Never a database password: the gate holds those. */
export function snippetFor(client: Client, token: string, url = mcpUrl()) {
  const headers = { Authorization: `Bearer ${token}` };
  switch (client) {
    case 'claude-code':
      return {
        title: 'Run in your terminal',
        label: 'Claude Code command',
        text: `claude mcp add --transport http ${SERVER_NAME} ${url} --header "Authorization: Bearer ${token}"`,
      };
    case 'cursor':
      return {
        title: '.cursor/mcp.json',
        label: 'Cursor config',
        text: JSON.stringify(
          { mcpServers: { [SERVER_NAME]: { url, headers } } },
          null,
          2,
        ),
      };
    case 'other':
      return {
        title: 'MCP config (JSON)',
        label: 'MCP config',
        text: JSON.stringify(
          { mcpServers: { [SERVER_NAME]: { type: 'http', url, headers } } },
          null,
          2,
        ),
      };
  }
}
/** A first thing to ask, which makes the agent call the gate once. */
export const FIRST_PROMPT = `List the databases you can use through ${SERVER_NAME}.`;

/** Copy, and say what happened on the spot rather than in a toast: nothing
 * may cover a one-time token. The answer is spoken once. */
export function useInlineCopy() {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  useEffect(() => {
    if (state !== 'copied') return;
    const timer = setTimeout(() => setState('idle'), 2500);
    return () => clearTimeout(timer);
  }, [state]);
  const copy = async (text: string) => {
    try {
      if (!navigator.clipboard) throw new Error('unavailable');
      await navigator.clipboard.writeText(text);
      setState('copied');
    } catch {
      setState('failed');
    }
  };
  return { state, copy };
}

/** What the copy did, in a live region next to the button. */
export function CopyResult({ state }: { state: 'idle' | 'copied' | 'failed' }) {
  return (
    <span className="connect-copied" role="status" data-state={state}>
      {state === 'copied'
        ? 'Copied'
        : state === 'failed'
          ? 'Could not copy. Select it yourself.'
          : ''}
    </span>
  );
}

/** A snippet with the token marked, and its own Copy button. */
export function Snippet({ client, token }: { client: Client; token: string }) {
  const { state, copy } = useInlineCopy();
  const snippet = snippetFor(client, token);
  const [before, after] = splitOnce(snippet.text, token);
  return (
    <figure className="connect-snippet" data-client={client}>
      <figcaption>
        <span className="connect-snippet-title">{snippet.title}</span>
        <span className="connect-copy">
          <CopyResult state={state} />
          <Button size="small" onClick={() => void copy(snippet.text)}>
            {state === 'copied' ? (
              <Check size={14} aria-hidden="true" />
            ) : (
              <Copy size={14} aria-hidden="true" />
            )}
            Copy
          </Button>
        </span>
      </figcaption>
      {/* A scrolling region: keyboard users focus it to scroll a long line. */}
      <pre tabIndex={0} role="region" aria-label={snippet.label}>
        <code>
          {before}
          {after !== undefined && (
            <>
              <mark>{token}</mark>
              {after}
            </>
          )}
        </code>
      </pre>
    </figure>
  );
}
const splitOnce = (text: string, part: string): [string, string?] => {
  const at = text.indexOf(part);
  return at < 0 ? [text] : [text.slice(0, at), text.slice(at + part.length)];
};

/** The line under every snippet. */
export function SnippetNote() {
  return (
    <p className="connect-note">
      This holds a gate token, never a database password. You can revoke the
      token at once on the agent&apos;s page.
    </p>
  );
}

/** A client picker and its snippet, for a token made on the agent's page. */
export function ClientSnippets({ token }: { token: string }) {
  const [client, setClient] = useState<Client>('claude-code');
  return (
    <div className="connect-snippets">
      <SegmentedControl
        label="Client"
        value={client}
        onChange={(value) => setClient(value as Client)}
        items={CLIENTS.map((item) => ({
          value: item.value,
          label: item.value === 'other' ? 'Other' : item.name,
        }))}
      />
      <Snippet client={client} token={token} />
      <SnippetNote />
    </div>
  );
}

const STEPS = ['Who and what', 'Pick your client', 'Copy and run', 'Verify'];
/** What each step asks, above its fields. */
const heading = (step: number, client: Client) =>
  [
    'Who is it, and what can it reach?',
    'Where will the agent run?',
    `Paste this into ${CLIENTS.find((item) => item.value === client)?.name ?? 'your client'}`,
    'Ask it something',
  ][step];
const EXPIRY = [
  { value: '7', label: '7 days' },
  { value: '30', label: '30 days' },
  { value: '90', label: '90 days' },
];
const environmentRank = { development: 0, staging: 1, production: 2 };
/** The database picked at first: the least risky one the person can reach. */
const safest = (clusters: Cluster[]) =>
  [...clusters].sort(
    (a, b) =>
      (environmentRank[a.environment as keyof typeof environmentRank] ?? 3) -
      (environmentRank[b.environment as keyof typeof environmentRank] ?? 3),
  )[0];
/** A free name among the person's own agents, so Continue just works. */
const freeName = (taken: string[]) => {
  const names = new Set(taken.map((name) => name.toLowerCase()));
  for (let n = 1; ; n += 1) {
    const name = n === 1 ? 'my-agent' : `my-agent-${n}`;
    if (!names.has(name)) return name;
  }
};

export function ConnectWizard({
  user,
  clusters,
  ownNames,
  onClose,
}: {
  user: User | null | undefined;
  clusters: Cluster[];
  /** Names of the person's own agents: a new one must differ. */
  ownNames: string[];
  /** Leave the page; with the id of the agent once it exists. */
  onClose: (agent?: string) => void;
}) {
  const reachable = clusters.filter((cluster) => cluster.my_access);
  const [step, setStep] = useState(0);
  const [name, setName] = useState(() => freeName(ownNames)),
    [description, setDescription] = useState(''),
    [level, setLevel] = useState<'read' | 'write'>('read'),
    [days, setDays] = useState('30'),
    [budget, setBudget] = useState('300'),
    [chosen, setChosen] = useState<string[]>(() => {
      const first = safest(reachable);
      return first ? [first.id] : [];
    }),
    [client, setClient] = useState<Client>('claude-code');
  const [agent, setAgent] = useState<Agent | null>(null),
    [token, setToken] = useState<NewAgentToken | null>(null);
  // No toast: the next step itself shows the agent and its token, and a
  // toast could cover the command that holds the token. Errors show in place.
  const save = useAction<Agent>('', { quietErrors: true }),
    mint = useAction<NewAgentToken>('', { quietErrors: true });
  const busy = save.isPending || mint.isPending;
  // A new step starts at its top, with the focus on its heading: on a phone
  // the button that moved on is far below it.
  const panel = useRef<HTMLElement>(null),
    stepHeading = useRef<HTMLHeadingElement>(null),
    shownStep = useRef(step);
  useEffect(() => {
    if (shownStep.current === step) return;
    shownStep.current = step;
    const narrow = globalThis.matchMedia?.('(max-width: 700px)').matches;
    panel.current?.scrollIntoView({ block: narrow ? 'start' : 'nearest' });
    stepHeading.current?.focus({ preventScroll: true });
  }, [step]);
  const taken = ownNames.some(
    (other) => other.toLowerCase() === name.trim().toLowerCase(),
  );
  const budgetOk =
    Number.isInteger(Number(budget)) &&
    Number(budget) >= 1 &&
    Number(budget) <= 100000;
  const valid =
    name.trim().length > 0 && !taken && chosen.length > 0 && budgetOk;
  const makeToken = (id: string) =>
    mint.mutate(
      { path: `/agents/${id}/tokens`, body: { expires_in_days: Number(days) } },
      {
        onSuccess: (fresh) => {
          setToken(fresh);
          setStep(2);
        },
      },
    );
  // The agent and its token are made together, when the person asks for
  // the snippet. A token that failed is asked for again; the agent stays.
  const create = () => {
    if (agent) return makeToken(agent.id);
    save.mutate(
      {
        path: '/agents',
        body: {
          name: name.trim(),
          description,
          max_level: level,
          cluster_ids: chosen,
          hourly_query_budget: Number(budget),
        },
      },
      {
        onSuccess: (made) => {
          setAgent(made);
          makeToken(made.id);
        },
      },
    );
  };
  const failure = save.error ?? mint.error;
  const picked = reachable.filter((cluster) => chosen.includes(cluster.id));
  return (
    <div className="connect">
      <div className="connect-top">
        <Button
          variant="ghost"
          size="small"
          disabled={busy}
          onClick={() => onClose(agent?.id)}
        >
          <ArrowLeft size={14} aria-hidden="true" />
          {agent ? `Go to ${agent.name}` : 'Back to agents'}
        </Button>
      </div>
      <header className="connect-heading">
        <h1>Connect an agent</h1>
        <p>
          Give an AI client its own key to the gate. It reads through the same
          guard as you, and it never sees a database password.
        </p>
      </header>
      <ol className="connect-steps" aria-label="Progress">
        {STEPS.map((title, index) => (
          <li
            key={title}
            data-state={
              index < step ? 'done' : index === step ? 'current' : 'next'
            }
            aria-current={index === step ? 'step' : undefined}
          >
            <span className="connect-step-n" aria-hidden="true">
              {index < step ? <Check size={13} strokeWidth={2.5} /> : index + 1}
            </span>
            <span className="connect-step-title">
              {title}
              <span className="sr-only">
                {index < step ? ', done' : index === step ? ', current' : ''}
              </span>
            </span>
          </li>
        ))}
      </ol>
      <div className="connect-body">
        <section
          ref={panel}
          className="connect-panel"
          aria-labelledby="connect-step-heading"
        >
          <h2 id="connect-step-heading" ref={stepHeading} tabIndex={-1}>
            <span className="sr-only">
              Step {step + 1} of {STEPS.length}:{' '}
            </span>
            {heading(step, client)}
          </h2>
          {step === 0 && (
            <form
              className="connect-form"
              onSubmit={(event) => {
                event.preventDefault();
                if (valid) setStep(1);
              }}
            >
              <Field
                label="Name"
                hint={
                  taken
                    ? 'You already have an agent with this name.'
                    : 'How it shows in sessions, requests and the audit log.'
                }
              >
                <input
                  value={name}
                  maxLength={100}
                  required
                  aria-invalid={taken || undefined}
                  onChange={(event) => setName(event.target.value)}
                />
              </Field>
              <div className="connect-owner">
                <span className="connect-label">Owner</span>
                <ActorBadge kind="human" name={user?.name ?? 'You'} />
                <span className="muted">
                  You. The agent can never do more than you can.
                </span>
              </div>
              <fieldset className="connect-choices">
                <legend>Databases it can reach</legend>
                {reachable.length === 0 ? (
                  <p className="muted">
                    You have access to no database yet. Ask an administrator for
                    access first.
                  </p>
                ) : (
                  <div className="connect-databases">
                    {reachable.map((cluster) => (
                      <label key={cluster.id} className="connect-database">
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
                    ))}
                  </div>
                )}
              </fieldset>
              <fieldset className="connect-choices">
                <legend>Level</legend>
                <div className="connect-levels">
                  <Choice
                    name="level"
                    checked={level === 'read'}
                    onChange={() => setLevel('read')}
                    title="Read only"
                    tag="Safe choice"
                  >
                    It can look, never change. Start here.
                  </Choice>
                  <Choice
                    name="level"
                    checked={level === 'write'}
                    onChange={() => setLevel('write')}
                    title="Read, and may ask for writes"
                  >
                    It may ask for a write. Nothing changes until a person
                    approves it.
                  </Choice>
                </div>
              </fieldset>
              <Field label="Token lasts" hint="1 to 90 days." group>
                <SegmentedControl
                  label="Token lasts"
                  value={days}
                  onChange={setDays}
                  items={EXPIRY}
                />
              </Field>
              <details className="connect-more">
                <summary>More options</summary>
                <Field label="What it is for" hint="Optional.">
                  <input
                    value={description}
                    maxLength={2000}
                    onChange={(event) => setDescription(event.target.value)}
                  />
                </Field>
                <Field
                  label="Queries per hour"
                  hint="1 to 100,000. Refused queries count too."
                >
                  <input
                    inputMode="numeric"
                    value={budget}
                    aria-invalid={!budgetOk || undefined}
                    onChange={(event) => setBudget(event.target.value)}
                  />
                </Field>
              </details>
              <Actions>
                <Button type="button" onClick={() => onClose()}>
                  Cancel
                </Button>
                <Button variant="primary" type="submit" disabled={!valid}>
                  Continue
                </Button>
              </Actions>
            </form>
          )}
          {step === 1 && (
            <form
              className="connect-form"
              onSubmit={(event) => {
                event.preventDefault();
                if (token) setStep(2);
                else create();
              }}
            >
              <fieldset className="connect-choices">
                <legend className="sr-only">Client</legend>
                <div className="connect-clients">
                  {CLIENTS.map((item) => (
                    <label
                      key={item.value}
                      className="connect-client"
                      data-checked={client === item.value || undefined}
                    >
                      <input
                        type="radio"
                        name="client"
                        checked={client === item.value}
                        onChange={() => setClient(item.value)}
                      />
                      <item.Icon size={20} aria-hidden="true" />
                      <span className="connect-client-name">{item.name}</span>
                      <span className="connect-client-line">{item.line}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
              {!token && (
                <p className="muted">
                  Continue makes the agent and its token. The token shows once,
                  on the next step.
                </p>
              )}
              {failure && (
                <p className="callout danger" role="alert">
                  {message(failure)}
                </p>
              )}
              <Actions>
                {!agent && (
                  <Button
                    type="button"
                    disabled={busy}
                    onClick={() => setStep(0)}
                  >
                    Back
                  </Button>
                )}
                <Button variant="primary" type="submit" disabled={busy}>
                  {busy
                    ? 'Making the token…'
                    : token
                      ? 'Continue'
                      : agent
                        ? 'Try again'
                        : 'Create token'}
                </Button>
              </Actions>
            </form>
          )}
          {step === 2 && token && (
            <div className="connect-form">
              <p className="connect-once" role="status">
                <strong>Copy it now.</strong> The token shows only on this page.
                When you leave, you will not see it again; you can make a new
                one.
              </p>
              <Snippet client={client} token={token.token} />
              <SnippetNote />
              <p className="muted connect-small">
                Token ending <span className="mono">{token.hint}</span>, valid
                until {formatTime(token.expires_at)}.
              </p>
              <Actions>
                <Button type="button" onClick={() => setStep(1)}>
                  Back
                </Button>
                <Button variant="primary" onClick={() => setStep(3)}>
                  Continue
                </Button>
              </Actions>
            </div>
          )}
          {step === 3 && agent && token && (
            <Verify
              agent={agent}
              token={token}
              client={client}
              onBack={() => setStep(2)}
              onDone={() => onClose(agent.id)}
            />
          )}
        </section>
        <GateCard
          name={agent?.name ?? (name.trim() || 'this agent')}
          owner={user?.name}
          level={level}
          databases={picked}
          days={days}
          budget={budgetOk ? Number(budget) : undefined}
        />
      </div>
    </div>
  );
}

function Actions({ children }: { children: ReactNode }) {
  return <div className="connect-actions">{children}</div>;
}

function Choice({
  name,
  checked,
  onChange,
  title,
  tag,
  children,
}: {
  name: string;
  checked: boolean;
  onChange: () => void;
  title: string;
  tag?: string;
  children: string;
}) {
  return (
    <label className="connect-choice" data-checked={checked || undefined}>
      <input type="radio" name={name} checked={checked} onChange={onChange} />
      <span className="connect-choice-title">
        {title}
        {tag && <span className="connect-tag">{tag}</span>}
      </span>
      <span className="connect-choice-line">{children}</span>
    </label>
  );
}

/** The four verdicts in one agent's terms: what it can reach and at which
 * level. Its owner's reach is the ceiling ("anything you cannot reach"),
 * so `owner` names that person when it is not the reader. */
export function GateAnswers({
  level,
  databases,
  unseen = 0,
  owner,
}: {
  level: 'read' | 'write';
  databases: Pick<Cluster, 'name'>[];
  /** Databases of the agent that the reader cannot see. */
  unseen?: number;
  owner?: string;
}) {
  const count = databases.length + unseen;
  return (
    <ul className="connect-answers">
      <li>
        <VerdictChip verdict="allowed" />
        <span>
          Reads on{' '}
          {count === 0
            ? 'the databases you pick'
            : databases.length === 1 && unseen === 0
              ? databases[0]!.name
              : `${count} databases`}
          , within their row and time limits.
        </span>
      </li>
      <li>
        <VerdictChip verdict="masked" />
        <span>Protected columns come back hidden.</span>
      </li>
      <li>
        <VerdictChip verdict="held" />
        <span>
          {level === 'write'
            ? 'A write it asks for waits for a person to approve.'
            : 'Writes never run. At read only, it cannot even ask.'}
        </span>
      </li>
      <li>
        <VerdictChip verdict="blocked" />
        <span>
          Blocked tables, and anything{' '}
          {owner ? `${owner} cannot` : 'you cannot'} reach.
        </span>
      </li>
    </ul>
  );
}

/** What the gate will answer this agent: the four verdicts, in its terms. */
function GateCard({
  name,
  owner,
  level,
  databases,
  days,
  budget,
}: {
  name: string;
  owner?: string;
  level: 'read' | 'write';
  databases: Cluster[];
  days: string;
  budget?: number;
}) {
  return (
    <aside className="connect-gate" aria-label="How the gate answers">
      <h2>
        How the gate answers <span className="identifier">{name}</span>
      </h2>
      <GateAnswers level={level} databases={databases} />
      <dl className="connect-facts">
        <div>
          <dt>Acts for</dt>
          <dd>
            <ActorBadge kind="human" name={owner ?? 'You'} />
          </dd>
        </div>
        <div>
          <dt>Token</dt>
          <dd>{days} days, then it stops working</dd>
        </div>
        {budget !== undefined && (
          <div>
            <dt>Budget</dt>
            <dd>{budget.toLocaleString('en')} queries an hour</dd>
          </div>
        )}
      </dl>
    </aside>
  );
}

/** Waits for the token's first call and shows it as it arrives. */
function Verify({
  agent,
  token,
  client,
  onBack,
  onDone,
}: {
  agent: Agent;
  token: NewAgentToken;
  client: Client;
  onBack: () => void;
  onDone: () => void;
}) {
  const copy = useCopy();
  const base = `/agents/${agent.id}/sessions`;
  const mine = (page?: Page<AgentSession>) =>
    page?.items.find((item) => item.token.id === token.id);
  // Ask every two seconds until a session of this token shows up; a paused
  // agent makes none.
  const sessions = useQuery({
    queryKey: ['api', `${base}?limit=5`],
    queryFn: ({ signal }) =>
      request<Page<AgentSession>>(`${base}?limit=5`, { signal }),
    refetchInterval: (query) =>
      mine(query.state.data) || agent.paused ? false : 2000,
  });
  const session = mine(sessions.data);
  // Then read its first steps, again while fewer than three are in.
  const path = `${base}/${session?.id ?? ''}/steps?after=0&limit=3`;
  const steps = useQuery({
    queryKey: ['api', path],
    queryFn: ({ signal }) => request<AgentSteps>(path, { signal }),
    enabled: !!session,
    refetchInterval: (query) =>
      (query.state.data?.items.length ?? 0) >= 3 ||
      query.state.data?.session.active === false
        ? false
        : 3000,
  });
  const calls = steps.data?.items ?? [];
  const clientName = CLIENTS.find((item) => item.value === client)!.name;
  const arrived = calls.length > 0;
  return (
    <div className="connect-form">
      <div
        className="connect-wait"
        data-state={arrived ? 'arrived' : 'waiting'}
      >
        <p className="connect-wait-title" role="status" aria-live="polite">
          {arrived ? (
            <>
              <Check size={16} strokeWidth={2.5} aria-hidden="true" />
              First call arrived
            </>
          ) : (
            <>
              <span className="connect-pulse" aria-hidden="true" />
              Waiting for the first call…
            </>
          )}
        </p>
        {arrived ? (
          <ol className="connect-calls" aria-label="First calls">
            {calls.map((call) => (
              <Call key={call.n} call={call} />
            ))}
          </ol>
        ) : (
          <p className="muted">
            {agent.paused
              ? 'This agent is paused, so no call can arrive.'
              : `Start ${clientName} with the snippet in place, and ask it something. The call shows up here.`}
          </p>
        )}
        {sessions.error && !arrived && (
          <p className="callout danger" role="alert">
            {message(sessions.error)}
          </p>
        )}
      </div>
      <div className="connect-prompt">
        <span className="connect-label">Try this first prompt</span>
        <div className="connect-prompt-row">
          <q>{FIRST_PROMPT}</q>
          <Button size="small" onClick={() => void copy(FIRST_PROMPT)}>
            <Copy size={14} aria-hidden="true" />
            Copy prompt
          </Button>
        </div>
      </div>
      <p className="muted">
        You can leave now; nothing breaks. The agent&apos;s sessions show every
        call on its page.
      </p>
      <Actions>
        <Button type="button" onClick={onBack}>
          Back
        </Button>
        {session && (
          <Link
            className="button secondary default"
            to={sessionPath(agent.id, session.id)}
          >
            Open the session
          </Link>
        )}
        <Button variant="primary" onClick={onDone}>
          Done
        </Button>
      </Actions>
    </div>
  );
}

function Call({ call }: { call: AgentStep }) {
  const verdict = verdictOfStep(call);
  return (
    <li className="connect-call">
      {verdict ? (
        <VerdictChip verdict={verdict} />
      ) : (
        <span className="connect-answered">
          {call.outcome === 'ok' ? 'Answered' : 'Failed'}
        </span>
      )}
      <span className="connect-call-tool">
        {toolText[call.tool] ?? call.tool} <code>{call.tool}</code>
      </span>
      <RelativeTime value={call.created_at} />
      {call.task && <span className="connect-call-task">{call.task}</span>}
    </li>
  );
}
