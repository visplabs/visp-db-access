import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { requestText } from '../../api/client';
import type { AgentLogin, Cluster, SetupFinding } from '../../api/types';
import { useAction, useResource } from '../../lib/query';
import {
  Badge,
  Button,
  Confirm,
  ErrorPanel,
  Field,
  Modal,
  Skeleton,
} from '../../components/ui';
import { useToast } from '../../components/ui/toast';
import { RelativeTime } from '../../components/ui/time';
import { useCopy } from '../../lib/clipboard';
import { message } from '../../lib/utils';

/** What the state means, in the words of the person who must act on it. */
function summary(login: Extract<AgentLogin, { configured: true }>) {
  if (login.needs_password)
    return {
      tone: 'danger',
      label: 'Password needed',
      text: "The cluster's connection changed, so the stored password was cleared. Agents are refused on this database until you enter the password again.",
    };
  // A result from before a change says nothing about now. Never show it as
  // the present state.
  if (login.stale)
    return {
      tone: 'warning',
      label: 'Check needed',
      text: 'The cluster or its policy changed after the last check, so the result below may be out of date. The next agent query checks again before it runs. You can check now.',
    };
  if (login.status === 'ok')
    return {
      tone: 'success',
      label: 'In sync',
      text: 'The database allows this login no more than the policy does. Agents run as this login.',
    };
  if (login.status === 'drift')
    return {
      tone: 'danger',
      label: 'Too open',
      text: 'The database allows this login more than the policy does. Agents are refused on this database until that is repaired.',
    };
  if (login.status === 'error')
    return {
      tone: 'danger',
      label: 'Could not check',
      text: 'The gateway could not check the login. Agents are refused on this database until a check succeeds.',
    };
  return {
    tone: 'neutral',
    label: 'Not checked',
    text: 'The login was not checked yet.',
  };
}

/** Database setup check: is the agent login in sync with the policy? */
export function AgentLoginPage({ cluster }: { cluster: Cluster }) {
  const base = `/clusters/${cluster.id}/agent-login`;
  const query = useResource<AgentLogin>(base, cluster.engine === 'postgres');
  const check = useAction<AgentLogin>('Checked'),
    remove = useAction('Agent login removed');
  const [setting, setSetting] = useState(false),
    [scripting, setScripting] = useState(false),
    [removing, setRemoving] = useState(false);
  if (cluster.engine !== 'postgres')
    return (
      <p className="muted">
        An agent login is available for PostgreSQL clusters. On this cluster,
        the gateway's own checks protect the data from agents.
      </p>
    );
  if (query.isPending) return <Skeleton />;
  if (query.error)
    return (
      <ErrorPanel error={query.error} retry={() => void query.refetch()} />
    );
  const login = query.data;
  return (
    <div className="agent-login">
      <h2>Agent login</h2>
      <p className="muted agent-login-intro">
        A second login on the database, for agents only. It can read exactly the
        columns that the policy allows. The gateway writes the setup script; a
        database administrator runs it. The gateway never changes the database
        itself.
      </p>
      {login.configured ? (
        <>
          <div className="agent-login-state">
            <Badge variant="verdict" tone={summary(login).tone}>
              {summary(login).label}
            </Badge>
            <strong className="identifier">{login.username}</strong>
            <span className="muted">
              {login.checked_at ? (
                <>
                  Checked <RelativeTime value={login.checked_at} />
                </>
              ) : (
                'Never checked'
              )}
            </span>
          </div>
          <p role="status">{summary(login).text}</p>
          <Findings items={login.findings} />
          <div className="agent-login-actions">
            <Button
              variant="primary"
              disabled={check.isPending}
              onClick={() => check.mutate({ path: `${base}/check` })}
            >
              Check now
            </Button>
            <Button onClick={() => setScripting(true)}>Get setup script</Button>
            <Button onClick={() => setSetting(true)}>
              {login.needs_password ? 'Enter password' : 'Change login'}
            </Button>
            <Button variant="danger" onClick={() => setRemoving(true)}>
              Remove
            </Button>
          </div>
        </>
      ) : (
        <>
          <p role="status">
            No agent login is set. Agents use the cluster's own login, and only
            the gateway's checks stand between them and the data.
          </p>
          <ol className="agent-login-steps">
            <li>
              Get the setup script and give it to a database administrator.
            </li>
            <li>
              The administrator runs it and sets a password for the new login.
            </li>
            <li>Enter the login here. The gateway checks it at once.</li>
          </ol>
          <div className="agent-login-actions">
            <Button variant="primary" onClick={() => setScripting(true)}>
              Get setup script
            </Button>
            <Button onClick={() => setSetting(true)}>Enter login</Button>
          </div>
        </>
      )}
      <SetLogin
        key={setting ? 'login-open' : 'login-closed'}
        open={setting}
        onClose={() => setSetting(false)}
        base={base}
        username={login.configured ? login.username : ''}
      />
      <Script
        key={scripting ? 'script-open' : 'script-closed'}
        open={scripting}
        onClose={() => setScripting(false)}
        base={base}
        username={login.configured ? login.username : 'vda_agent'}
        cluster={cluster}
      />
      <Confirm
        open={removing}
        onOpenChange={setRemoving}
        title="Remove the agent login?"
        description="Agents then use the cluster's own login again. Only the gateway's checks protect the data from them."
        danger
        onConfirm={() => remove.mutate({ path: base, method: 'DELETE' })}
      />
    </div>
  );
}

function Findings({ items }: { items: SetupFinding[] }) {
  if (items.length === 0) return null;
  const group = (severity: SetupFinding['severity']) =>
    items.filter((item) => item.severity === severity);
  return (
    <div className="agent-login-findings">
      {(
        [
          ['critical', 'Must be repaired'],
          ['warning', 'Worth a look'],
        ] as const
      ).map(([severity, title]) =>
        group(severity).length === 0 ? null : (
          <section key={severity} aria-label={title}>
            <h3>
              {title} ({group(severity).length})
            </h3>
            <ul>
              {group(severity).map((item, index) => (
                <li key={`${item.code}-${item.object}-${index}`}>
                  <code>{item.object}</code>
                  <span>{item.message}</span>
                </li>
              ))}
            </ul>
          </section>
        ),
      )}
    </div>
  );
}

function SetLogin({
  open,
  onClose,
  base,
  username,
}: {
  open: boolean;
  onClose: () => void;
  base: string;
  username: string;
}) {
  // The panel shows the result of the check; the toast only says it was saved.
  const save = useAction<AgentLogin>('Agent login saved');
  const [name, setName] = useState(username),
    [password, setPassword] = useState('');
  return (
    <Modal
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title="Agent login"
      description="Enter the login that the administrator created with the setup script. It must be a different login from the cluster's own."
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate(
            { path: base, method: 'PUT', body: { username: name, password } },
            {
              onSuccess: onClose,
              // Do not keep the database password in the request cache.
              onSettled: () => save.reset(),
            },
          );
        }}
      >
        <Field
          label="Login name"
          hint="Lower-case letters, digits and underscore."
        >
          <input
            className="mono"
            value={name}
            autoComplete="off"
            onChange={(event) => setName(event.target.value)}
            required
          />
        </Field>
        <Field label="Password">
          <input
            type="password"
            value={password}
            autoComplete="new-password"
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </Field>
        <div className="dialog-actions">
          <Button type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            type="submit"
            disabled={!name || !password || save.isPending}
          >
            Save and check
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function Script({
  open,
  onClose,
  base,
  username,
  cluster,
}: {
  open: boolean;
  onClose: () => void;
  base: string;
  username: string;
  cluster: Cluster;
}) {
  const toast = useToast(),
    cache = useQueryClient(),
    copy = useCopy();
  const [name, setName] = useState(username),
    [script, setScript] = useState<string | null>(null),
    [busy, setBusy] = useState(false);
  const load = async () => {
    setBusy(true);
    try {
      setScript(
        await requestText(
          `${base}/script?username=${encodeURIComponent(name)}`,
        ),
      );
    } catch (error) {
      toast(message(error), 'error');
    } finally {
      setBusy(false);
      void cache.invalidateQueries({ queryKey: ['api', base] });
    }
  };
  return (
    <Modal
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title="Setup script"
      description={`For a database administrator of ${cluster.name}. It is made from the current tables and the current policy, and it holds no password.`}
      wide
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void load();
        }}
      >
        <Field
          label="Login name"
          hint="Use a new name. The script stops if the login owns anything, because it first removes all that the login holds."
        >
          <input
            className="mono"
            value={name}
            autoComplete="off"
            onChange={(event) => {
              setName(event.target.value);
              setScript(null);
            }}
            required
          />
        </Field>
        {script !== null && (
          <Field label="SQL">
            <textarea
              readOnly
              rows={14}
              className="mono agent-login-script"
              value={script}
            />
          </Field>
        )}
        <div className="dialog-actions">
          <Button type="button" onClick={onClose}>
            Close
          </Button>
          {script !== null && (
            <>
              <Button onClick={() => void copy(script)}>Copy</Button>
              <Button
                onClick={() => {
                  const url = URL.createObjectURL(
                    new Blob([script], { type: 'application/sql' }),
                  );
                  const link = document.createElement('a');
                  link.href = url;
                  link.download = `${cluster.name}-agent-login.sql`;
                  link.click();
                  URL.revokeObjectURL(url);
                }}
              >
                Download
              </Button>
            </>
          )}
          <Button variant="primary" type="submit" disabled={!name || busy}>
            {script === null ? 'Write script' : 'Write again'}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
