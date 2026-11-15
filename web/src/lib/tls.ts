import type { HealthStatus, TlsMode } from '../api/types';

/** Matches hosts that are obviously this machine: localhost and loopback IPs. */
export function isLoopbackHost(host: string): boolean {
  const name = host
    .trim()
    .toLowerCase()
    .replace(/^\[(.*)\]$/, '$1')
    .replace(/\.$/, '');
  return (
    name === 'localhost' ||
    name.endsWith('.localhost') ||
    name === '::1' ||
    /^127(\.\d{1,3}){3}$/.test(name)
  );
}

/** TLS modes that fail outright when the server does not offer TLS. */
const strictModes: readonly TlsMode[] = ['require', 'verify_full'];

/**
 * Suggests, before a test, a non-TLS mode for a loopback host. The suggestion
 * is advice only: the form never changes the TLS mode on its own.
 */
export function localTlsSuggestion(host: string, tls: TlsMode): string | null {
  if (!isLoopbackHost(host) || !strictModes.includes(tls)) return null;
  return 'This looks like a database on the gateway’s own machine. Local databases often run without TLS: if this one does, set TLS mode to “disable”. Loopback hosts are refused unless the gateway runs with VDA_ALLOW_PRIVATE_TARGETS=true; under Docker Compose, use the service name (for example demo-postgres) instead.';
}

/**
 * Explains a failed probe in terms of the TLS mode field. The server does not
 * return the driver error, so this names TLS as a likely cause, not a certain one.
 */
export function tlsFailureHint(
  status: HealthStatus,
  tls: TlsMode,
): string | null {
  if (status !== 'down') return null;
  if (tls === 'verify_full')
    return 'TLS mode is “verify full”: the database must offer TLS with a certificate the gateway trusts for this exact host name. If the database does not use TLS (such as a local or demo database), set TLS mode to “disable”; if it uses a self-signed certificate, use “require”. Keep “verify full” for production databases.';
  if (tls === 'require')
    return 'TLS mode is “require”: the database must offer TLS. If it does not (such as a local or demo database), set TLS mode to “disable”.';
  return null;
}
