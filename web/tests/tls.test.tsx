import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import {
  isLoopbackHost,
  localTlsSuggestion,
  tlsFailureHint,
} from '../src/lib/tls';
import { createMockTransport } from '../src/api/mock';
import {
  ConnectionFields,
  type ClusterDraft,
} from '../src/features/clusters/forms';
import type { Health, TlsMode } from '../src/api/types';

const post = (body: unknown): RequestInit => ({
  method: 'POST',
  body: JSON.stringify(body),
});
const draft = (host: string, tls_mode: TlsMode): ClusterDraft => ({
  project_id: '',
  name: '',
  engine: 'postgres',
  provider: 'onprem',
  region: 'local',
  environment: 'development',
  host,
  port: 5432,
  database: 'shop',
  username: 'demo',
  password: '',
  tls_mode,
  replica_host: null,
  replica_port: null,
  tags: {},
});

describe('loopback host detection', () => {
  it('recognizes localhost and loopback addresses', () => {
    for (const host of [
      'localhost',
      'LOCALHOST',
      ' localhost ',
      'localhost.',
      'db.localhost',
      '127.0.0.1',
      '127.1.2.3',
      '::1',
      '[::1]',
    ])
      expect(isLoopbackHost(host), host).toBe(true);
  });
  it('does not flag remote or private-network hosts', () => {
    for (const host of [
      '',
      'demo-postgres',
      'db.internal.example.com',
      'localhost.example.com',
      'mylocalhost',
      '10.0.0.5',
      '128.0.0.1',
      '127.0.0',
      '::2',
    ])
      expect(isLoopbackHost(host), host).toBe(false);
  });
});

describe('TLS guidance', () => {
  it('suggests disable for a loopback host only under strict TLS modes', () => {
    expect(localTlsSuggestion('localhost', 'verify_full')).toContain(
      'set TLS mode to “disable”',
    );
    expect(localTlsSuggestion('127.0.0.1', 'require')).toContain(
      'VISP_GATE_ALLOW_PRIVATE_TARGETS',
    );
    expect(localTlsSuggestion('localhost', 'disable')).toBeNull();
    expect(localTlsSuggestion('localhost', 'prefer')).toBeNull();
    expect(localTlsSuggestion('db.example.com', 'verify_full')).toBeNull();
  });
  it('names the TLS mode field when a strict-TLS connection is down', () => {
    expect(tlsFailureHint('down', 'verify_full')).toMatch(
      /TLS mode is “verify full”.*set TLS mode to “disable”.*Keep “verify full” for production/,
    );
    expect(tlsFailureHint('down', 'require')).toContain(
      'set TLS mode to “disable”',
    );
  });
  it('stays quiet when TLS cannot be the cause', () => {
    expect(tlsFailureHint('down', 'disable')).toBeNull();
    expect(tlsFailureHint('down', 'prefer')).toBeNull();
    for (const status of ['healthy', 'degraded', 'unknown'] as const)
      expect(tlsFailureHint(status, 'verify_full')).toBeNull();
  });
  it('shows the local suggestion in the form without changing the mode', () => {
    const view = (host: string, tls: TlsMode) =>
      renderToStaticMarkup(
        <QueryClientProvider client={new QueryClient()}>
          <MemoryRouter>
            <ConnectionFields
              draft={draft(host, tls)}
              update={() => undefined}
            />
          </MemoryRouter>
        </QueryClientProvider>,
      );
    expect(view('localhost', 'verify_full')).toContain('role="note"');
    expect(view('db.example.com', 'verify_full')).not.toContain('role="note"');
    expect(view('localhost', 'disable')).not.toContain('role="note"');
  });
});

describe('mock connection test', () => {
  it('fails strict TLS against a no-TLS demo host and passes with disable', async () => {
    const api = createMockTransport({ delay: 0 });
    await api(
      '/auth/login',
      post({ email: 'admin@visp.dev', password: 'demo-password' }),
    );
    const test = (host: string, tls_mode: TlsMode) =>
      api<Health>(
        '/clusters/test-connection',
        post({
          engine: 'postgres',
          host,
          port: 5432,
          database: 'shop',
          username: 'demo',
          password: 'demo-local-only',
          tls_mode,
        }),
      );
    expect(await test('demo-postgres', 'verify_full')).toMatchObject({
      status: 'down',
      error: 'Target database unavailable',
    });
    expect((await test('demo-postgres', 'disable')).status).toBe('healthy');
    expect((await test('db.example.com', 'verify_full')).status).toBe(
      'healthy',
    );
  });
});
