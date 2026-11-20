// Mirrors docs/API.md. Credentials are write-only.
export type OrgRole = 'admin' | 'member';
export type AccessLevel = 'read' | 'write' | 'admin';
export type Engine = 'postgres' | 'mysql';
export type Provider = 'aws' | 'gcp' | 'azure' | 'onprem' | 'other';
export type Environment = 'production' | 'staging' | 'development';
export type TlsMode = 'disable' | 'prefer' | 'require' | 'verify_full';
export type HealthStatus = 'healthy' | 'degraded' | 'down' | 'unknown';
export type Verdict = 'allow' | 'requires_approval' | 'deny';
export type Severity = 'info' | 'warning' | 'block';
export type Risk = 'low' | 'medium' | 'high' | 'critical';
export type StatementKind =
  | 'select'
  | 'explain'
  | 'show'
  | 'insert'
  | 'update'
  | 'delete'
  | 'merge'
  | 'ddl'
  | 'dcl'
  | 'transaction'
  | 'utility'
  | 'other';

export interface User {
  id: string;
  email: string;
  name: string;
  org_role: OrgRole;
  disabled: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  cluster_count: number;
  created_at: string;
}

export interface Health {
  status: HealthStatus;
  latency_ms: number | null;
  server_version: string | null;
  is_replica: boolean | null;
  active_connections: number | null;
  max_connections: number | null;
  error: string | null;
  checked_at: string | null;
}

export interface Cluster {
  id: string;
  project_id: string;
  name: string;
  engine: Engine;
  provider: Provider;
  region: string;
  environment: Environment;
  host: string;
  port: number;
  database: string;
  username: string;
  tls_mode: TlsMode;
  replica_host: string | null;
  replica_port: number | null;
  tags: Record<string, string>;
  health: Health;
  my_access: AccessLevel | null; // effective level of the caller
  created_at: string;
  updated_at: string;
}
// password is write-only: accepted on create/update, never returned.

export interface Policy {
  max_rows: number; // default 1000 (prod) / 5000 (non-prod)
  statement_timeout_ms: number; // default 15000 (prod) / 60000
  lock_timeout_ms: number; // default 2000
  max_cost: number | null; // EXPLAIN total cost gate for reads
  max_concurrent_queries: number; // per node, default 4
  allow_writes: boolean; // default false in production
  require_approval_for_writes: boolean; // default true
  max_affected_rows: number; // default 1000
  allow_ddl: boolean; // default false
  route_reads_to_replica: boolean; // default true
  masked_columns: string[]; // patterns: "email", "users.ssn", "*.password*"
  blocked_tables: string[]; // patterns: "secrets.*", "audit_trail"
  allowed_cidrs: string[]; // empty = only org-level rule applies
}

export interface Issue {
  severity: Severity;
  code: string;
  message: string;
}
export interface StatementAnalysis {
  kind: StatementKind;
  sql: string;
  tables: string[];
  functions: string[];
  risk: Risk;
  issues: Issue[];
  has_where: boolean;
  has_limit: boolean;
}
export interface Analysis {
  verdict: Verdict;
  risk: Risk;
  statements: StatementAnalysis[];
  rewritten_sql: string | null;
  issues: Issue[];
  /** Advisory performance hints; absent on analyses stored by older servers. */
  suggestions?: Suggestion[];
} // issues = flattened, incl. top-level

export interface Fix {
  label: string;
  sql: string;
  /** `replace` swaps the editor text; `new_tab` opens the SQL alongside it. */
  action: 'replace' | 'new_tab';
}
export interface Suggestion {
  code: string;
  message: string;
  fix?: Fix;
}

export interface Column {
  name: string;
  type_name: string;
  masked: boolean;
}
export interface QueryResult {
  query_id: string;
  columns: Column[];
  rows: unknown[][];
  row_count: number;
  truncated: boolean;
  affected_rows: number | null;
  elapsed_ms: number;
  executed_sql: string;
  routed_to: 'primary' | 'replica';
  analysis: Analysis;
}

export interface HistoryEntry {
  id: string;
  cluster_id: string;
  cluster_name: string;
  user_id: string;
  user_email: string;
  sql: string;
  verdict: Verdict;
  status: 'running' | 'unknown' | 'ok' | 'blocked' | 'error' | 'cancelled';
  row_count: number | null;
  elapsed_ms: number | null;
  error: string | null;
  created_at: string;
}

export interface Approval {
  id: string;
  cluster_id: string;
  cluster_name: string;
  requester: { id: string; email: string; name: string };
  sql: string;
  reason: string;
  analysis: Analysis;
  status:
    | 'pending'
    | 'approved'
    | 'rejected'
    | 'executing'
    | 'executed'
    | 'failed'
    | 'expired'
    | 'withdrawn';
  error: string | null;
  /** The code of the error that stopped the write, such as `effect_changed`;
   * null until a write fails. */
  error_code: string | null;
  sql_truncated: boolean;
  /** The agent that asked, for its owner (the requester). The id is null
   * once the agent is deleted; the name stays. */
  agent: { id: string | null; name: string } | null;
  /** What the dry run showed. Null in lists, for an agent's request until a
   * person previews it, and for requests from before previews existed. */
  preview: Preview | null;
  /** The signed record of a write that ran. Null in lists and until it ran. */
  receipt: Receipt | null;
  reviewer: { id: string; email: string; name: string } | null;
  review_note: string | null;
  result: QueryResult | null;
  created_at: string;
  reviewed_at: string | null;
  executed_at: string | null;
  expires_at: string;
}

/** A few rows of a preview, already masked. */
export interface RowSample {
  columns: string[];
  /** Columns whose values are not shown (masked, or computed from something
   * that may not be shown). */
  hidden: string[];
  /** The hidden columns that the policy protects (a subset of `hidden`).
   * Absent on previews stored before the server sent it. */
  masked?: string[];
  /** At most 20 rows. */
  rows: unknown[][];
  /** How many rows there were in all. */
  total: number;
}
/** What a write would do, seen by running it and rolling it back. The server
 * leaves out the fields that have no value. */
export interface Preview {
  /** False when the write is not previewed (MySQL); `reason` says why. */
  supported: boolean;
  reason?: string;
  kind?: StatementKind;
  target?: string;
  affected_rows?: number;
  /** The rows it changes, as they are now (UPDATE, DELETE). */
  before?: RowSample;
  /** The rows as the write leaves them (INSERT, UPDATE). */
  after?: RowSample;
  /** The approval runs only on these exact rows, or only if it changes the
   * same number of rows. */
  bound_to?: 'rows' | 'count';
  /** The columns the statement writes (UPDATE, and INSERT with a column list
   * of written-out values); left out when not known. */
  written?: string[];
  /** What the preview could not show. */
  notes: string[];
}
export interface ReceiptPerson {
  id: string;
  email: string;
}
/** The signed record of a write that ran. */
export interface Receipt {
  version: number;
  approval_id: string;
  cluster: { id: string; name: string; engine: Engine };
  sql: string;
  reason: string;
  requested_by: ReceiptPerson;
  agent: { id: string | null; name: string } | null;
  approved_by: ReceiptPerson;
  review_note: string | null;
  executed_by: ReceiptPerson;
  requested_at: string;
  approved_at: string;
  executed_at: string;
  /** Null when there was no preview (MySQL, or an old request). */
  previewed_rows: number | null;
  affected_rows: number | null;
  /** Null when nothing was bound (MySQL, or an old request). */
  bound_to: 'rows' | 'count' | null;
  key_id: string;
  digest: string;
  signature: string;
}
/** `GET /approvals/:id/receipt` */
export interface ReceiptCheck {
  receipt: Receipt;
  /** The digest and signature match, and the receipt is this request's. */
  valid: boolean;
  /** The content matches its own digest; needs no key. */
  digest_matches: boolean;
  /** False for a receipt signed before the master key changed. */
  signed_with_current_key: boolean;
}

export interface Grant {
  id: string;
  user: { id: string; email: string; name: string };
  scope: 'project' | 'cluster';
  scope_id: string;
  scope_name: string;
  level: AccessLevel;
  expires_at: string | null;
  created_at: string;
  created_by: string | null;
}

export interface AuditEvent {
  id: string;
  actor: { id: string; email: string } | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  details: unknown;
  created_at: string;
  /** The number of the event in the order it was written. Gaps are normal. */
  seq: number;
  /** Whether the event is in the hash chain yet. */
  sealed: boolean;
}
/** The last link of the audit hash chain. */
export interface AuditChainHead {
  position: number;
  hash: string;
  key_id: string;
  sealed_at: string;
}
export type AuditProblemKind =
  | 'row_changed'
  | 'row_missing'
  | 'row_inserted'
  | 'chain_broken'
  | 'chain_truncated'
  | 'checkpoint_mismatch';
/** The first place where the audit log no longer matches its chain. */
export interface AuditProblem {
  kind: AuditProblemKind;
  position: number;
  audit_id: string | null;
  seq: number | null;
  message: string;
}
/** Links that were sealed with another master key than the current one. */
export interface AuditSegment {
  key_id: string;
  first_position: number;
  last_position: number;
}
/** `GET /audit/integrity`. */
export interface AuditIntegrity {
  head: AuditChainHead | null;
  key_id: string;
  sealed: number;
  unsealed: number;
  oldest_unsealed_at: string | null;
  oldest_unsealed_seconds: number | null;
  verification: {
    status: 'pending' | 'intact' | 'partial' | 'broken';
    checked_at: string | null;
    key_id: string | null;
    links: number;
    verified: number;
    unverifiable: AuditSegment[];
    problem: AuditProblem | null;
    running: { position: number; started_at: string | null } | null;
  };
}
/** `POST /audit/verify`. */
export interface AuditVerification {
  status: 'intact' | 'partial' | 'broken';
  key_id: string;
  from_position: number;
  to_position: number;
  links: number;
  verified: number;
  unverifiable: AuditSegment[];
  problem: AuditProblem | null;
  head: AuditChainHead | null;
}

export interface SchemaTree {
  schemas: {
    name: string;
    tables: {
      name: string;
      kind: 'table' | 'view' | 'materialized_view';
      row_estimate: number | null;
      columns: {
        name: string;
        data_type: string;
        nullable: boolean;
        is_primary_key: boolean;
      }[];
    }[];
  }[];
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export type UserLookup = Pick<User, 'id' | 'email' | 'name'>;

export type DiscoveryProvider = 'aws';
export type ResourceStatus = 'new' | 'imported' | 'ignored' | 'gone';
export type Drift =
  'endpoint_changed' | 'replica_changed' | 'deleted' | 'engine_changed';
export interface ScanRun {
  id: string;
  source_id: string;
  status: 'running' | 'succeeded' | 'partial' | 'failed';
  started_at: string;
  finished_at: string | null;
  found: number;
  new: number;
  gone: number;
  changed: number;
  errors: { region: string | null; message: string }[];
}
export interface DiscoverySource {
  id: string;
  provider: DiscoveryProvider;
  name: string;
  role_arn: string | null;
  external_id_set: boolean;
  regions: string[];
  default_project_id: string | null;
  environment_tag_keys: string[];
  scan_interval_minutes: number;
  enabled: boolean;
  last_scan: ScanRun | null;
  last_test:
    | (Pick<DiscoveryTest, 'ok' | 'account_id' | 'identity_arn'> & {
        tested_at: string;
      })
    | null;
  created_at: string;
  updated_at: string;
}
export interface DiscoveredResource {
  id: string;
  source_id: string;
  source_name: string;
  provider: DiscoveryProvider;
  kind: 'rds_instance' | 'aurora_cluster';
  arn: string;
  identifier: string;
  account_id: string;
  region: string;
  engine: Engine;
  engine_detail: string;
  engine_version: string;
  host: string;
  port: number;
  replica_host: string | null;
  replica_port: number | null;
  database: string | null;
  status_detail: string;
  publicly_accessible: boolean;
  encrypted: boolean;
  multi_az: boolean;
  iam_auth_enabled: boolean;
  vpc_id: string | null;
  tags: Record<string, string>;
  suggested_environment: Environment;
  status: ResourceStatus;
  cluster_id: string | null;
  drift: Drift[];
  first_seen_at: string;
  last_seen_at: string;
}
export interface DiscoveryTest {
  ok: boolean;
  account_id: string | null;
  identity_arn: string | null;
  regions: { region: string; ok: boolean; error: string | null }[];
}
export type DiscoveryCounts = Record<ResourceStatus, number>;
export interface ResourcePage extends Page<DiscoveredResource> {
  counts: DiscoveryCounts;
}
export interface SourceDraft {
  provider: DiscoveryProvider;
  name: string;
  role_arn: string | null;
  external_id?: string | null;
  regions: string[];
  default_project_id: string | null;
  environment_tag_keys: string[];
  scan_interval_minutes: number;
  enabled: boolean;
}

export interface AgentToken {
  id: string;
  /** The last four characters of the token. The token itself is shown once. */
  hint: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
}
export interface Agent {
  id: string;
  name: string;
  description: string;
  max_level: 'read' | 'write';
  paused: boolean;
  hourly_query_budget: number;
  owner: { id: string; email: string; name: string };
  cluster_ids: string[];
  tokens: AgentToken[];
  created_at: string;
  updated_at: string;
}
export interface NewAgentToken {
  id: string;
  token: string;
  hint: string;
  expires_at: string;
}
export interface SetupFinding {
  severity: 'critical' | 'warning';
  code: string;
  object: string;
  message: string;
}
/** The least-privilege database login that agents' queries run as. */
export type AgentLogin =
  | { configured: false }
  | {
      configured: true;
      username: string;
      status: 'unchecked' | 'ok' | 'drift' | 'error';
      findings: SetupFinding[];
      checked_at: string | null;
      stale: boolean;
      needs_password: boolean;
    };
export type NoticeFormat = 'webhook' | 'slack';
export type NoticeEvent =
  | 'approval.created'
  | 'approval.previewed'
  | 'approval.approved'
  | 'approval.rejected'
  | 'approval.withdrawn'
  | 'approval.executed'
  | 'approval.failed'
  | 'approval.expired';
/** Notices to approvers, as an organization administrator reads them. The
 * webhook address and the signing secret are never part of it. */
export interface NoticeSettings {
  enabled: boolean;
  format: NoticeFormat;
  url_set: boolean;
  url_host: string | null;
  secret_set: boolean;
  events: NoticeEvent[];
  include_reason: boolean;
  include_row_count: boolean;
  /** Whether a notice can link to its request (the public URL is set). */
  links: boolean;
  delivery: {
    pending: number;
    dead: number;
    last_success_at: string | null;
    last_error: string | null;
    last_error_at: string | null;
  };
}
/** The body of `PUT /settings/notices`. `url` left out keeps the stored
 * address; an empty string removes it. */
export interface NoticeUpdate {
  enabled: boolean;
  format: NoticeFormat;
  url?: string;
  events: NoticeEvent[];
  include_reason: boolean;
  include_row_count: boolean;
}
export interface NoticeSecret {
  secret: string;
  rotated: boolean;
}
export interface NoticeTest {
  delivered: boolean;
  status: number | null;
  error: string | null;
}
