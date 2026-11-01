/** Typed views of the backend API responses the dashboard consumes. */

export type AgentState = "active" | "stale" | "revoked";

export interface AgentSummary {
  id: string;
  hostname: string | null;
  platform: string | null;
  agent_version: string | null;
  status: AgentState;
  enrolled_at: string | null;
  revoked_at: string | null;
  last_heartbeat_at: string | null;
  seconds_since_heartbeat: number | null;
  heartbeat_interval_seconds: number | null;
  capabilities: string[];
  claimed_ips: string[];
  latest_inventory_at: string | null;
}

export interface EnrollmentRequest {
  id: string;
  identity_key_hash: string;
  hostname: string | null;
  platform: Record<string, unknown> | null;
  agent_version: string | null;
  claimed_ips: string[] | null;
  mac: string | null;
  gateway: string | null;
  status: string;
  requested_at: string;
  updated_at: string | null;
  expires_at: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  reject_reason: string | null;
  enrolled_agent_id: string | null;
}

export interface InventoryData {
  collected_at?: string;
  os_name?: string;
  os_version?: string;
  kernel?: string;
  arch?: string;
  python_version?: string;
  boot_time?: string;
  uptime_seconds?: number;
  hostname?: string;
  interfaces?: NetworkInterface[];
  default_gateway?: string | null;
  dns_servers?: string[] | null;
  [k: string]: unknown;
}

export interface NetworkInterface {
  name: string;
  display_name?: string;
  type?: string;
  classification?: string | null;
  up?: boolean | null;
  speed_mbps?: number | null;
  mac: string | null;
  ipv4: string[];
  ipv6: string[];
  prefixlen?: number | null;
  subnet_mask?: string | null;
  gateway: string | null;
  dns_servers?: string[] | null;
  mtu?: number | null;
}

export interface TaskRow {
  id: string;
  agent_id: string;
  type: string;
  status: string;
  params: Record<string, unknown>;
  result: Record<string, unknown> | null;
  error: string | null;
  created_at: string | null;
  expires_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
}

export interface AuditRow {
  at: string;
  actor: string;
  action: string;
  target: string | null;
  outcome: string;
  detail?: Record<string, unknown>;
}

export interface ConsoleSession {
  id: string;
  agent_id: string;
  actor: string;
  status: string;
  created_at: string;
  expires_at: string | null;
  idle_timeout_seconds: number | null;
  last_active_at: string | null;
}

export interface ConsoleCommand {
  id: string;
  session_id: string;
  seq: number;
  code: string;
  status: string;
  submitted_at: string | null;
  finished_at: string | null;
  stdout: string | null;
  stderr: string | null;
  result_repr: string | null;
  error: string | null;
  duration_ms: number | null;
  truncated?: boolean;
}

export interface Overview {
  agents: {
    total: number;
    active: number;
    stale: number;
    revoked: number;
    pending_approval: number;
    pending_requests: EnrollmentRequest[];
  };
  hosts: number;
  events: { total: number; last_24h: number };
  alerts: {
    total: number;
    last_24h: number;
    by_severity: { severity: number; count: number }[];
  };
  tasks: { pending: number | null };
  investigations: { total: number; running?: number; [k: string]: unknown };
  console_sessions_active: number;
  trend_7d: { date: string; events: number; alerts: number; audit: number }[];
  recent_audit: AuditRow[];
  generated_at: string;
}

export interface NetworkObservation {
  agent_id: string;
  observed_at: string;
  interface_name: string;
  ipv4?: string[];
  subnet?: string | null;
  gateway?: string | null;
  [k: string]: unknown;
}

export interface NetworkRow {
  prefix: string;
  gateway?: string | null;
  first_seen_at?: string;
  last_seen_at?: string;
  host_count?: number;
  agent_count?: number;
  reporters?: string[];
  [k: string]: unknown;
}

export interface HostRow {
  ip: string;
  hostname: string | null;
  mac: string | null;
  first_seen: string | null;
  last_seen: string | null;
  source?: string | null;
  [k: string]: unknown;
}

export interface AlertRow {
  id: number;
  ts: string | null;
  severity: number;
  signature: string | null;
  signature_id: number | null;
  src_ip: string | null;
  dest_ip: string | null;
  src_port: number | null;
  dest_port: number | null;
  proto: string | null;
  app_proto: string | null;
  action: string | null;
  [k: string]: unknown;
}

export interface Investigation {
  id: number;
  created_at: string;
  finished_at: string | null;
  trigger: string;
  target_ip: string | null;
  question: string | null;
  status: string;
  confidence: string | null;
  iterations: number | null;
  error: string | null;
  report_text: string | null;
  report_json: Record<string, unknown> | null;
  evidence: Record<string, unknown>[] | null;
  [k: string]: unknown;
}
