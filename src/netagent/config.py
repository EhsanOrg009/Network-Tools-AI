"""Application configuration.

All settings come from environment variables (with optional ``.env`` support).
Nothing is hardcoded at call sites; adjust via environment only.

Policy model (v2):
- All non-destructive diagnostic tools are enabled by default. There are no
  per-tool feature flags for nmap / arp-scan anymore.
- The single authorization gate is the configured *scope*:
  MONITOR_CIDRS + AUTHORIZED_TARGETS. Targets outside the scope are rejected;
  policy-derived networks apply only to low-impact discovery.
- Missing executables / missing OS capabilities (e.g. nmap -O needs root)
  are detected and reported explicitly; unprivileged alternatives are used
  where possible.
"""

from __future__ import annotations

import ipaddress
import shutil
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _parse_int_list(raw: str) -> list[int]:
    out: list[int] = []
    for part in raw.replace(" ", "").split(","):
        if not part:
            continue
        try:
            value = int(part)
        except ValueError:
            continue
        if 1 <= value <= 65535:
            out.append(value)
    return out


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # --- HTTP server ---
    app_host: str = "127.0.0.1"
    app_port: int = 8000

    # --- Suricata ---
    suricata_eve_path: Path = Path("/var/log/suricata/eve.json")
    monitor_interface: str = "wlo1"

    # --- Local LLM (OpenAI-compatible: Ollama / Msty) ---
    # Default provider is Ollama; Msty users set MSTY_* envs (accepted as
    # aliases) to keep their existing setup working unchanged.
    llm_provider: str = "ollama"
    llm_base_url: str = Field(
        default="http://127.0.0.1:11434/v1",
        validation_alias=AliasChoices("LLM_BASE_URL", "MSTY_BASE_URL"),
    )
    llm_api_key: str = Field(
        default="ollama",
        validation_alias=AliasChoices("LLM_API_KEY", "MSTY_API_KEY"),
    )
    llm_model: str = Field(
        default="gemma-4-e4b:latest",
        validation_alias=AliasChoices("LLM_MODEL", "MSTY_MODEL"),
    )
    llm_timeout_seconds: float = Field(default=600.0, ge=1, le=1800)
    llm_connect_timeout_seconds: float = Field(default=5.0, ge=0.1, le=30)
    llm_timeout_cooldown_seconds: float = Field(default=60.0, ge=1, le=1800)
    llm_max_output_tokens: int = 4096
    llm_max_input_chars: int = 12000
    llm_temperature: float = 0.2
    # Structured Outputs (Ollama json_schema response_format) keep the model
    # honest — parsing/Pydantic validation still runs in the backend.
    llm_structured_outputs: bool = True
    # When false, investigations produce a deterministic fallback report
    # without contacting the LLM at all.
    llm_enabled: bool = True

    # --- Storage ---
    database_path: Path = Path("./data/netagent.sqlite3")

    # --- Monitoring ---
    enable_monitor: bool = True
    monitor_interval_seconds: float = 15.0
    max_events_per_prompt: int = Field(default=20, ge=1, le=200)

    # --- Authorized scope (the only gate for active diagnostics) ---
    # Comma-separated CIDRs of networks you are authorized to assess.
    monitor_cidrs: str = ""
    # Explicit individual authorized targets (IPs or /32 CIDRs).
    authorized_targets: str = ""

    # --- Diagnostics ---
    allowed_tcp_ports: str = "80,443,22,53,8080,445,3389,3306,5353,8000,8443,9000"
    ping_count: int = Field(default=3, ge=1, le=10)
    ping_timeout_seconds: int = Field(default=2, ge=1, le=10)
    gateway_ip: str = ""

    # --- Nmap ---
    # Bounded common-port set used for service discovery unless a smaller
    # explicit subset is requested.
    nmap_service_ports: str = "22,80,443,445,3306,3389,5353,8000,8080,8443,9000"
    nmap_max_ports: int = Field(default=20, ge=1, le=100)
    nmap_discovery_timeout: int = Field(default=120, ge=5, le=600)
    nmap_service_timeout: int = Field(default=120, ge=5, le=600)
    nmap_os_timeout: int = Field(default=120, ge=5, le=600)
    nmap_os_max_hosts: int = Field(default=3, ge=1, le=10)

    # --- arp-scan ---
    arp_scan_timeout: int = Field(default=60, ge=5, le=300)

    # Offline capture access is independent of active network scope.
    pcap_allowed_dirs: str = ""

    # --- Agent loop / investigation budget ---
    max_tool_calls_per_investigation: int = Field(default=10, ge=2, le=30)
    # Overall wall-clock deadline for one investigation; when exceeded a
    # partial report with the collected evidence is produced.
    investigation_deadline_seconds: float = Field(default=900.0, ge=60.0, le=7200.0)
    # Max total bytes of tool results fed back to the LLM per investigation.
    max_total_tool_output_bytes: int = Field(default=200 * 1024, ge=4 * 1024)
    # Repeated identical tool calls (same tool + same args) are suppressed
    # after this many executions.
    max_identical_tool_calls: int = Field(default=1, ge=1, le=3)
    subprocess_timeout_seconds: int = Field(default=60, ge=1, le=600)
    max_tool_output_bytes: int = Field(default=64 * 1024, ge=1024)
    job_workers: int = Field(default=2, ge=1, le=8)
    job_queue_size: int = Field(default=32, ge=1, le=500)
    job_timeout_seconds: float = Field(default=900, ge=1, le=7200)
    job_shutdown_seconds: float = Field(default=5, ge=0, le=60)

    # ------------------------------------------------------------------
    # Endpoint agents (v3)
    # ------------------------------------------------------------------
    # Default heartbeat interval advertised to agents; staleness threshold
    # below. Agents reconnect and retry with bounded backoff on failures.
    agent_heartbeat_interval_seconds: int = Field(default=30, ge=5, le=3600)
    # An agent whose last heartbeat is older than this is reported *stale*,
    # never assumed powered off.
    agent_heartbeat_timeout_seconds: int = Field(default=180, ge=30, le=86400)
    agent_inventory_interval_seconds: int = Field(default=300, ge=30, le=86400)
    agent_inventory_history_limit: int = Field(default=20, ge=1, le=100)
    agent_task_default_ttl_seconds: int = Field(default=600, ge=10, le=86400)
    agent_task_default_timeout_seconds: int = Field(default=120, ge=5, le=3600)
    agent_max_task_result_bytes: int = Field(default=256 * 1024, ge=4096, le=4 * 1024 * 1024)
    # Static bootstrap enrollment token (alternative to admin-issued tokens).
    agent_enrollment_token: str = ""

    # ------------------------------------------------------------------
    # Automatic registration with administrator approval (v4)
    # ------------------------------------------------------------------
    # Un-enrolled agents may introduce themselves; the request lands in
    # PENDING_APPROVAL until an administrator approves it from the dashboard.
    allow_auto_registration: bool = True
    enrollment_request_ttl_minutes: int = Field(default=1440, ge=10, le=7 * 24 * 60)
    max_pending_enrollment_requests: int = Field(default=100, ge=1, le=1000)
    # Sliding-window per-source-IP limit for the open registration endpoints.
    registration_rate_limit_per_hour: int = Field(default=30, ge=1, le=1000)

    # ------------------------------------------------------------------
    # Background AI analysis of security alerts (v5)
    # ------------------------------------------------------------------
    # Uses the SAME local LLM client as investigations (no second client).
    # The worker runs in a daemon thread; API latency never depends on it.
    ai_analysis_enabled: bool = True
    ai_analysis_max_attempts: int = Field(default=3, ge=1, le=10)
    ai_analysis_poll_seconds: float = Field(default=5.0, ge=1.0, le=300.0)
    # Bounded processing window and manual admission capacity. Automatic
    # overflow remains in durable intake until there is room; no alert is lost.
    ai_analysis_backlog_limit: int = Field(default=200, ge=10, le=5000)
    # Overflow beyond this bound remains stored as unprocessed alerts and
    # can be admitted explicitly with the recent backlog policy or manually.
    ai_analysis_intake_limit: int = Field(default=1000, ge=10, le=10000)
    # Batch analysis: related alerts (same source IP + same rule + same
    # severity) share one model request to cut request count on weak local
    # hardware. Each alert still gets its own stored result; uncovered items
    # fall back to individual analysis. 1 disables batching.
    ai_analysis_batch_size: int = Field(default=1, ge=1, le=10)
    # Anti-starvation: every this-many minutes of waiting improves a queued
    # row's effective priority by one level, so low-priority events
    # eventually get analyzed even under a constant critical-event stream.
    ai_analysis_starvation_minutes: float = Field(
        default=20.0, ge=1.0, le=1440.0
    )

    # ------------------------------------------------------------------
    # Endpoint traffic monitoring (v6) — host-local metadata only
    # ------------------------------------------------------------------
    traffic_monitoring_enabled: bool = True
    # Samples kept per agent (default ≈ 24h at a 2.5-minute cadence).
    traffic_retention_samples_per_agent: int = Field(default=576, ge=50, le=10000)
    traffic_max_connections_per_sample: int = Field(default=50, ge=0, le=200)

    # ------------------------------------------------------------------
    # Administrator control plane (v3) — disabled unless explicitly configured
    # ------------------------------------------------------------------
    # ADMIN_API_TOKEN (plaintext, >=16 chars) or ADMIN_API_TOKEN_SHA256.
    # Empty/weak values keep /api/admin/v1 disabled; there is no default.
    admin_api_token: str = ""
    admin_api_token_sha256: str = ""
    # HMAC-SHA256 key used to sign admin script/console task envelopes. The
    # signing key is never exposed to the LLM or stored in the database.
    task_signing_key: str = ""
    task_signing_v2_key_path: Path | None = None
    task_signing_allow_legacy: bool = True
    task_signing_legacy_days: int = Field(default=30, ge=0, le=90)
    # Master switches for the two administrator-only remote-execution features.
    allow_admin_python_exec: bool = False
    allow_admin_python_console: bool = False
    # On-demand screen capture of an endpoint (agent must also opt in
    # locally with --allow-screenshot). Images are never stored long-term:
    # they live inside the bounded task result.
    allow_admin_screenshot: bool = False
    screenshot_max_bytes: int = Field(default=6 * 1024 * 1024, ge=64 * 1024, le=32 * 1024 * 1024)
    admin_script_max_bytes: int = Field(default=64 * 1024, ge=256, le=1024 * 1024)
    admin_script_max_runtime_seconds: int = Field(default=60, ge=5, le=3600)
    admin_script_output_max_bytes: int = Field(default=64 * 1024, ge=1024)

    # ------------------------------------------------------------------
    # Interactive Python console (v3) — administrator-only, task-queue based
    # ------------------------------------------------------------------
    console_max_sessions_per_admin: int = Field(default=2, ge=1, le=10)
    console_max_sessions_per_agent: int = Field(default=1, ge=1, le=5)
    console_session_ttl_seconds: int = Field(default=1800, ge=60, le=4 * 3600)
    console_idle_timeout_seconds: int = Field(default=300, ge=30, le=1800)
    console_command_timeout_seconds: int = Field(default=30, ge=5, le=600)
    console_max_code_bytes: int = Field(default=32 * 1024, ge=256, le=256 * 1024)
    console_max_output_bytes: int = Field(default=64 * 1024, ge=1024, le=1024 * 1024)
    console_max_pending_commands: int = Field(default=5, ge=1, le=50)
    console_command_history_limit: int = Field(default=100, ge=10, le=1000)

    # ------------------------------------------------------------------
    # Automatic network discovery (v3)
    # ------------------------------------------------------------------
    # When enabled, private directly-connected subnets reported by enrolled
    # agents become eligible for low-impact host discovery, subject to the
    # limits below. Never applies to public/VPN/loopback/link-local ranges.
    auto_discovery_enabled: bool = False
    discovery_excluded_cidrs: str = ""
    discovery_excluded_interfaces: str = ""
    # Subnets larger (more addresses) than this are never auto-eligible.
    auto_discovery_max_addresses: int = Field(default=1024, ge=2, le=65536)
    # A subnet needs at least this many agreeing agent observations.
    auto_discovery_min_reporters: int = Field(default=1, ge=1, le=10)
    auto_discovery_ttl_seconds: int = Field(default=900, ge=30, le=86400)

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------

    @property
    def monitor_cidr_list(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for part in self.monitor_cidrs.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                continue
        return nets

    @property
    def authorized_target_list(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for part in self.authorized_targets.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                continue
        return nets

    @property
    def allowed_tcp_port_list(self) -> list[int]:
        return _parse_int_list(self.allowed_tcp_ports)

    @property
    def nmap_service_port_list(self) -> list[int]:
        ports = _parse_int_list(self.nmap_service_ports)
        return ports[: self.nmap_max_ports]

    def is_target_authorized(self, target: str) -> bool:
        """True when *target* (IP or CIDR) fits inside the authorized scope:
        MONITOR_CIDRS ∪ AUTHORIZED_TARGETS."""
        from netagent.scope import normalized_network
        try:
            addr = normalized_network(target)
        except ValueError:
            return False
        for net in self.monitor_cidr_list + self.authorized_target_list:
            net = normalized_network(str(net))
            if addr.version == net.version and addr.subnet_of(net):
                return True
        return False

    def scope_description(self) -> dict[str, list[str]]:
        return {
            "cidrs": [str(n) for n in self.monitor_cidr_list],
            "authorized_targets": [str(n) for n in self.authorized_target_list],
        }

    # --- endpoint agent / admin helpers (v3) ---

    @property
    def discovery_excluded_cidr_list(self) -> list[str]:
        return [
            p.strip() for p in self.discovery_excluded_cidrs.split(",") if p.strip()
        ]

    @property
    def discovery_excluded_interface_list(self) -> list[str]:
        return [
            p.strip() for p in self.discovery_excluded_interfaces.split(",") if p.strip()
        ]

    def agent_stale_threshold_epoch(self, now_epoch: float | None = None) -> float:
        import time as _time

        return (now_epoch if now_epoch is not None else _time.time()) - self.agent_heartbeat_timeout_seconds


def load_settings() -> Settings:
    return Settings()


def binary_available(name_or_path: str) -> bool:
    """Report whether an external executable is available."""
    if "/" in name_or_path:
        return Path(name_or_path).exists()
    return shutil.which(name_or_path) is not None
