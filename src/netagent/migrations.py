"""مهاجرت‌های افزایشی و تکرارپذیر؛ داده‌ها و شناسه‌های موجود حفظ می‌شوند."""

MIGRATIONS = {
    "003_security_ai_control": """
        INSERT OR IGNORE INTO meta(key, value) VALUES('security_ai_auto_enabled', 'false');
        ALTER TABLE alert_analyses ADD COLUMN job_id TEXT;
        ALTER TABLE alert_analyses ADD COLUMN origin TEXT NOT NULL DEFAULT 'legacy';
        ALTER TABLE alert_analyses ADD COLUMN next_retry_epoch REAL NOT NULL DEFAULT 0;
        ALTER TABLE alert_analyses ADD COLUMN provider_failures INTEGER NOT NULL DEFAULT 0;
        UPDATE alert_analyses SET job_id = lower(hex(randomblob(16))) WHERE job_id IS NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_analysis_job ON alert_analyses(job_id);
        CREATE TABLE IF NOT EXISTS ai_analysis_intake (
            alert_id INTEGER PRIMARY KEY REFERENCES alerts(id),
            job_id TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
            priority INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ai_analysis_history (
            job_id TEXT PRIMARY KEY, alert_id INTEGER NOT NULL REFERENCES alerts(id),
            archived_at TEXT NOT NULL, result_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ai_history_alert ON ai_analysis_history(alert_id);
    """,
    "001_agent_result_receipts": """
        CREATE TABLE IF NOT EXISTS agent_result_receipts (
            result_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL UNIQUE REFERENCES agent_tasks(id),
            agent_id TEXT NOT NULL REFERENCES endpoint_agents(id),
            payload_sha256 TEXT NOT NULL,
            received_at TEXT NOT NULL,
            disposition TEXT NOT NULL,
            late_result_json TEXT
        );
    """,
    "002_background_jobs": """
        CREATE TABLE IF NOT EXISTS background_jobs (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL,
            created_at REAL NOT NULL, started_at REAL, finished_at REAL,
            timeout_seconds REAL NOT NULL, result_json TEXT, error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_background_jobs_status ON background_jobs(status, created_at);
    """,
}


def apply_migrations(connection):
    for name, sql in MIGRATIONS.items():
        if connection.execute("SELECT 1 FROM meta WHERE key = ?", (f"migration:{name}",)).fetchone():
            continue
        # executescript is used only during Database initialization, before
        # application workers can access the shared connection.
        try:
            connection.executescript("BEGIN;\n" + sql)
            connection.execute("INSERT INTO meta(key, value) VALUES(?, 'applied')", (f"migration:{name}",))
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
