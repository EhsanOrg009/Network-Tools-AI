"""مهاجرت‌های افزایشی و تکرارپذیر؛ داده‌ها و شناسه‌های موجود حفظ می‌شوند."""

MIGRATIONS = {
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
