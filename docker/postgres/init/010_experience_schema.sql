CREATE TABLE IF NOT EXISTS experiences (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_hint TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL,
    problem_summary TEXT NOT NULL,
    solution_summary TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('solved', 'partial', 'failed')),
    confidence REAL NOT NULL DEFAULT 0.0,
    reproducibility REAL NOT NULL DEFAULT 0.0,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT 'clawpwn',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_experiences_tenant_created
    ON experiences (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_experiences_fingerprint
    ON experiences (fingerprint);

CREATE TABLE IF NOT EXISTS experience_steps (
    id BIGSERIAL PRIMARY KEY,
    experience_id BIGINT NOT NULL REFERENCES experiences(id) ON DELETE CASCADE,
    step_order INT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_input JSONB NOT NULL DEFAULT '{}'::jsonb,
    result_summary TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_experience_steps_experience
    ON experience_steps (experience_id, step_order);

CREATE TABLE IF NOT EXISTS experience_signals (
    id BIGSERIAL PRIMARY KEY,
    experience_id BIGINT NOT NULL REFERENCES experiences(id) ON DELETE CASCADE,
    signal_key TEXT NOT NULL,
    signal_value TEXT NOT NULL,
    weight REAL NOT NULL DEFAULT 1.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_experience_signals_key_value
    ON experience_signals (signal_key, signal_value);

CREATE TABLE IF NOT EXISTS experience_embeddings (
    experience_id BIGINT PRIMARY KEY REFERENCES experiences(id) ON DELETE CASCADE,
    embedding vector(1536) NOT NULL,
    model_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
