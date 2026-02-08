-- Seed high-value exploitation knowledge. Re-applied idempotently.

-- 1) Generic stateful login workflow
DELETE FROM experiences
WHERE tenant_id = 'default'
  AND fingerprint = 'stateful_form_login_v1';

WITH inserted AS (
    INSERT INTO experiences (
        tenant_id,
        project_hint,
        fingerprint,
        problem_summary,
        solution_summary,
        outcome,
        confidence,
        reproducibility,
        metadata,
        created_by
    )
    VALUES (
        'default',
        'generic',
        'stateful_form_login_v1',
        'Credential tests fail because login endpoints require hidden fields and session continuity.',
        'Always perform GET->parse all hidden + visible fields->preserve cookies->POST full payload->evaluate redirect/content. If credentials_tested=0, treat parser as failed and retry with alternate form selection.',
        'solved',
        0.95,
        0.90,
        '{"category":"auth","tags":["forms","csrf","cookies","redirect"],"kind":"playbook"}'::jsonb,
        'seed'
    )
    RETURNING id
)
INSERT INTO experience_steps (experience_id, step_order, tool_name, tool_input, result_summary)
SELECT inserted.id, v.step_order, v.tool_name, v.tool_input, v.result_summary
FROM inserted
JOIN (
    VALUES
        (1, 'http_get', '{"purpose":"collect cookies and hidden fields"}'::jsonb, 'Initial state captured'),
        (2, 'form_parse', '{"include_hidden":true,"prefer_auth_form":true}'::jsonb, 'All required params extracted'),
        (3, 'http_post', '{"preserve_cookies":true,"include_all_fields":true}'::jsonb, 'Auth request mirrors browser flow'),
        (4, 'auth_validate', '{"check_redirect":true,"check_logout_marker":true}'::jsonb, 'Success inferred safely')
) AS v(step_order, tool_name, tool_input, result_summary)
ON TRUE;

INSERT INTO experience_signals (experience_id, signal_key, signal_value, weight)
SELECT e.id, s.signal_key, s.signal_value, s.weight
FROM experiences e
JOIN (
    VALUES
        ('pattern', 'hidden_input_required', 1.0),
        ('pattern', 'session_cookie_required', 1.0),
        ('pattern', 'redirect_based_success', 0.8),
        ('diagnostic', 'credentials_tested_zero', 1.0)
) AS s(signal_key, signal_value, weight)
ON e.tenant_id = 'default'
AND e.fingerprint = 'stateful_form_login_v1';

-- 2) phpMyAdmin specific login flow
DELETE FROM experiences
WHERE tenant_id = 'default'
  AND fingerprint = 'phpmyadmin_login_flow_v1';

WITH inserted AS (
    INSERT INTO experiences (
        tenant_id,
        project_hint,
        fingerprint,
        problem_summary,
        solution_summary,
        outcome,
        confidence,
        reproducibility,
        metadata,
        created_by
    )
    VALUES (
        'default',
        'phpmyadmin',
        'phpmyadmin_login_flow_v1',
        'phpMyAdmin auth fails when only username/password are submitted.',
        'Submit pma_username+pma_password with hidden fields token/set_session plus server=1 and target=index.php while preserving phpMyAdmin/pma_lang cookies from the initial GET.',
        'solved',
        0.98,
        0.92,
        '{"category":"auth","tags":["phpmyadmin","cookies","token","set_session"],"kind":"target_profile"}'::jsonb,
        'seed'
    )
    RETURNING id
)
INSERT INTO experience_steps (experience_id, step_order, tool_name, tool_input, result_summary)
SELECT inserted.id, v.step_order, v.tool_name, v.tool_input, v.result_summary
FROM inserted
JOIN (
    VALUES
        (1, 'http_get', '{"path":"/phpMyAdmin/index.php","capture_cookies":true}'::jsonb, 'Captured token and session cookies'),
        (2, 'form_parse', '{"expected_fields":["pma_username","pma_password","token","set_session"]}'::jsonb, 'Parsed phpMyAdmin login payload'),
        (3, 'http_post', '{"path":"/phpMyAdmin/index.php","extra_fields":{"server":"1","target":"index.php"}}'::jsonb, 'Submitted complete phpMyAdmin auth request'),
        (4, 'auth_validate', '{"success_markers":["logout","mainFrameset","db_structure"],"redirect_target":"index.php"}'::jsonb, 'Validated authenticated state')
) AS v(step_order, tool_name, tool_input, result_summary)
ON TRUE;

INSERT INTO experience_signals (experience_id, signal_key, signal_value, weight)
SELECT e.id, s.signal_key, s.signal_value, s.weight
FROM experiences e
JOIN (
    VALUES
        ('path', '/phpMyAdmin/', 1.0),
        ('field', 'pma_username', 1.0),
        ('field', 'pma_password', 1.0),
        ('field', 'set_session', 1.0),
        ('field', 'token', 1.0),
        ('cookie', 'phpMyAdmin', 1.0),
        ('cookie', 'pma_lang', 0.6)
) AS s(signal_key, signal_value, weight)
ON e.tenant_id = 'default'
AND e.fingerprint = 'phpmyadmin_login_flow_v1';

-- 3) phpMyAdmin setup.php exploit knowledge (CVE-2009-1151 pattern)
DELETE FROM experiences
WHERE tenant_id = 'default'
  AND fingerprint = 'phpmyadmin_setup_cve_2009_1151_v1';

WITH inserted AS (
    INSERT INTO experiences (
        tenant_id,
        project_hint,
        fingerprint,
        problem_summary,
        solution_summary,
        outcome,
        confidence,
        reproducibility,
        metadata,
        created_by
    )
    VALUES (
        'default',
        'phpmyadmin',
        'phpmyadmin_setup_cve_2009_1151_v1',
        'Old phpMyAdmin installs may expose setup.php config write leading to code execution.',
        'Check /phpMyAdmin/scripts/setup.php reachability, extract token+session, submit save action for malicious configuration path, then trigger config load endpoint. Abort if setup is disabled or non-vulnerable version.',
        'partial',
        0.85,
        0.70,
        '{"category":"rce","tags":["phpmyadmin","setup.php","cve-2009-1151"],"kind":"exploit_path"}'::jsonb,
        'seed'
    )
    RETURNING id
)
INSERT INTO experience_steps (experience_id, step_order, tool_name, tool_input, result_summary)
SELECT inserted.id, v.step_order, v.tool_name, v.tool_input, v.result_summary
FROM inserted
JOIN (
    VALUES
        (1, 'http_get', '{"path":"/phpMyAdmin/scripts/setup.php"}'::jsonb, 'Validated setup endpoint and extracted token'),
        (2, 'http_post', '{"action":"save","requires_token":true,"preserve_cookies":true}'::jsonb, 'Attempted configuration write'),
        (3, 'http_get', '{"path":"/phpMyAdmin/config/config.inc.php"}'::jsonb, 'Triggered config load path'),
        (4, 'verify', '{"check_effect":"command_execution_or_file_write"}'::jsonb, 'Confirmed or rejected exploitability')
) AS v(step_order, tool_name, tool_input, result_summary)
ON TRUE;

INSERT INTO experience_signals (experience_id, signal_key, signal_value, weight)
SELECT e.id, s.signal_key, s.signal_value, s.weight
FROM experiences e
JOIN (
    VALUES
        ('path', '/phpMyAdmin/scripts/setup.php', 1.0),
        ('version', 'legacy_phpmyadmin', 0.9),
        ('cve', 'CVE-2009-1151', 1.0)
) AS s(signal_key, signal_value, weight)
ON e.tenant_id = 'default'
AND e.fingerprint = 'phpmyadmin_setup_cve_2009_1151_v1';

-- 4) Diagnostics when credential testing reports zero attempts
DELETE FROM experiences
WHERE tenant_id = 'default'
  AND fingerprint = 'credential_test_zero_attempts_diagnostic_v1';

WITH inserted AS (
    INSERT INTO experiences (
        tenant_id,
        project_hint,
        fingerprint,
        problem_summary,
        solution_summary,
        outcome,
        confidence,
        reproducibility,
        metadata,
        created_by
    )
    VALUES (
        'default',
        'generic',
        'credential_test_zero_attempts_diagnostic_v1',
        'Credential test reports zero attempted pairs despite login form being present.',
        'Treat as parsing/field-mapping defect: enumerate all forms, include hidden fields, map app-specific usernames/password fields, and replay with preserved cookies before concluding no valid credentials.',
        'solved',
        0.92,
        0.88,
        '{"category":"diagnostic","tags":["credential_test","parser","form_selection"],"kind":"runbook"}'::jsonb,
        'seed'
    )
    RETURNING id
)
INSERT INTO experience_steps (experience_id, step_order, tool_name, tool_input, result_summary)
SELECT inserted.id, v.step_order, v.tool_name, v.tool_input, v.result_summary
FROM inserted
JOIN (
    VALUES
        (1, 'diagnose', '{"condition":"credentials_tested==0"}'::jsonb, 'Identified parser miss condition'),
        (2, 'form_enumeration', '{"all_forms":true,"score_by_auth_indicators":true}'::jsonb, 'Selected best auth form'),
        (3, 'field_mapping', '{"support_aliases":["user","username","login","email","pma_username","pass","password","pma_password"]}'::jsonb, 'Mapped usable credentials fields'),
        (4, 'retry_auth', '{"preserve_cookies":true,"include_hidden":true}'::jsonb, 'Retested credentials with corrected payload')
) AS v(step_order, tool_name, tool_input, result_summary)
ON TRUE;

INSERT INTO experience_signals (experience_id, signal_key, signal_value, weight)
SELECT e.id, s.signal_key, s.signal_value, s.weight
FROM experiences e
JOIN (
    VALUES
        ('diagnostic', 'credentials_tested_zero', 1.0),
        ('diagnostic', 'form_found_true', 0.8),
        ('action', 'retry_with_full_payload', 0.9)
) AS s(signal_key, signal_value, weight)
ON e.tenant_id = 'default'
AND e.fingerprint = 'credential_test_zero_attempts_diagnostic_v1';
