# Autonomous Agent Testing

This directory contains end-to-end autonomous agent tests that validate ClawPwn's ability to discover and exploit vulnerabilities without human guidance.

## Test File: `test_agent_autonomous.py`

Full autonomous tests against the msf2 (Metasploitable 2) container.

### Requirements

1. **API Key**: Set `ANTHROPIC_API_KEY` in your environment
2. **Target**: msf2 container running at `172.17.0.2`
3. **Network**: Host must be able to reach the container

### Running Autonomous Tests

```bash
# Skip autonomous tests (default behavior)
uv run pytest

# Run ONLY autonomous tests (requires ANTHROPIC_API_KEY)
uv run pytest -m autonomous

# Run with verbose output to see agent reasoning
uv run pytest -m autonomous -v -s

# Run a specific autonomous test
uv run pytest tests/test_agent_autonomous.py::test_phpmyadmin_autonomous_discovery -v -s
```

### Test Cases

| Test | Target | Validates |
|------|--------|-----------|
| `test_phpmyadmin_autonomous_discovery` | phpMyAdmin on MSF2 | Fingerprints, researches, and tests credentials autonomously |
| `test_web_server_autonomous_discovery` | MSF2 root web server | Discovers multiple vulnerable apps and researches them |
| `test_agent_uses_multiple_rounds` | phpMyAdmin on MSF2 | Uses multiple tool rounds and chains tools logically |

### What These Tests Verify

**Methodology Adherence**:
- Agent fingerprints before attacking ✓
- Agent researches discovered technologies ✓
- Agent tests appropriate attack vectors ✓
- Tools are chained in logical order (RECON → RESEARCH → ATTACK) ✓

**Autonomous Capabilities**:
- Identifies unknown applications without being told ✓
- Searches the web for vulnerability information ✓
- Selects appropriate tools based on discovery ✓
- Tests default credentials on login pages ✓
- Uses 8 tool rounds effectively for complex targets ✓

### Example Output

```
========================================
AUTONOMOUS TEST: phpMyAdmin Discovery
========================================
Target: http://172.17.0.2/phpMyAdmin/
Tool sequence: ['fingerprint_target', 'web_search', 'credential_test', 'web_scan']
Total tool calls: 4
========================================

✓ Agent searched: phpMyAdmin default credentials vulnerabilities
✓ Agent tested credentials
  Credential test result preview: Credential testing results for http://172.17.0.2/phpMyAdmin/...
✓ Agent found valid credentials!
✓ Session logged 4 actions

✓ PASSED: Agent successfully pentested phpMyAdmin autonomously
  - Followed methodology: FINGERPRINT → RESEARCH → CREDENTIAL TEST
  - Used 4 tool calls
  - Tool diversity: 4 unique tools
```

### Skipping Tests in CI

By default, these tests are skipped unless explicitly requested:

```yaml
# GitHub Actions example
- name: Run Autonomous Tests
  if: env.ANTHROPIC_API_KEY != ''
  run: uv run pytest -m autonomous
```

### Test Duration

- `test_phpmyadmin_autonomous_discovery`: ~15-30 seconds
- `test_web_server_autonomous_discovery`: ~30-60 seconds (marked `@slow`)
- `test_agent_uses_multiple_rounds`: ~15-30 seconds

Total: ~1-2 minutes for all autonomous tests.

### Troubleshooting

**Tests skipped with "Requires ANTHROPIC_API_KEY"**:
```bash
export ANTHROPIC_API_KEY=your_api_key
uv run pytest -m autonomous
```

**Connection errors to 172.17.0.2**:
```bash
# Verify msf2 is running
docker ps | grep msf2

# Test connectivity
curl -I http://172.17.0.2/phpMyAdmin/
```

**Test failures**:
- Check that msf2 hasn't been hardened (default credentials should work)
- Verify network connectivity from test environment to container
- Check ANTHROPIC_API_KEY is valid and has credits
- Run with `-v -s` flags to see detailed agent reasoning
