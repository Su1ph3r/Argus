# Claude Code Instructions for Nubicustos

## Standard Operating Procedures

### After modifying these files, ALWAYS run verification:

**Trigger files:**
- `api/requirements.txt`
- `api/routers/scans.py`
- `api/services/docker_executor.py`
- `docker-compose.yml` (especially API section)
- `report-processor/**`

**Required steps:**
1. Rebuild the API container:
   ```bash
   docker compose build api && docker compose up -d api
   ```

2. Wait for API to be healthy:
   ```bash
   curl -s http://localhost:8000/api/health
   ```

3. Run integration tests:
   ```bash
   docker exec security-api sh -c "pytest /app/tests/test_report_processing.py -v --tb=short"
   ```

4. If tests pass, run a quick scan to verify end-to-end:
   ```bash
   curl -s -X POST "http://localhost:8000/api/scans" \
     -H "Content-Type: application/json" \
     -d '{"profile": "quick", "aws_profile": "nubicustos-audit"}'
   ```

5. Wait for scan completion and verify findings > 0

### Before committing changes:

- Ensure all integration tests pass
- Verify at least one scan type completes with findings
- Do NOT commit if report processing is broken

### API Request Format

When creating scans via API, use `profile` not `scan_type`:
- `"profile": "quick"` - Prowler only (~3 min)
- `"profile": "comprehensive"` - All tools (~11 min)
- `"profile": "compliance-only"` - Prowler + ScoutSuite (~5 min)

### Git Commit Guidelines

- Do not include "Claude" or "Co-Authored-By" in commit messages
- Keep commit messages descriptive of what changed and why

### Known Dependencies

The API container requires these for direct report processing:
- pandas, numpy (data processing)
- jinja2, tabulate (templating)
- pyyaml, click, colorama (utilities)
- `/processed` tmpfs mount (writable directory)
- `/reports` volume mount (readable)
- `/app/report-processor` volume mount (code)
