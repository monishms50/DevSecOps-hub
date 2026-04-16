# CHANGELOG

All changes to devsecops-hub are logged here.
Format: `## YYYY-MM — description`

---

## 2025-04 — Initial build

**Added workflows:**
- `gitleaks.yml` — secret scanning with full git history support
- `bandit.yml` — Python SAST, configurable severity/confidence thresholds
- `semgrep.yml` — SAST with OWASP Top 10 + Python rulesets
- `sca.yml` — pip-audit CVE scanning + license compliance check
- `trivy.yml` — container image vulnerability scanning
- `owasp-zap.yml` — DAST baseline and full scan modes
- `pipeline.yml` — full orchestrator (stages 1–5 with conditional Trivy/ZAP)

**Added configs:**
- `.gitleaks.toml` — extends default ruleset with custom allowlist
- `.semgrep/custom-rules.yml` — FastAPI/JWT/SQL injection custom rules
- `.trivyignore` — CVE suppression file (empty — no suppressions yet)

**Added scripts:**
- `gate.py` — SARIF + pip-audit aggregation and severity gating
- `notify.sh` — Slack webhook notification on pipeline failure

**First consumer:**
- `SentryIAM` — running stages 1 (Gitleaks), 2 (Bandit + Semgrep), 3 (SCA)
- Trivy and ZAP stubs are in the caller workflow, commented out pending Dockerfile
