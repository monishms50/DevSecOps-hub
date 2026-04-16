# devsecops-hub

A centralized security pipeline library. All CI/CD security tooling, configurations, and reusable workflows live here. Project repos call in — they don't copy anything.

---

## What This Repo Is

This is a **library repo**, not an application. It contains:

- Reusable GitHub Actions workflows (one per security tool)
- Tool configuration files (Gitleaks rules, Semgrep rulesets, Trivy ignore lists, ZAP rules)
- Helper scripts (SARIF aggregation, Slack notifications, severity gating)
- Research notes on tools evaluated or in use

Project repos integrate by referencing workflows here with a single `uses:` line. When a tool is updated or tuned here, all projects benefit automatically on their next run.

---

## Repository Structure

```
devsecops-hub/
├── .github/
│   └── workflows/
│       ├── gitleaks.yml          # Secret scanning
│       ├── semgrep.yml           # SAST — fast, custom rules
│       ├── bandit.yml            # SAST — Python-specific
│       ├── codeql.yml            # SAST — deep interprocedural analysis
│       ├── sca.yml               # pip-audit + license check
│       ├── trivy.yml             # Container image scanning
│       ├── owasp-zap.yml         # DAST — authenticated scan support
│       └── pipeline.yml          # Orchestrator (calls all stages in order)
│
├── configs/
│   ├── .gitleaks.toml            # Custom secret detection rules
│   ├── .secrets.baseline         # detect-secrets baseline (known false positives)
│   ├── .semgrep/
│   │   └── custom-rules.yml      # Project-specific Semgrep rules
│   ├── .trivyignore              # CVEs suppressed with documented justification
│   └── zap-rules.tsv             # ZAP passive/active scan rule overrides
│
├── scripts/
│   ├── gate.py                   # Reads SARIF, fails pipeline on HIGH/CRITICAL
│   └── notify.sh                 # Posts Slack alert with run URL on failure
│
├── docs/
│   └── tool-research/
│       ├── gitleaks.md
│       ├── semgrep.md
│       ├── trivy.md
│       └── owasp-zap.md          # Notes, tradeoffs, config decisions per tool
│
├── README.md
└── CHANGELOG.md
```

---

## Pipeline Stages

| Stage | Tool(s) | What It Catches |
|---|---|---|
| Pre-flight | Gitleaks, detect-secrets | Secrets committed to source code |
| SAST | Bandit, Semgrep, CodeQL | Insecure code patterns, data flow vulnerabilities |
| SCA | pip-audit, pip-licenses | Vulnerable dependencies, license compliance |
| Build | Docker + Trivy | Vulnerabilities in the container image and OS packages |
| DAST | OWASP ZAP | Runtime vulnerabilities in a live running app |
| Report | gate.py, notify.sh | Aggregate findings, fail on severity threshold, alert team |

Each stage is a separate reusable workflow file. Projects can call individual stages or the full orchestrator.

---

## How Projects Integrate

Each workflow in `.github/workflows/` is a **reusable workflow** — it declares `on: workflow_call` so external repos can invoke it directly.

### Calling a single tool

```yaml
# In your project repo's .github/workflows/security.yml

jobs:
  gitleaks:
    uses: monish/devsecops-hub/.github/workflows/gitleaks.yml@main
    secrets: inherit
```

### Calling multiple tools with ordering

```yaml
jobs:
  semgrep:
    uses: monish/devsecops-hub/.github/workflows/semgrep.yml@main
    secrets: inherit

  gitleaks:
    needs: semgrep          # waits for semgrep to pass before running
    uses: monish/devsecops-hub/.github/workflows/gitleaks.yml@main
    secrets: inherit
```

### Passing inputs (e.g. image name for Trivy)

```yaml
jobs:
  trivy:
    uses: monish/devsecops-hub/.github/workflows/trivy.yml@main
    with:
      image_ref: myapp:${{ github.sha }}
    secrets: inherit
```

### Running the full pipeline

```yaml
jobs:
  security:
    uses: monish/devsecops-hub/.github/workflows/pipeline.yml@main
    secrets: inherit
```

The rule is simple: **this repo controls how each tool runs. Your project repo controls when and in what order.**

---

## Severity Thresholds

The `gate.py` script reads SARIF output from all tools and makes the final pass/fail decision.

| Severity | Default Behavior |
|---|---|
| CRITICAL | ❌ Fail pipeline immediately |
| HIGH | ❌ Fail pipeline |
| MEDIUM | ⚠️ Warn only (logged, not blocking) |
| LOW | ⚠️ Warn only |

To override for a specific project, pass a threshold input:

```yaml
uses: monish/devsecops-hub/.github/workflows/pipeline.yml@main
with:
  fail_on: "CRITICAL"    # only fail on critical, not high
```

---

## Suppressing False Positives

Every suppression must have a reason and an expiry. No undocumented ignores.

**Inline (SAST):**
```python
subprocess.call(cmd, shell=True)  # nosec B602 — TICKET-123, review 2025-09-01
```

**Trivy — `.trivyignore`:**
```
# CVE-2024-12345 — no upstream patch available as of 2025-03-01, review 2025-06-01
CVE-2024-12345
```

**Semgrep — inline:**
```python
result = eval(expr)  # nosemgrep: python.lang.security.audit.eval-detected — TICKET-456
```

Suppressions are reviewed quarterly. Expired suppressions fail the pipeline.

---

## Adding a New Tool

1. Research the tool — write notes in `docs/tool-research/<toolname>.md` covering: what it finds, what it misses, config options, known false positive patterns, and how it compares to existing tools.
2. Add a config file to `configs/` if the tool supports one.
3. Create a reusable workflow in `.github/workflows/<toolname>.yml` with `on: workflow_call`.
4. Add the new stage to `pipeline.yml` at the appropriate position.
5. Update this README's pipeline stage table.
6. Log the addition in `CHANGELOG.md`.

---

## Projects Using This Hub

| Project | Workflows Used | Trigger |
|---|---|---|
| `iam-service` | `pipeline.yml` (full) | Every PR + push to main |
| *(add your project here)* | | |

---

## CHANGELOG

### 2025-03
- Initial repo setup
- Added: Gitleaks, Semgrep, Bandit, pip-audit, Trivy, OWASP ZAP
- Added: `gate.py` severity gating script
- Added: `notify.sh` Slack notification
