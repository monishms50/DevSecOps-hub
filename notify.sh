#!/usr/bin/env bash
# notify.sh — Post a Slack alert when the security pipeline fails.
#
# Required environment variables:
#   SLACK_WEBHOOK_URL  — Incoming Webhook URL from your Slack app
#   GITHUB_REPOSITORY  — Set automatically by GitHub Actions
#   GITHUB_RUN_ID      — Set automatically by GitHub Actions
#   GITHUB_REF_NAME    — Set automatically by GitHub Actions
#   GITHUB_ACTOR       — Set automatically by GitHub Actions (who triggered the run)
#
# Usage (in a GitHub Actions step):
#   env:
#     SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
#   run: bash scripts/notify.sh

set -euo pipefail

if [[ -z "${SLACK_WEBHOOK_URL:-}" ]]; then
  echo "SLACK_WEBHOOK_URL not set — skipping notification."
  exit 0
fi

RUN_URL="https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"

PAYLOAD=$(cat <<EOF
{
  "text": "❌ *Security pipeline failed*",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "❌ *Security pipeline failed*\n*Repo:* \`${GITHUB_REPOSITORY}\`\n*Branch:* \`${GITHUB_REF_NAME}\`\n*Triggered by:* ${GITHUB_ACTOR}"
      }
    },
    {
      "type": "actions",
      "elements": [
        {
          "type": "button",
          "text": { "type": "plain_text", "text": "View Run" },
          "url": "${RUN_URL}"
        }
      ]
    }
  ]
}
EOF
)

curl -s -X POST \
  -H 'Content-type: application/json' \
  --data "${PAYLOAD}" \
  "${SLACK_WEBHOOK_URL}"

echo "Slack notification sent."
