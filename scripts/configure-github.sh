#!/usr/bin/env bash
# Apply the repository's security settings. Everything here is free for
# public repositories. Run once after creating the repository, as an org
# admin:  ./scripts/configure-github.sh gydr-ai/mcp-oauth
set -euo pipefail

repo="${1:?usage: configure-github.sh <owner/repo>}"

echo "Repository settings"
gh api -X PATCH "repos/$repo" --silent \
  -F has_wiki=false -F has_projects=false -F has_discussions=false \
  -F allow_merge_commit=false -F allow_rebase_merge=false \
  -F allow_squash_merge=true -F allow_auto_merge=false \
  -F delete_branch_on_merge=true -F allow_update_branch=true \
  -f squash_merge_commit_title=PR_TITLE \
  -f squash_merge_commit_message=PR_BODY \
  -F web_commit_signoff_required=false \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
# Non-provider patterns and validity checks are paid GitHub Advanced Security
# features, so they are deliberately not requested: everything here is free
# for public repositories.

echo "Private vulnerability reporting"
gh api -X PUT "repos/$repo/private-vulnerability-reporting" --silent

echo "Dependabot alerts and security updates"
gh api -X PUT "repos/$repo/vulnerability-alerts" --silent
gh api -X PUT "repos/$repo/automated-security-fixes" --silent

# can_approve_pull_request_reviews also governs whether a workflow may
# OPEN a pull request, which release-please needs. An approval by Actions
# never satisfies the ruleset: it requires a code owner's review.
echo "Actions: read-only token, release PRs by Actions, SHA pinning"
gh api -X PUT "repos/$repo/actions/permissions/workflow" --silent \
  -f default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=true
gh api -X PUT "repos/$repo/actions/permissions" --silent \
  -F enabled=true -f allowed_actions=all -F sha_pinning_required=true
gh api -X PUT "repos/$repo/actions/permissions/fork-pr-contributor-approval" \
  --silent -f approval_policy=all_external_contributors

echo "Protected npm environment (add required reviewers in the UI)"
# Releases are published by the workflow run on main that merged the
# release pull request, so main is the only ref allowed to deploy.
gh api -X PUT "repos/$repo/environments/npm" --silent --input - <<JSON
{
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true }
}
JSON
if ! gh api "repos/$repo/environments/npm/deployment-branch-policies" \
  --jq '.branch_policies[].name' | grep -qx main; then
  gh api -X POST "repos/$repo/environments/npm/deployment-branch-policies" \
    --silent -f name=main -f type=branch
fi

# Org admins may merge their own pull request without a second approval
# (bypass_mode "pull_request"), but nobody can push to main directly.
echo "Branch ruleset for main"
ruleset_id=$(gh api "repos/$repo/rulesets" --jq '.[] | select(.name=="main") | .id')
method=POST
path="repos/$repo/rulesets"
if [ -n "$ruleset_id" ]; then method=PUT; path="repos/$repo/rulesets/$ruleset_id"; fi
gh api -X "$method" "$path" --silent --input - <<'JSON'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "pull_request" }
  ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    { "type": "required_signatures" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true,
        "allowed_merge_methods": ["squash"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "Check (Node 22)" },
          { "context": "Check (Node 24)" },
          { "context": "Check (Node 26)" },
          { "context": "Dependency audit" },
          { "context": "Analyze (javascript-typescript)" }
        ]
      }
    }
  ]
}
JSON

echo "Tag ruleset: release tags can't be moved or deleted"
gh api -X POST "repos/$repo/rulesets" --silent --input - <<'JSON' || true
{
  "name": "release-tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [ { "type": "deletion" }, { "type": "non_fast_forward" }, { "type": "update" } ]
}
JSON

echo "Done. Still in the UI: add required reviewers to the npm environment."
