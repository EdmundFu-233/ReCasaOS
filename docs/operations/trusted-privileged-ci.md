# Trusted privileged exact-SHA CI

Issue [#27](https://github.com/EdmundFu-233/ReCasaOS/issues/27) tracks this
merge-evidence boundary. This runbook does not authorize a deployment, a host
mount, or a persistent runner. Every privileged test runs on a disposable
GitHub-hosted Ubuntu VM and inside the existing private mount-namespace guard.

## Why a separate status is required

The primary PR workflow intentionally skips the dedicated privileged mount job
for forks, Dependabot, and authors without a trusted repository association.
GitHub considers a skipped check successful, so that job name cannot prove that
the current PR head ran the privileged matrix. GitHub also documents that its
hosted runners provide a privileged environment; the association guard limits
which code ReCasaOS elects to test, but it does not sandbox arbitrary PR code.

The required evidence context is exactly:

```text
ReCasaOS / trusted privileged exact-SHA
```

The status is attached to the complete PR head commit, not a branch name or a
rebuilt/cherry-picked commit. A new push creates a new SHA without the earlier
status and therefore invalidates the evidence automatically. GitHub requires a
required status on the latest commit; see its
[required-check troubleshooting guide](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks).

## Security boundary

The workflow has two paths:

1. After an eligible same-repository PR run, a default-branch `workflow_run`
   job reads only GitHub API metadata. It does not check out PR code, consume
   artifacts, or use a shared cache. It publishes success only if the primary
   workflow, trusted workflow, and their two policy checkers are byte-identical
   to `main`, the current PR head equals the run SHA, the privileged job passed,
   and the two root-only Samba/SQLite steps each passed exactly once.
2. A fork, Dependabot, workflow-changing, or otherwise untrusted PR requires a
   maintainer-created `trusted-privileged-promote` repository event. GitHub
   binds `repository_dispatch` to the default branch, so the caller cannot
   select a PR version of this workflow. An API-only preparation job compares
   the supplied SHA to the open PR, creates a one-time
   `ci/trusted-pr-<PR>-<full-SHA>` ref without checking out code, and records the
   commit's tree. A separate runner checks out only that ref with
   `contents: read`, `persist-credentials: false`, no secrets, no OIDC write
   permission, and no shared cache. API-only publication then re-reads the PR,
   ref, commit, tree, and runner outputs before setting the final status.

The write-capable preparation, publication, cleanup, and automatic-attestation
jobs never check out repository code. The privileged code-execution job cannot
write contents or statuses. The workflow never uses `pull_request_target` and
does not consume PR-created artifacts. GitHub warns that privileged
`workflow_run` jobs must not execute untrusted code; this split follows that
guidance in the
[GitHub Actions secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use)
and the
[workflow event documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

## Maintainer promotion procedure

Review the PR and its ordinary CI first. Never dispatch using a SHA copied only
from a comment. Read it directly from GitHub immediately before dispatch:

```bash
set -euo pipefail
repo=EdmundFu-233/ReCasaOS
pr=123
sha="$(gh pr view "$pr" --repo "$repo" --json headRefOid --jq .headRefOid)"
test "${#sha}" -eq 40
jq -n --arg pr "$pr" --arg sha "$sha" '{
  event_type: "trusted-privileged-promote",
  client_payload: {pull_request: $pr, head_sha: $sha}
}' | gh api --method POST "repos/$repo/dispatches" --input -
```

The repository-dispatch endpoint requires Contents write permission. GitHub
sets this event's SHA and ref from the default branch and only triggers a
workflow that exists there; no caller-selected workflow ref is accepted. The
jobs verify that default ref again. See GitHub's
[repository-dispatch event documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#repository_dispatch)
and
[dispatch API](https://docs.github.com/en/rest/repos/repos#create-a-repository-dispatch-event).
No `.env` value or personal token belongs in a payload, log, ref, or status.

Wait for all four manual jobs. The cleanup job must remove the one-time ref even
when testing or publication fails. Then verify the latest status directly:

```bash
set -euo pipefail
gh api "repos/$repo/commits/$sha/status" --jq '
  [.statuses[] |
    select(.context == "ReCasaOS / trusted privileged exact-SHA")] |
  if length == 0 then error("trusted status is missing")
  else sort_by(.created_at) | last |
    [.state, .target_url, .creator.login] | @tsv
  end'

trusted_ref="refs/heads/ci/trusted-pr-${pr}-${sha}"
remaining_refs="$(
  gh api \
    "repos/$repo/git/matching-refs/heads/ci/trusted-pr-${pr}-${sha}" |
    jq --arg ref "$trusted_ref" \
      '[.[] | select(.ref == $ref)] | length'
)"
test "$remaining_refs" -eq 0
```

Before merge, fetch the PR again and prove `headRefOid` still equals `sha`.
The ordinary required checks remain independently mandatory; this status proves
only the trusted-only privileged matrix for the exact object.

## Branch-protection rollout

Do not require the context until both conditions hold:

- this workflow is present on `main`; and
- a real PR head received a successful status from the expected GitHub Actions
  provider within the last seven days.

Back up and review the current protection first. Add only the single new
context; never replace the complete protection object:

```bash
repo=EdmundFu-233/ReCasaOS
gh api "repos/$repo/branches/main/protection"
gh api --method POST \
  "repos/$repo/branches/main/protection/required_status_checks/contexts" \
  -f 'contexts[]=ReCasaOS / trusted privileged exact-SHA'
```

Read the protection back and create or refresh a test PR. Confirm that a new
head without this status cannot merge, that the current exact head can merge
only after the status succeeds, and that the provider is the GitHub Actions app
observed during the verified rollout. GitHub's
[branch-protection API documentation](https://docs.github.com/en/rest/branches/branch-protection)
and
[commit-status API documentation](https://docs.github.com/en/rest/commits/statuses)
define the relevant controls.

Record the test PR number, every exercised head SHA, the automatic and manual
run URLs, the status creator, the temporary-ref cleanup result, and the final
read-back of required contexts. Evidence attached to an older head is useful
for the audit trail but must never be treated as evidence for the current head.

If the trusted workflow itself becomes unavailable, remove only this one
required context after recording the incident and opening a security issue:

```bash
gh api --method DELETE \
  "repos/$repo/branches/main/protection/required_status_checks/contexts" \
  -f 'contexts[]=ReCasaOS / trusted privileged exact-SHA'
```

Do not disable branch protection, force-push `main`, or weaken the other
required checks as a workaround.

## Expected negative behavior

| Condition | Required result |
| --- | --- |
| Malformed or shortened SHA | Preparation refuses before creating a ref or status. |
| Supplied SHA differs from the live PR head | Preparation refuses. |
| PR head moves during a run | Success is withheld; the old SHA cannot satisfy the new head. |
| Automatic PR changes the trusted primary workflow | Automatic status is withheld; manual promotion is required. |
| Privileged test or identity proof fails | Exact-SHA status becomes failure and merge remains blocked. |
| One-time ref moves unexpectedly | Publication fails and cleanup refuses to delete the moved ref. |
| External PR has only a skipped primary job | Required exact-SHA status is absent; merge remains blocked. |
| Promotion completes | The one-time ref is deleted; the immutable status remains on only that SHA. |

The repository's policy checker and mutation tests enforce these structural
boundaries before any workflow change can merge. Passing them is static
evidence only. Issue #27 stays open until live automatic/manual runs and the
branch-protection behavior above are recorded.
