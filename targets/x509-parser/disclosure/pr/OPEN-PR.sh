#!/usr/bin/env bash
# Ready-to-fire: open the ASN1Time::add PR — run ONLY if the maintainer greenlights a PR.
# The commit is already made locally on branch fix/asn1time-add-checked-add.
set -euo pipefail
PRDIR=~/Documents/x509-parser-pr
cd "$PRDIR"
# 1) fork rusticata/x509-parser under the authed gh account (scadastrangelove) if not already
gh repo fork rusticata/x509-parser --remote=false --clone=false || true
# 2) push the branch to the fork
gh_user=$(gh api user --jq .login)
git remote get-url fork >/dev/null 2>&1 || git remote add fork "https://github.com/${gh_user}/x509-parser.git"
git push -u fork fix/asn1time-add-checked-add
# 3) open the PR against upstream main
gh pr create --repo rusticata/x509-parser \
  --base master --head "${gh_user}:fix/asn1time-add-checked-add" \
  --title "fix(time): return None on ASN1Time + Duration overflow instead of panicking" \
  --body-file "$PRDIR/PR-BODY.md"
