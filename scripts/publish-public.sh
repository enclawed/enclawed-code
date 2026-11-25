#!/usr/bin/env bash
# Snapshot the current working tree to every public mirror as a single orphan
# commit on `main`, after wiping every branch and tag on each mirror. The SAME
# snapshot commit is pushed to all mirrors, so they end up byte-identical. The
# private remote (`origin`, a *-private repository with the full history) and
# the local working tree / HEAD are not touched.
#
# Public mirrors = every remote whose name matches `public-*`. Set one up with:
#   git remote add public-enclawed git@github.com:enclawed/<name>.git
#
# Usage: scripts/publish-public.sh [--yes | --check]
#   --yes    skip the interactive confirmation
#   --check  run every gate and build the snapshot tree, then stop (no push)
#
# The snapshot is HEAD's tree (committed and pushed to origin), never the
# working tree. vendor/enclawed-oss is re-pointed in the snapshot: the private
# repository pins a commit of the private enclawed-oss repository, which the
# public cannot fetch. enclawed-oss is itself published as an orphan snapshot
# (enclawed-oss scripts/publish-public.sh), so the public commit has another
# SHA. This script finds the public enclawed-oss main, checks that its tree is
# exactly the pinned private commit's tree as that script publishes it, and
# pins the public commit instead. It refuses otherwise: publish enclawed-oss
# at the pinned commit first. The private repository keeps its own pin.
#
# Order of a release: enclawed-oss publish-public.sh at commit P; bump
# vendor/enclawed-oss here to P, commit, push origin; then this script.
# Every later enclawed-oss publish replaces its public main, so the public
# Enclawed Code must be published again after it.
#
# Environment:
#   ENCLAWED_OSS_DIR  a clone of the private enclawed-oss (default ../enclawed-oss)
#                     holding the pinned commit; the public main is fetched into it
#
# Notes:
#   - GitHub-managed `refs/pull/*` refs cannot be deleted by push; left as-is.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
APP_ROOT="$(pwd)"

# The public enclawed-oss mirror the submodule must name, and the paths its
# publish-public.sh removes from every snapshot (keep in step with it).
OSS_PUBLIC_REPO="enclawed/enclawed-oss"
OSS_PUBLIC_URL="https://github.com/${OSS_PUBLIC_REPO}.git"
OSS_SNAPSHOT_EXCLUDES=(clients .github/workflows .github/dependabot.yml)

mapfile -t PUBLIC_REMOTES < <(git remote | grep -E '^public-.+$' | sort)
if [ "${#PUBLIC_REMOTES[@]}" -eq 0 ]; then
  echo "error: no public mirror configured (need a remote named 'public-*')" >&2
  exit 1
fi

# This force-replaces every branch and tag on each mirror with one orphan
# commit. Pointed at the wrong repository by a typo, it would flatten the
# private history. Refuse the private source, any *-private repository, the
# enterprise tree, and anything outside the enclawed organization.
ORIGIN_URL=$(git remote get-url origin 2>/dev/null || echo "")
repo_of() { # owner/name from an ssh, https or ssh-alias GitHub URL
  echo "$1" | sed -E 's#^[a-z+]+://##; s#^git@##; s#^[^:/]+[:/]##; s#\.git$##; s#/$##'
}
for r in "${PUBLIC_REMOTES[@]}"; do
  url=$(git remote get-url "$r")
  repo=$(repo_of "$url")
  if [ -n "$ORIGIN_URL" ] && [ "$repo" = "$(repo_of "$ORIGIN_URL")" ]; then
    echo "REFUSING TO PUBLISH: $r points at origin ($url), the private source." >&2
    exit 1
  fi
  case "$repo" in
    *-private | */enclawed-enclaved | */*-enclaved)
      echo "REFUSING TO PUBLISH: $r points at $repo, which is private." >&2
      exit 1
      ;;
    enclawed/*) ;;
    *)
      echo "REFUSING TO PUBLISH: $r points at $repo, which is not an enclawed repository." >&2
      exit 1
      ;;
  esac
done


# A public snapshot is a copy of a RECORDED private commit, never of whatever is
# on disk: refuse a dirty tree, and refuse a HEAD that is not on the private
# origin yet. The snapshot is then built from HEAD's tree, so the public mirror
# can never be newer than the private repository it is cut from.
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  echo "REFUSING TO PUBLISH: the working tree has uncommitted changes." >&2
  echo "  commit them and push to origin first; the snapshot is taken from HEAD." >&2
  git status --short | head -20 >&2
  exit 1
fi
git fetch -q origin
UPSTREAM=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)
if [ -z "$UPSTREAM" ] || [ "$(git rev-parse HEAD)" != "$(git rev-parse "$UPSTREAM")" ]; then
  echo "REFUSING TO PUBLISH: HEAD is not pushed to the private origin (upstream: ${UPSTREAM:-none})." >&2
  echo "  push first: git push origin HEAD" >&2
  exit 1
fi

SNAP_INDEX=$(mktemp -u)
trap 'rm -f "$SNAP_INDEX"' EXIT
GIT_INDEX_FILE="$SNAP_INDEX" git read-tree HEAD
# Public mirrors carry no CI/automation: drop GitHub Actions workflows and the
# Dependabot config from the snapshot (index only; the working tree and origin
# keep them).
GIT_INDEX_FILE="$SNAP_INDEX" git rm -r --cached --quiet --ignore-unmatch \
  .github/workflows .github/dependabot.yml >/dev/null 2>&1 || true

# vendor/enclawed-oss: re-point the gitlink at the public commit whose tree is
# the pinned private commit's published tree.
SUB_URL=$(git config -f .gitmodules --get submodule.vendor/enclawed-oss.url || true)
if [ "$(repo_of "$SUB_URL")" != "$OSS_PUBLIC_REPO" ]; then
  echo "REFUSING TO PUBLISH: .gitmodules points vendor/enclawed-oss at '$SUB_URL', not the public ${OSS_PUBLIC_URL}" >&2
  exit 1
fi
PIN=$(git ls-tree HEAD vendor/enclawed-oss | awk '$2 == "commit" {print $3}')
if [ -z "$PIN" ]; then
  echo "REFUSING TO PUBLISH: vendor/enclawed-oss is not a gitlink in HEAD" >&2
  exit 1
fi
OSS_DIR="${ENCLAWED_OSS_DIR:-$APP_ROOT/../enclawed-oss}"
if ! git -C "$OSS_DIR" cat-file -e "${PIN}^{commit}" 2>/dev/null; then
  echo "REFUSING TO PUBLISH: the pinned enclawed-oss commit $PIN is not in $OSS_DIR" >&2
  echo "  set ENCLAWED_OSS_DIR to a clone of the private enclawed-oss that has it" >&2
  exit 1
fi
echo "finding the public enclawed-oss commit for the pinned ${PIN:0:12} ..."
git -C "$OSS_DIR" fetch -q --no-tags "$OSS_PUBLIC_URL" main
PUBLIC_OSS=$(git -C "$OSS_DIR" rev-parse FETCH_HEAD)
OSS_INDEX=$(mktemp -u)
GIT_INDEX_FILE="$OSS_INDEX" git -C "$OSS_DIR" read-tree "$PIN"
GIT_INDEX_FILE="$OSS_INDEX" git -C "$OSS_DIR" rm -r --cached --quiet --ignore-unmatch \
  "${OSS_SNAPSHOT_EXCLUDES[@]}" >/dev/null 2>&1 || true
WANT_TREE=$(GIT_INDEX_FILE="$OSS_INDEX" git -C "$OSS_DIR" write-tree)
rm -f "$OSS_INDEX"
HAVE_TREE=$(git -C "$OSS_DIR" rev-parse "${PUBLIC_OSS}^{tree}")
if [ "$WANT_TREE" != "$HAVE_TREE" ]; then
  echo "REFUSING TO PUBLISH: the public enclawed-oss main (${PUBLIC_OSS:0:12}) is not the published" >&2
  echo "  snapshot of the pinned commit ${PIN:0:12}. Publish enclawed-oss at ${PIN:0:12} first" >&2
  echo "  (enclawed-oss scripts/publish-public.sh), or pin the commit that was published." >&2
  exit 1
fi
GIT_INDEX_FILE="$SNAP_INDEX" git update-index --cacheinfo "160000,${PUBLIC_OSS},vendor/enclawed-oss"
echo "  ok — vendor/enclawed-oss -> public ${PUBLIC_OSS:0:12} (snapshot of ${PIN:0:12})"

SNAP_FILES=$(GIT_INDEX_FILE="$SNAP_INDEX" git ls-files --cached | grep -v '^vendor/enclawed-oss$')

# Filenames that look sensitive stop the publish (a small repo has no reason
# to ship them; move the file or add it to .gitignore).
SUSPECT=$(echo "$SNAP_FILES" \
  | grep -iE '(^|/)\.env($|\.[^e]|_)|\.pem$|\.key$|id_rsa|id_ed25519|\.netrc|\.p12$|\.pfx$|credentials\.json$' || true)
if [ -n "$SUSPECT" ]; then
  echo "REFUSING TO PUBLISH: sensitive-looking files are in the snapshot:" >&2
  echo "$SUSPECT" >&2
  exit 1
fi

# Secret-shaped content in any published text file stops the publish, decided
# by enclawed-oss's own checker from the pinned commit (one definition for both
# public trees): real-shaped keys and tokens fail; obvious test stand-ins and
# lines recorded in security/secret-scan-reviewed.txt do not. A pinned commit
# without the checker is a refusal: pin one that has it.
echo "checking the snapshot for secret-shaped text ..."
SECRET_CHECK=$(mktemp --suffix=.mjs)
if ! git -C "$OSS_DIR" show "${PIN}:scripts/check-secret-text.mjs" >"$SECRET_CHECK" 2>/dev/null; then
  rm -f "$SECRET_CHECK"
  echo "REFUSING TO PUBLISH: the pinned enclawed-oss ${PIN:0:12} has no scripts/check-secret-text.mjs; pin a newer commit." >&2
  exit 1
fi
if ! echo "$SNAP_FILES" | node "$SECRET_CHECK"; then
  rm -f "$SECRET_CHECK"
  echo "REFUSING TO PUBLISH: secret-shaped text found." >&2
  exit 1
fi
rm -f "$SECRET_CHECK"

# No Enclaweder internals (the enclawed-oss rule, applied with its own
# checker from the pinned commit's tree): hardware internals stop the publish.
echo "checking the snapshot for Enclaweder hardware internals ..."
HW_CHECK=$(mktemp --suffix=.mjs)
git -C "$OSS_DIR" show "${PIN}:scripts/check-hardware-disclosure.mjs" >"$HW_CHECK"
if ! echo "$SNAP_FILES" | node "$HW_CHECK"; then
  rm -f "$HW_CHECK"
  echo "REFUSING TO PUBLISH: the snapshot may describe Enclaweder internals." >&2
  exit 1
fi
rm -f "$HW_CHECK"

# Dependency audit at zero, every time. With no lockfile there is nothing to
# audit only when the package declares no dependencies at all.
DECLARED=$(node -e 'const p=require("./package.json");const n=Object.keys({...p.dependencies,...p.optionalDependencies,...p.peerDependencies}).length;console.log(n)')
if [ ! -f package-lock.json ] && [ ! -f pnpm-lock.yaml ] && [ "$DECLARED" != "0" ]; then
  echo "REFUSING TO PUBLISH: package.json declares $DECLARED dependencies but there is no lockfile to audit." >&2
  exit 1
fi
if [ -f package-lock.json ] || [ -f pnpm-lock.yaml ]; then
  echo "checking the dependency tree for known vulnerabilities ..."
  if [ -f pnpm-lock.yaml ]; then AUDIT="pnpm audit"; else AUDIT="npm audit --omit=dev"; fi
  if ! $AUDIT >/dev/null 2>&1; then
    echo "REFUSING TO PUBLISH: '$AUDIT' is not clean, or could not run." >&2
    $AUDIT 2>&1 | tail -20 >&2 || true
    exit 1
  fi
  echo "  ok"
fi

if [ "${1:-}" = "--check" ]; then
  echo
  echo "check only: every gate passed; snapshot tree $(GIT_INDEX_FILE="$SNAP_INDEX" git write-tree) (nothing pushed)"
  exit 0
fi

DIRTY=$(git status --short | wc -l | tr -d ' ')
HEAD_SHA=$(git rev-parse --short HEAD)
BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null || echo "(detached)")

echo
echo "About to publish one identical snapshot to ${#PUBLIC_REMOTES[@]} public mirror(s):"
for r in "${PUBLIC_REMOTES[@]}"; do
  echo "  - $r  ($(git remote get-url "$r"))"
done
echo "  source branch : $BRANCH @ $HEAD_SHA"
echo "  snapshot of   : HEAD (committed and pushed to origin)"
echo "  destination   : <remote>/main (force-replace, single orphan commit)"
echo

if [ "${1:-}" != "--yes" ]; then
  read -r -p "Proceed? [y/N] " ans
  case "$ans" in
    y|Y|yes|YES) ;;
    *) echo "aborted"; exit 1 ;;
  esac
fi

TREE=$(GIT_INDEX_FILE="$SNAP_INDEX" git write-tree)
COMMIT=$(git commit-tree "$TREE" -m "Snapshot $(date -u +%Y-%m-%d)")
echo "built snapshot commit $COMMIT (tree $TREE)"

for r in "${PUBLIC_REMOTES[@]}"; do
  echo "publishing to $r ..."
  git ls-remote --heads "$r" | awk '$2 != "refs/heads/main" {print $2}' | sed 's|^|:|' | xargs -r -n1 git push "$r"
  git ls-remote --tags "$r" | awk '{print $2}' | sed 's|^|:|' | xargs -r -n1 git push "$r"
  git push "$r" "$COMMIT:refs/heads/main" --force
  echo "  $r/main -> $COMMIT"
done
echo
echo "done. all public mirrors -> $COMMIT"
