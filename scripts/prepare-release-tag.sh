#!/usr/bin/env bash
set -euo pipefail

mode="${1:?usage: prepare-release-tag.sh plan|publish TAG [CI_SHA] [REMOTE]}"
tag="${2:?tag is required}"
ci_sha="${3:-}"
remote="${4:-origin}"

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid stable version tag: $tag" >&2
  exit 2
fi

if git ls-remote --exit-code --tags "$remote" "refs/tags/$tag" >/dev/null 2>&1; then
  echo "$tag already exists; skip"
  exit 10
fi

if [[ "$mode" == "plan" ]]; then
  if [[ -n "$ci_sha" ]] && [[ "$(git rev-parse "$remote/main")" != "$ci_sha" ]]; then
    echo "CI sha $ci_sha is no longer main; skip stale release"
    exit 10
  fi
  echo "$tag requires release approval"
  exit 0
fi

if [[ "$mode" != "publish" ]]; then
  echo "unsupported mode: $mode" >&2
  exit 2
fi

target="$(git rev-parse HEAD)"
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git tag -a "$tag" "$target" -m "Release $tag"
git push "$remote" "$tag"
echo "created and pushed $tag at $target"
