#!/bin/bash

# This is my own simple codeberg generic releaser. It takes to
# binaries to be uploaded as arguments and takes every other args from
# env. Works on tags or normal commits (push), tags must start with v.


set -e

die() {
    echo $*
    exit 1
}

if test -z "$DEPLOY_TOKEN"; then
    die "token DEPLOY_TOKEN not set"
fi

git fetch --all

# determine current tag or commit hash
version="$CI_COMMIT_TAG"
previous=""
log=""
if test -z "$version"; then
    version="${CI_COMMIT_SHA:0:6}"
    log=$(git log -1 --oneline)
else
    previous=$(git tag -l | grep -E "^v" | tac | grep -A1 "$version" | tail -1)
    log=$(git log -1 --oneline "${previous}..${version}" | sed 's|^|- |g')
fi

# release body
printf "# Changes\n\n %s\n" "$log" > body.txt

# create the release
https --ignore-stdin --check-status -b -A bearer -a "$DEPLOY_TOKEN" POST \
      "https://codeberg.org/api/v1/repos/${CI_REPO_OWNER}/${CI_REPO_NAME}/releases" \
      tag_name="$version" name="Release $version" body=@body.txt > release.json

# we need the id to upload files
ID=$(jq -r .id < release.json)

if test -z "$ID"; then
    cat release.json
    die "failed to create release"
fi

# actually upload
for file in "$@"; do
    https --ignore-stdin --check-status -A bearer -a "$DEPLOY_TOKEN" -f POST \
          "https://codeberg.org/api/v1/repos/${CI_REPO_OWNER}/${CI_REPO_NAME}/releases/$ID/assets" \
          "name=${file}" "attachment@${file}"
done
