#!/bin/sh

. ./ci/preamble.sh

cargo_publish() {
    version="$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[0].version')"
    sed -i -e 's/^zar =.*version.*$/zar = { path = ".", version = "'"$version"'" }/' Cargo.toml
    for package in zar zar-cli; do
        cargo publish --quiet --package "$package" --allow-dirty
    done
}

if test "$GITHUB_ACTIONS" = "true" && test "$GITHUB_REF_TYPE" != "tag"; then
    exit 0
fi
cargo_publish
