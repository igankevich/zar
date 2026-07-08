#!/bin/sh
set -e
version="$(sed -rne 's/^version = "(.*)"$/\1/p' Cargo.toml)"
if test -z "$version"; then
    printf "Version not found\n" >&2
    exit 1
fi
{
    printf "VERSION=%s\n" "$version"
    printf "OS=%s\n" "$(uname -s)"
    printf "ARCH=%s\n" "$(uname -m)"
} >>"$GITHUB_ENV"
