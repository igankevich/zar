#!/bin/sh

. ./ci/preamble.sh

main() {
    set -e
    workdir="$(mktemp -d)"
    trap cleanup EXIT
    if test -z "$VERSION"; then
        printf "VERSION not set.\n" >&2
        exit 1
    fi
    if test -z "$ARCH"; then
        printf "ARCH not set.\n" >&2
        exit 1
    fi
    if test -z "$OS"; then
        printf "OS not set.\n" >&2
        exit 1
    fi
    root="$(pwd)"
    case "$OS-$ARCH" in
    Linux-x86_64) build_linux ;;
    Darwin-arm64) build_macos ;;
    *)
        printf "Unsupported OS/architecture combination: %s-%s\n" "$OS" "$ARCH" >&2
        exit 1
        ;;
    esac
}

build_linux() {
    target="$ARCH"-unknown-linux-musl
    cargo build \
        --quiet \
        --release \
        --target "$target" \
        --package zar-cli
    rm -rf --one-file-system release
    mkdir "$workdir"/linux
    cp -v target/"$target"/release/zar "$workdir"/linux
    cd "$workdir"/linux
    create_tar_archive
}

build_macos() {
    target=aarch64-apple-darwin
    cargo build \
        --quiet \
        --release \
        --target "$target" \
        --package zar-cli
    mkdir "$workdir"/macos
    cp -v target/"$target"/release/zar "$workdir"/macos
    cd "$workdir"/macos
    create_tar_archive
}

create_tar_archive() {
    find . -type f -print0 | sort --unique --zero-terminated >"$workdir"/files
    tar --create \
        --mtime=@0 \
        --numeric-owner \
        --owner=0 \
        --group=0 \
        --gzip \
        --verbose \
        --file="$root"/zar-"$OS"-"$ARCH"-"$VERSION".tar.gz \
        --null \
        --files-from="$workdir"/files
}

cleanup() {
    rm -rf "$workdir"
}

main "$@"
