#!/bin/sh
# Bootstrap installer for the AWS Workload Credentials Provider on Linux.
#
#   sudo AWCP_VERSION=3.1.1 /bin/bash -c "$(curl --proto '=https' --tlsv1.2 -fsSL \
#     https://raw.githubusercontent.com/aws/aws-workload-credentials-provider/HEAD/install.sh)" \
#     -- --config /path/to/config.toml
#
# Downloads the release binary and the matching configuration directory, then
# runs the install script from it. Options other than --dry-run are passed
# through to that script.
#
# The version is explicit: the binary comes from the artifact host and the
# service units and install scripts come from the repository at tag v$AWCP_VERSION,
# so both halves are pinned to the same release.
#
# Environment:
#   AWCP_VERSION   Version to install, in the pattern x.y.z. Required.
#   AWCP_BASE_URL  Artifact host.
#   AWCP_REPO_URL  Repository the configuration directory is fetched from.
#
# Everything runs from main, called on the last line, so a download truncated
# mid-transfer can't execute a partial install.

set -eu

BASE_URL="${AWCP_BASE_URL:-https://artifacts.awcp.global.on.aws}"
REPO_URL="${AWCP_REPO_URL:-https://github.com/aws/aws-workload-credentials-provider}"
BIN=aws-workload-credentials-provider

die() {
    echo "install.sh: $*" >&2
    exit 1
}

fetch() {
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" -- "$1" ||
        die "download failed: $1"
}

main() {
    # `bash -c <script> [name [args...]]` assigns the first word after the
    # script to $0, so an operator who omits the `--` loses their first option
    # silently. Refuse rather than install something they didn't ask for.
    case "$0" in
        --) ;;
        -*) die "unexpected \$0 '$0': put -- before the options, as in 'sh -s -- --dry-run'" ;;
    esac

    [ "$(id -u)" -eq 0 ] || die "must run as root"
    [ "$(uname -s)" = Linux ] || die "unsupported OS: $(uname -s). On Windows, use install.ps1"

    case "$(uname -m)" in
        x86_64 | amd64) target=x86_64-unknown-linux-gnu ;;
        aarch64 | arm64) target=aarch64-unknown-linux-gnu ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac

    # Commands used here and by the install script this hands off to, so a host
    # missing one of them fails before anything is downloaded or created.
    for cmd in chgrp chmod chown curl grep groupadd id install mktemp \
        systemctl tar useradd; do
        command -v "$cmd" >/dev/null || die "required command not found: $cmd"
    done

    version="${AWCP_VERSION:-}"
    [ -n "$version" ] ||
        die "set AWCP_VERSION to the version to install, as in 'sudo AWCP_VERSION=3.1.1 ...'"
    echo "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
        die "not a valid version: $version"

    # `bash -c <script> -- <options>` consumes the -- as $0, but running the
    # file directly leaves it as the first argument, so drop it here to make
    # both invocations behave the same.
    if [ "${1:-}" = "--" ]; then
        shift
    fi

    # Strip --dry-run and leave the rest in "$@" for the install script.
    # Rotating through "$@" keeps arguments containing spaces intact.
    dry_run=false
    remaining=$#
    while [ "$remaining" -gt 0 ]; do
        arg=$1
        shift
        if [ "$arg" = --dry-run ]; then
            dry_run=true
        else
            set -- "$@" "$arg"
        fi
        remaining=$((remaining - 1))
    done

    # /var/tmp rather than /tmp, and TMPDIR deliberately ignored: the install
    # script execs the binary from here for its pre-flight checks, and hardened
    # hosts commonly mount /tmp noexec.
    tmp=$(mktemp -d /var/tmp/awcp-install.XXXXXX)
    trap 'rm -rf "$tmp"' EXIT
    # A signal handler returns to the next command, so these have to exit
    # themselves or the script would carry on with its work directory deleted.
    trap 'rm -rf "$tmp"; exit 130' HUP INT TERM
    mkdir "$tmp/repo"

    echo "Installing $BIN $version ($target)"

    # The tag is what ties the units and scripts to the release. A missing tag
    # means the version was published without being tagged. Fetched before the
    # binary so a bad version fails on 200 KB rather than tens of megabytes.
    archive="$REPO_URL/archive/refs/tags/v$version.tar.gz"
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp/repo.tar.gz" -- "$archive" ||
        die "cannot fetch $archive; is v$version tagged?"
    tar --no-same-owner -xzf "$tmp/repo.tar.gz" -C "$tmp/repo"
    # GitHub names the archive's top directory after the repository and tag, so
    # a glob finds it without depending on find(1) being installed.
    configuration=""
    for candidate in "$tmp"/repo/*/aws_workload_credentials_provider_common/configuration; do
        if [ -f "$candidate/install" ]; then
            configuration=$candidate
            break
        fi
    done
    [ -n "$configuration" ] || die "no configuration directory in $archive"

    # The install script installs the binary itself, from ../../target/release
    # relative to its own location, which is where a source build leaves it. So
    # download straight there and let it do the rest: it owns the destination,
    # its ownership, and the order things are created in. Downloaded after the
    # archive is extracted, so no archive member can stand in for the binary.
    source_dir="$configuration/../../target/release"
    mkdir -p "$source_dir"
    fetch "$BASE_URL/$version/$target/$BIN" "$source_dir/$BIN"
    chmod 755 "$source_dir/$BIN"

    if [ "$dry_run" = true ]; then
        echo "Downloaded $BIN $version and the v$version configuration. Install skipped (--dry-run)."
        return 0
    fi

    # Run through bash rather than exec'ing the file, so a noexec staging
    # directory doesn't block the install. -e is explicit because `bash <file>`
    # drops the shebang's flags, and releases up to 3.1.1 take errexit from the
    # shebang alone: without it their installer runs past a rejected config and
    # reports success.
    bash -e "$configuration/install" "$@"
}

main "$@"
