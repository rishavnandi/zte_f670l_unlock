#!/usr/bin/env bash
# Fetch stich86/zteOnu v0.0.7 and open telnet on a ZTE ONU.
#
# Telnet is disabled in current ZTE ONU firmware. zteOnu exploits factory mode to
# enable it and prints temporary credentials. Those credentials rotate on every
# router reboot, so re-run this whenever you need access.
#
# See GUIDE.md step 2.

set -euo pipefail

VERSION="0.0.7"
REPO="stich86/zteOnu"
ROUTER_IP="${ROUTER_IP:-192.168.1.1}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/zteOnu}"

usage() {
    cat <<EOF
Usage: ${0##*/} [options]

  -i, --ip <addr>      ONT address (default: $ROUTER_IP)
  -u, --user <str>     web UI / factory mode username
                       Use this if the built-in credential list fails --
                       Airtel locks the factory account ~1 month after activation.
  -p, --pass <str>     web UI / factory mode password
      --seclvl <1-3>   telnet security level; use 3 if you get "Permission Denied"
      --permanent      enable permanent telnet (root / Zte521) instead of
                       temporary credentials. Widens LAN attack surface.
      --with-mac       use the --new method, which requires your adapter to have
                       MAC 00:07:29:55:35:57 (wired on Windows, any adapter on Linux)
      --install        download zteOnu, then exit
  -h, --help           show this help

env: ROUTER_IP, INSTALL_DIR, VERSION
EOF
}

need_args() { while [[ $# -gt 0 ]]; do case "$1" in
    -i|--ip) ROUTER_IP="$2"; shift 2 ;;
    -u|--user) USER="$2"; shift 2 ;;
    -p|--pass) PASS="$2"; shift 2 ;;
    --seclvl) SECLVL="$2"; shift 2 ;;
    --permanent) PERMANENT=1; shift ;;
    --with-mac) NEWMAC=1; shift ;;
    --install) INSTALL_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
esac; done; }

detect_asset() {
    local os arch
    case "$(uname -s)" in
        Linux)  os=linux ;;
        Darwin) os=darwin ;;
        *) echo "unsupported OS: $(uname -s)" >&2; return 1 ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64)  arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        i386|i686)     arch=386 ;;
        *) echo "unsupported arch: $(uname -m)" >&2; return 1 ;;
    esac
    echo "zteOnu_${VERSION}_${os}_${arch}.tar.gz"
}

install_zteonu() {
    local asset url tmp
    if [[ -x "$INSTALL_DIR/zteOnu" ]]; then
        echo "zteOnu already present at $INSTALL_DIR/zteOnu"
        return 0
    fi
    asset="$(detect_asset)" || return 1
    url="https://github.com/$REPO/releases/download/v$VERSION/$asset"
    tmp="$(mktemp -d)"
    echo "Downloading $asset"
    if ! curl -fsSL "$url" -o "$tmp/zteonu.tar.gz"; then
        echo "download failed: $url" >&2
        rm -rf "$tmp"
        return 1
    fi
    mkdir -p "$INSTALL_DIR"
    tar xzf "$tmp/zteonu.tar.gz" -C "$INSTALL_DIR"
    chmod +x "$INSTALL_DIR"/zteOnu*
    rm -rf "$tmp"
    echo "Installed to $INSTALL_DIR"
}

main() {
    need_args "$@"

    if [[ -n "${INSTALL_ONLY:-}" ]]; then install_zteonu; return $?; fi

    command -v zteOnu >/dev/null 2>&1 || {
        echo "zteOnu not on PATH. Fetching it..." >&2
        install_zteonu || return 1
    }
    local bin; bin="$(command -v zteOnu)"

    local args=(-i "$ROUTER_IP")
    [[ -n "${USER:-}"   ]] && args+=(-u "$USER")
    [[ -n "${PASS:-}"   ]] && args+=(-p "$PASS")
    [[ -n "${SECLVL:-}" ]] && args+=(--seclvl "$SECLVL")
    [[ -n "${PERMANENT:-}" ]] && args+=(--telnet)
    [[ -n "${NEWMAC:-}" ]]    && args+=(--new)

    cat <<EOF

  ONT      $ROUTER_IP
  Method   $([[ -n "${NEWMAC:-}" ]] && echo "--new (needs MAC 00:07:29:55:35:57)" || echo "default")
  Creds    $([[ -n "${USER:-}" ]] && echo "supplied" || echo "built-in list (pass -u/-p if this fails)")

EOF
    echo "Running: zteOnu ${args[*]}"
    echo
    "$bin" "${args[@]}" || {
        cat >&2 <<'EOF'

  If this retried and failed:
    - pass your real web UI credentials:  -u <user> -p <pass>
    - try the MAC method:                 --with-mac
    - "step [2] send sq: unknown error" means the firmware is patched. See README.md.

EOF
        return 1
    }

    cat <<'EOF'

  Telnet credentials are printed above.
    username = between "=" and "&"
    password = after "=", without the trailing "\"

  They rotate on every reboot -- re-run this script after each one.

EOF
}

main "$@"