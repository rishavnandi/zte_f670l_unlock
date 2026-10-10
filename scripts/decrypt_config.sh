#!/usr/bin/env bash
# Decrypt the ZTE ONT config and pull it to your machine over telnet.
#
# Run this BEFORE you change anything if you want to see what the ISP provisioned.
# Note that "decry" was removed in later firmware -- if it prints the command list
# back at you instead of producing a file, your firmware does not have it and this
# is a dead end rather than a syntax error.
#
# See GUIDE.md step 7.

set -euo pipefail

ROUTER_IP="${ROUTER_IP:-192.168.1.1}"
CFG="/userconfig/cfg/db_user_cfg.xml"
OUT="${OUT:-db_user_cfg.xml}"
LOCAL_IP="${LOCAL_IP:-$(ipconfig getifaddr en0 2>/dev/null || ip -4 addr show scope global | awk '/inet/{print $2}' | cut -d/ -f1 | head -1)}"

usage() {
    cat <<EOF
Usage: ${0##*/} [options]

  -i, --ip <addr>      ONT address (default: $ROUTER_IP)
  -l, --local <addr>   your LAN address, for the tftp pull (default: autodetect)
  -o, --out <file>     output filename (default: $OUT)
      --dump-only      run sendcmd, skip the tftp pull
      --sql            print the sendcmd query reference and exit
  -h, --help           show this help

env: ROUTER_IP, LOCAL_IP, OUT
EOF
}

sql_ref() {
    cat <<'EOF'
  sendcmd 1 DB decry /userconfig/cfg/db_user_cfg.xml   decrypt config -> /tmp/debug-decry-cfg
    sendcmd 1 DB all                     list all table names
    sendcmd 1 DB p <Table Name>          print one table
    sendcmd 1 DB set <T> <row> <F> <V>   modify a field
    sendcmd 1 DB save                    persist changes
    /etc/init.d/regioncode               current region settings

  Example -- change the super password:
    sendcmd 1 DB set UserInfo 0 Password <new_password>
EOF
}

while [[ $# -gt 0 ]]; do case "$1" in
    -i|--ip) ROUTER_IP="$2"; shift 2 ;;
    -l|--local) LOCAL_IP="$2"; shift 2 ;;
    -o|--out) OUT="$2"; shift 2 ;;
    --dump-only) DUMP_ONLY=1; shift ;;
    --sql) sql_ref; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
esac; done

[[ -n "${DUMP_ONLY:-}" ]] && { echo "Run in your telnet session:"; echo; sql_ref; exit 0; }

if [[ -z "$LOCAL_IP" ]]; then
    echo "could not detect your LAN address; pass -l <addr>" >&2
    exit 1
fi

command -v telnet >/dev/null 2>&1 || {
    cat >&2 <<'EOF'
note: no telnet client found. The commands below still apply -- run them from
      any telnet client, or use a serial console if you prefer.
        macOS:   brew install telnet   (or use a client from your terminal)
        Windows: Settings > Apps > Optional features > Telnet Client
        Linux:   apt install telnet  /  apt install inetutils-telnet

      telnet needs interactive input for the credentials from open_telnet.sh,
      so this script cannot log in for you. Run the commands below by hand.

EOF
}

cat <<EOF
Decrypting config on $ROUTER_IP and pulling it to $LOCAL_IP as $OUT

The decrypted file will land at /tmp/debug-decry-cfg on the ONT.
If your firmware has no "decry" command it will print the command list instead --
that means this firmware removed it.

Paste these into your telnet session:

  sendcmd 1 DB decry $CFG
  cd /tmp
  ls -l debug-decry-cfg

Then, with a tftp server listening on $LOCAL_IP:

  tftp -l $OUT -p $LOCAL_IP

EOF

if command -v tftp >/dev/null 2>&1; then
    echo "To serve it, run in another terminal:"
    echo "  cd $(dirname "$OUT") && tftp -l -a $LOCAL_IP -i $OUT"
else
    echo "NOTE: no tftp client found. Install one (brew install inetutils, apt install tftp),"
    echo "      or pull the file manually from the ONT."
fi

sql_ref