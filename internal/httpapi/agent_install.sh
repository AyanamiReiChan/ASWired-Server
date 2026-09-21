#!/bin/sh
set -eu
umask 077
die() { printf '%s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die 'Run this command as root.'
[ "$(uname -s)" = Linux ] || die 'Only Linux is supported.'
[ -d /run/systemd/system ] || die 'A running systemd installation is required.'
for tool in curl sha256sum base64 install systemctl mktemp flock; do
  command -v "$tool" >/dev/null 2>&1 || die "Missing prerequisite: $tool"
done
exec 9>/run/aswired-agent-install.lock
flock -n 9 || die 'Another Agent installation is running.'
case "$(uname -m)" in
  x86_64|amd64) arch=amd64; checksum=@@AMD64@@ ;;
  aarch64|arm64) arch=arm64; checksum=@@ARM64@@ ;;
  *) die 'Only amd64 and arm64 are supported.' ;;
esac
[ -n "$checksum" ] || die "The controller has no verified package for $arch."
# This entry point is for new installations. Existing installations use the
# versioned maintenance workflow so their data/configuration cannot be replaced.
for path in /usr/local/bin/aswired-agent /etc/aswired-agent /var/lib/aswired-agent /etc/systemd/system/aswired-agent.service; do
  [ ! -e "$path" ] && [ ! -L "$path" ] || die "Existing installation at $path; refusing to overwrite."
done
[ "$(systemctl show -p LoadState --value aswired-agent.service 2>/dev/null || true)" = not-found ] || die 'An Agent service already exists.'
work=$(mktemp -d)
created=0
complete=0
cleanup() {
  status=$?
  if [ "$created" = 1 ] && [ "$complete" = 0 ]; then
    systemctl disable --now aswired-agent.service >/dev/null 2>&1 || true
    rm -f /usr/local/bin/aswired-agent /etc/systemd/system/aswired-agent.service
    rm -rf /etc/aswired-agent /var/lib/aswired-agent
    systemctl daemon-reload || true
    printf '%s\n' 'Installation failed; the new installation was rolled back.' >&2
  fi
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
base=@@BASE@@
ticket=@@TICKET@@
curl -fSsL --proto '=http,https' --proto-redir '=https' "$base/linux-$arch?ticket=$ticket" -o "$work/aswired-agent"
printf '%s  %s\n' "$checksum" "$work/aswired-agent" | sha256sum -c -
printf '%s' '@@CONFIG@@' | base64 -d > "$work/agent.json"
chmod 700 "$work/aswired-agent"
"$work/aswired-agent" -config "$work/agent.json" -check
cat > "$work/aswired-agent.service" <<'UNIT'
[Unit]
Description=ASWired Agent with embedded Xray
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/aswired-agent -supervise -config /etc/aswired-agent/agent.json
WorkingDirectory=/var/lib/aswired-agent
Restart=on-failure
RestartSec=5
UMask=0077
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
UNIT
created=1
install -d -m 700 /etc/aswired-agent /var/lib/aswired-agent
install -m 755 "$work/aswired-agent" /usr/local/bin/aswired-agent
install -m 600 "$work/agent.json" /etc/aswired-agent/agent.json
install -m 644 "$work/aswired-agent.service" /etc/systemd/system/aswired-agent.service
systemctl daemon-reload
systemctl enable --now aswired-agent.service
sleep 2
systemctl is-active --quiet aswired-agent.service || die 'Agent failed to start. Inspect: journalctl -u aswired-agent -n 50'
complete=1
printf '%s\n' 'Agent service started. Return to the controller to confirm that it is online.'
