#!/usr/bin/env bash
set -euo pipefail
umask 077

version="${1:-}"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo 'Usage: sudo bash install.sh vX.Y.Z (an exact published version is required)' >&2
  exit 2
fi
[[ "$(uname -s)" == Linux ]] || { echo 'This installer supports Linux.' >&2; exit 2; }
[[ "$(id -u)" == 0 ]] || { echo 'Install requires root to create the service account and systemd unit.' >&2; exit 2; }
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported architecture.' >&2; exit 2;; esac
for program in curl sha256sum tar install systemctl; do command -v "$program" >/dev/null || { echo "Missing $program" >&2; exit 2; }; done
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
asset="aswired-server_${version}_linux_${arch}.tar.gz"
base="https://github.com/AyanamiReiChan/ASWired-Release/releases/download/${version}"
if ! curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$base/SHA256SUMS" -o "$temporary/SHA256SUMS"; then
  echo 'Release unavailable. It may not be published or may still be private. Nothing was installed.' >&2
  exit 1
fi
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$base/$asset" -o "$temporary/$asset"
expected=$(awk -v file="$asset" '$2 == file {print $1}' "$temporary/SHA256SUMS")
[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || { echo 'Missing or ambiguous SHA256 checksum.' >&2; exit 1; }
actual=$(sha256sum "$temporary/$asset"); actual="${actual%% *}"
[[ "${expected,,}" == "$actual" ]] || { echo 'Checksum mismatch. Nothing was installed.' >&2; exit 1; }
tar --extract --gzip --file "$temporary/$asset" --directory "$temporary" --no-same-owner --no-same-permissions -- aswired-server
[[ -f "$temporary/aswired-server" && ! -L "$temporary/aswired-server" ]] || { echo 'Archive executable is invalid.' >&2; exit 1; }
id aswired >/dev/null 2>&1 || useradd --system --home-dir /var/lib/aswired --shell /usr/sbin/nologin aswired
install -d -o aswired -g aswired -m 0700 /var/lib/aswired
install -d -m 0750 /etc/aswired
install -m 0755 "$temporary/aswired-server" /usr/local/bin/.aswired-server-new
mv -f /usr/local/bin/.aswired-server-new /usr/local/bin/aswired-server
if [[ ! -e /etc/aswired/server.env ]]; then
  printf '%s\n' 'ASWIRED_LISTEN=127.0.0.1:12889' 'ASWIRED_PUBLIC_URL=http://127.0.0.1:12889' > /etc/aswired/server.env
  chmod 0600 /etc/aswired/server.env
fi
cat > /etc/systemd/system/aswired-server.service <<'UNIT'
[Unit]
Description=ASWired controller
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=aswired
Group=aswired
StateDirectory=aswired
StateDirectoryMode=0700
WorkingDirectory=/var/lib/aswired
EnvironmentFile=-/etc/aswired/server.env
Environment=ASWIRED_DATA_DIR=/var/lib/aswired
ExecStart=/usr/local/bin/aswired-server serve
Restart=on-failure
RestartSec=5
TimeoutStopSec=240
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/aswired
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now aswired-server
systemctl restart aswired-server
echo "Installed $version. Listening on localhost by default."
echo 'Initial setup token: /var/lib/aswired/setup-token (read locally as root).'
echo 'Existing data, keys and /etc/aswired/server.env were preserved.'
