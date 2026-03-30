#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <url>"
  exit 1
fi

URL="$1"

if [[ ! "$URL" =~ ^https?:// ]]; then
  echo "[!] URL should start with http:// or https://"
  exit 1
fi

HOST="$(echo "$URL" | sed -E 's#https?://([^/:]+).*#\1#')"

echo "== KOROLI Net Audit =="
echo "Target URL: $URL"
echo "Host: $HOST"
echo

echo "[1] HTTP reachability + status"
curl -sS -o /dev/null -w "HTTP status: %{http_code}\nTotal time: %{time_total}s\nRemote IP: %{remote_ip}\n" "$URL"
echo

echo "[2] Response headers"
curl -sSI --max-time 15 "$URL" || true
echo

if command -v openssl >/dev/null 2>&1; then
  echo "[3] TLS certificate quick view"
  echo | openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null | openssl x509 -noout -issuer -subject -dates || true
  echo
fi

if command -v nmap >/dev/null 2>&1; then
  echo "[4] nmap SSL scripts (only run on assets you own/are authorized to test)"
  nmap -Pn -p 443 --script ssl-cert,ssl-enum-ciphers "$HOST" || true
  echo
else
  echo "[4] nmap not installed (optional)"
fi

if command -v nuclei >/dev/null 2>&1; then
  echo "[5] nuclei quick web scan (optional templates required)"
  nuclei -u "$URL" -severity medium,high,critical || true
  echo
else
  echo "[5] nuclei not installed (optional)"
fi

echo "Audit complete. Cross-check results before trusting any site/API."
