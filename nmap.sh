#!/bin/bash
set -euo pipefail

echo "Prescan - Updating scripts"
sudo nmap --script-updatedb

echo "Phase 1 - Discovery"
PRIMARY_ROUTE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')
if [[ -z "${PRIMARY_ROUTE:-}" ]]; then
  PRIMARY_ROUTE=$(networksetup -listallhardwareports 2>/dev/null | awk '/Device:/{print $2; exit}')
fi

LOCAL_INFO=$(ifconfig "${PRIMARY_ROUTE:-en0}" 2>/dev/null | awk '
  /inet / { ip=$2 }
  /ether / { mac=toupper($2) }
  END {
    if (ip != "" && mac != "") {
      print ip "  " mac " (Local Machine)"
    }
  }
')

TARGETS=$(
  sudo nmap -sn 192.168.222.0/24 |
  awk '
    /Nmap scan report/ {
      ip=$NF
      gsub(/[()]/, "", ip)
      printf "%s  ", ip
    }
    /MAC Address:/ {
      print substr($0, index($0, $3))
    }
  ' |
  {
    if [[ -n "${LOCAL_INFO:-}" ]]; then
      echo "$LOCAL_INFO"
    fi
    cat
  } | sort -V
)

echo "$TARGETS"

echo "Phase 2 - OS, services, reporting"
printf '%s\n' "$TARGETS" | awk '{print $1}' | grep -E '^[0-9.]+$' > targets.tmp
sudo nmap -sS -sV -sC -O -T4 --min-rate 3000 --script vulners --stylesheet nmap-modern.xsl -iL targets.tmp -oX phase2_results.xml
xsltproc -o phase2_results.html phase2_results.xml
open phase2_results.html
rm -f targets.tmp
