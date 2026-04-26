#!/bin/bash


echo "Prescan - Updating scripts";
sudo nmap --script-updatedb;
echo "\nPhase 1 - Discovery";
LOCAL_INFO=$(ifconfig en13 | awk '/inet / {ip=$2} /ether / {mac=$2; print ip "  " toupper(mac) " (Local Machine)"}'); \
TARGETS=$(sudo nmap -sn 192.168.222.0/24 | \
awk '/Nmap scan report/{ip=$NF; gsub(/[()]/,"",ip); printf ip "  "} /MAC Address:/{print substr($0, index($0,$3))}' | \
{ echo "$LOCAL_INFO"; cat; } | sort -V); \
echo "$TARGETS" \
echo "\nPhase 2 - OS, services, reporting"; \
echo "$TARGETS" | awk '{print $1}' | grep -E '^[0-9.]+$' > targets.tmp; \
sudo nmap -sS -sV -sC -O -T4 --min-rate 3000 --script vulners --stylesheet nmap-modern.xsl -iL targets.tmp -oX phase2_results.xml; \ xsltproc -o phase2_results.html phase2_results.xml; open phase2_results.html;\
rm targets.tmp
