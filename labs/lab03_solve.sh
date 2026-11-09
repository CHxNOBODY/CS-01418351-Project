#!/usr/bin/env bash
# Lab 03 helper: run while connected to KU network/VPN with DNS = 158.108.16.155.
# Start Wireshark capture (filter: dns or http) BEFORE running each section.
NS=@158.108.16.155
sec(){ echo; echo "=================== $* ==================="; }

sec "Warm-up 1: dig test.network.lab ANY"
dig $NS test.network.lab ANY

sec "Flag 1: flag.network.lab (try every record type)"
for t in ANY TXT MX CNAME NS AAAA SRV; do echo "--- $t"; dig $NS +short flag.network.lab $t; done

sec "Flag 2: name server of network.lab"
dig $NS network.lab NS
dig $NS +short flag.network.lab NS

sec "Flag 3: follow the CNAME chain from cname.network.lab"
name=cname.network.lab
for i in $(seq 1 15); do
  next=$(dig $NS +short "$name" CNAME | head -1)
  echo "$name -> ${next:-<no CNAME>}"
  dig $NS +short "$name" TXT
  [ -z "$next" ] && break
  name=${next%.}
done

sec "Warm-up 2: HTTP versions (two objects each to show connection reuse)"
curl -sv -o /dev/null http://v10.network.lab/ -o /dev/null http://v10.network.lab/ 2>&1 | grep -E '^(< HTTP|\* (Connected|Re-using|Closing))'
curl -sv -o /dev/null http://v11.network.lab/ -o /dev/null http://v11.network.lab/ 2>&1 | grep -E '^(< HTTP|\* (Connected|Re-using|Closing))'

sec "Warm-up 3: conditional GET on cache.network.lab"
hdr=$(curl -sI http://cache.network.lab/)
echo "$hdr"
lm=$(echo "$hdr" | grep -i '^Last-Modified:' | cut -d' ' -f2- | tr -d '\r')
et=$(echo "$hdr" | grep -i '^ETag:' | cut -d' ' -f2- | tr -d '\r')
args=(); [ -n "$lm" ] && args+=(-H "If-Modified-Since: $lm"); [ -n "$et" ] && args+=(-H "If-None-Match: $et")
curl -si "${args[@]}" http://cache.network.lab/ | head -15

sec "Flag 4: GET /start (raw, do NOT follow redirect)"
resp=$(printf 'GET /start HTTP/1.1\r\nHost: v11.network.lab\r\nConnection: close\r\n\r\n' | nc v11.network.lab 80)
echo "$resp" | sed '/^\r\?$/q'
loc=$(echo "$resp" | grep -i '^Location:' | cut -d' ' -f2- | tr -d '\r')

sec "Flag 5: follow Location ($loc) and check every referenced object"
case "$loc" in http*) url=$loc;; *) url="http://v11.network.lab$loc";; esac
page=$(curl -s "$url"); echo "$page"
base="${url%/*}"
for obj in $(echo "$page" | grep -oiE '(src|href)="[^"]+"' | cut -d'"' -f2 | sort -u); do
  case "$obj" in http*) u=$obj;; /*) u="http://v11.network.lab$obj";; *) u="$base/$obj";; esac
  body=$(curl -si "$u")
  echo "--- $u : $(echo "$body" | head -1)"
  echo "$body" | grep -ao 'FLAG{[^}]*}'
done
