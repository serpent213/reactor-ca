#!/usr/bin/env bash

if [ $# -lt 1 ]; then
  echo "Usage: $0 <url> [num_requests]"
  exit 1
fi

url=$1
count=${2:-7}  # Default to 7 if not provided
total=0

echo "Target: $url"

for ((i=0; i<=count; i++)); do
  if [ $i -eq 0 ]; then
    echo -n "Warm up request: "
  else
    echo -n "Request $i of $count: "
  fi
  time_sec=$(curl -s -o /dev/null -w "%{time_appconnect}\n" --head "$url")
  time_ms=$(echo "$time_sec * 1000" | bc)
  echo "${time_ms%.*} ms"
  if [ $i -gt 0 ]; then
    total=$(echo "$total + ${time_ms%.*}" | bc)
  fi
done

avg=$(echo "scale=1; $total / $count" | bc)
echo "Average TLS handshake time: $avg ms"
