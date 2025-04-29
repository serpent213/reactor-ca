#!/usr/bin/env bash

if [ $# -lt 1 ]; then
  echo "Usage: $0 <url> [num_requests]"
  exit 1
fi

url=$1
count=${2:-7}  # Default to 7 if not provided
total=0

echo "Target: $url"

for ((i=1; i<=count; i++)); do
  echo -n "Request $i of $count: "
  time_sec=$(curl -s -o /dev/null -w "%{time_appconnect}\n" --head "$url")
  time_ms=$(echo "$time_sec * 1000" | bc)
  echo "${time_ms%.*} ms"
  total=$(echo "$total + ${time_ms%.*}" | bc)
done

avg=$(echo "scale=2; $total / $count" | bc)
echo "Average TLS handshake time: $avg ms"
