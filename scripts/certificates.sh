#!/usr/bin/env bash
set -euo pipefail
umask 027
cd /usr/share/elasticsearch
if [ ! -f /private/ca/ca.key ]; then
  bin/elasticsearch-certutil ca --silent --pem --out /private/ca.zip --days 3650
  unzip -q /private/ca.zip -d /private
  rm /private/ca.zip
fi
mkdir -p /certs/ca
cp /private/ca/ca.crt /certs/ca/ca.crt
for service in elasticsearch kibana; do
  if [ ! -f "/certs/$service/$service.crt" ]; then
    bin/elasticsearch-certutil cert --silent --pem --name "$service" \
      --dns "$service,localhost" --ip 127.0.0.1 --days 825 \
      --ca-cert /private/ca/ca.crt --ca-key /private/ca/ca.key --out "/certs/$service.zip"
    unzip -q "/certs/$service.zip" -d /certs
    rm "/certs/$service.zip"
  fi
done
find /certs -type d -exec chmod 750 {} \;
find /certs -type f -exec chmod 640 {} \;
echo 'Lab certificates ready; private CA key stays in its own volume.'
