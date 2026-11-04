#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Serves website/public from busybox httpd inside LiteBox, through Docker and the LiteBox
# containerd shim; see README.md. ADDRESS (default 127.0.0.1) and PORT (default 18080) choose the
# host address the broker publishes the guest's port 80 on.
#
# Guests use the host's network through the broker, so the port is published with the shim's
# `io.litebox.publish.tcp` annotation rather than `-p`. httpd runs `*.sh` files with busybox `sh`,
# since the image has no bash.

set -euo pipefail

public=$(cd "$(dirname "$0")/public" && pwd)
address=${ADDRESS:-127.0.0.1}
port=${PORT:-18080}

docker rm -f litebox-site >/dev/null 2>&1 || true
docker run -d --name litebox-site --restart unless-stopped \
    --runtime io.containerd.litebox.v1 --network host \
    --annotation "io.litebox.publish.tcp=$address:$port:80" \
    -v "$public:/www" busybox sh -c \
    'echo "*.sh:/bin/sh" > /tmp/httpd.conf && exec httpd -f -p 80 -h /www -c /tmp/httpd.conf' \
    >/dev/null

url="http://$address:$port/"
for _ in $(seq 1 60); do
    if curl -sf --max-time 2 "$url" >/dev/null; then
        echo "LiteBox site: $url"
        exit 0
    fi
    sleep 0.5
done
echo "the site did not answer at $url; see \`docker logs litebox-site\`" >&2
exit 1
