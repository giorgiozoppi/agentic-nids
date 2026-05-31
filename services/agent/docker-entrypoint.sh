#!/bin/sh
set -e

# Create runtime directories in case the image is run with a read-only rootfs
# that mounts /var/run and /var/log as tmpfs volumes.
mkdir -p /var/run /var/log

# Start the collector as a Unix daemon (double-fork).
# All extra arguments passed to this entrypoint are forwarded (e.g. --interface).
nids-collector --daemon "$@"

# Keep the container alive and make log output visible to `docker logs`.
exec tail -f /var/log/nids-collector.log
