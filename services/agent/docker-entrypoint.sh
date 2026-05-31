#!/bin/sh
set -e

mkdir -p /var/run /var/log

# Run in foreground — Docker manages the process lifecycle.
# Logs go to stdout and are visible via `docker logs`.
exec nids-collector "$@"
