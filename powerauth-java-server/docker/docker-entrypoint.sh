#!/usr/bin/env bash
set -euo pipefail

exec java ${JAVA_OPTS:-} -cp "${APP_PATH}:${EXTLIB_PATH}/*" org.springframework.boot.loader.launch.WarLauncher