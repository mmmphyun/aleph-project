#!/usr/bin/env bash
# Debian tcpdump가 장치를 연 뒤 전용 tcpdump UID/GID로 권한을 낮추게 한다.
# NET_RAW는 장치 열기에, SETUID/SETGID는 기본 권한 강하에만 사용한다.
set -euo pipefail
exec /usr/bin/tcpdump "$@"
