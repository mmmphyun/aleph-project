#!/usr/bin/env bash
# Debian의 기본 권한 강하를 끈다. NET_RAW만 가진 캡처 프로세스에
# SETUID/SETGID를 추가하지 않기 위한 로컬 실험 전용 어댑터다.
set -euo pipefail
exec /usr/bin/tcpdump -Z root "$@"
