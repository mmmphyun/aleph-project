#!/usr/bin/env bash
# Why: Kali 실행 진입점을 고정해 다른 Python·PATH 설정으로 우회되는 것을 막는다.
# Constraints: Python 러너의 dry-run 기본값과 단일 실행 가드를 그대로 적용한다.
# Side-effects: run --execute는 실제 SSH 실패·TCP 탐침·패킷 캡처를 발생시킨다.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
command -v python3 >/dev/null || { printf '%s\n' 'python3 필요' >&2; exit 127; }
exec python3 "$root/ec2_hydra_measurement.py" "$@"
