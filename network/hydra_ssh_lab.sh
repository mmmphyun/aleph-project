#!/usr/bin/env bash
# 임의 호스트 인자를 받지 않는다. 소유권 검증과 수명 관리는 전용 Docker 러너가 담당한다.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
command -v python3 >/dev/null || { printf '%s\n' 'python3 필요' >&2; exit 127; }
exec python3 "$root/lab/hydra_lab.py" "$@"
