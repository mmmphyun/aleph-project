#!/usr/bin/env bash
# 기존 러너의 Docker 소유권 검증·시간 제한·private tmpfs 정리를 공유한다.
# 기본은 dry-run이며 운영 대상/계정/비밀번호 입력을 받지 않는다. 외부 명령 실패는 그대로 반환한다.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
command -v python3 >/dev/null || { printf '%s\n' 'python3 필요' >&2; exit 127; }
exec python3 "$root/lab/hydra_lab.py" "$@" --mode password-spraying
