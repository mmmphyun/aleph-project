#!/usr/bin/env bash
# 단일 연결의 실패를 호출자에게 전달하기 위해 엄격 모드와 exec를 사용한다.
set -euo pipefail

fail() {
    printf '%s\n' "$1" >&2
    exit 2
}

# 기존 네트워크 스크립트와 동일하게 IPv4만 받는다. DNS 조회 및 옵션 주입을 배제한다.
[[ $# -ge 2 && $# -le 4 ]] || fail '사용법: bash ssh_single_connect.sh <IPv4> <사용자> [포트:22] [연결제한초:5]'
target=$1
user=$2
port=${3-22}
timeout=${4-5}
[[ $target =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail 'IPv4 형식이 잘못되었습니다.'
IFS=. read -r -a octets <<< "$target"
for octet in "${octets[@]}"; do
    [[ $octet == 0 || $octet != 0* ]] || fail 'IPv4 옥텟의 선행 0은 허용하지 않습니다.'
    (( 10#$octet <= 255 )) || fail 'IPv4 옥텟은 0~255여야 합니다.'
done
[[ $user =~ ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$ ]] || fail '사용자는 영문/밑줄로 시작하는 영숫자/밑줄/하이픈 1~32자여야 합니다.'
[[ $port =~ ^[1-9][0-9]{0,4}$ ]] || fail '포트는 선행 0 없는 정수여야 합니다.'
(( port <= 65535 )) || fail '포트 범위는 1~65535입니다.'
[[ $timeout =~ ^[1-9][0-9]{0,2}$ ]] || fail '연결 제한은 초 단위 정수여야 합니다.'
(( timeout <= 120 )) || fail '연결 제한 범위는 1~120초입니다.'

# 개인 SSH 설정의 ProxyCommand/다중 연결 재사용을 배제하고 기존 known_hosts만 신뢰한다.
# BatchMode는 비밀번호 입력을 막으며, 인증 성공 시 원격 true만 실행하고 종료한다.
# ConnectTimeout은 연결/초기 핸드셰이크 제한이며 전체 실행 시간 제한은 아니다.
# 실제 실행은 네트워크 및 서버 인증 로그를 발생시킨다. SSH 종료 코드(오류:255)를 보존한다.
exec ssh -F /dev/null -T -n \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o ConnectionAttempts=1 \
    -o "ConnectTimeout=$timeout" \
    -o NumberOfPasswordPrompts=0 \
    -o ClearAllForwardings=yes \
    -p "$port" -l "$user" "$target" true
