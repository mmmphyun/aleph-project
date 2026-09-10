#!/usr/bin/env bash
# 실측 범위를 고정하고 실패를 호출자에게 전달한다. 자동 권한 상승은 하지 않는다.
set -euo pipefail

fail() { printf '%s\n' "$2" >&2; exit "$1"; }
[[ $# -ge 4 && $# -le 6 ]] || fail 2 '사용법: bash tcpdump_capture.sh <IPv4> <포트> <인터페이스> <출력.pcap> [초:10] [패킷:1000]'
target=$1 port=$2 interface=$3 output=$4 seconds=${5-10} count=${6-1000}
[[ $target =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail 2 'IPv4 형식 오류'
IFS=. read -r -a octets <<< "$target"
for octet in "${octets[@]}"; do
    [[ $octet == 0 || $octet != 0* ]] || fail 2 'IPv4 선행 0 금지'
    (( 10#$octet <= 255 )) || fail 2 'IPv4 옥텟 범위: 0~255'
done
[[ $port =~ ^[1-9][0-9]{0,4}$ ]] && (( port <= 65535 )) || fail 2 '포트 범위: 1~65535, 선행 0 금지'
[[ $interface =~ ^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}$ && $interface != any ]] || fail 2 '단일 인터페이스 이름: 영숫자로 시작하는 1~15자, any 금지'
[[ $seconds =~ ^[1-9][0-9]{0,2}$ ]] && (( seconds <= 120 )) || fail 2 '시간 범위: 1~120초, 선행 0 금지'
[[ $count =~ ^[1-9][0-9]{0,5}$ ]] && (( count <= 100000 )) || fail 2 '패킷 범위: 1~100000, 선행 0 금지'
[[ -n $output && $output == *.pcap && ! $output =~ [[:cntrl:]] ]] || fail 2 '출력은 제어문자 없는 .pcap 경로여야 합니다.'
[[ $output == /* ]] || output="$PWD/$output"
parent=${output%/*}
[[ -d $parent && -w $parent && -x $parent ]] || fail 2 '출력 부모 디렉토리가 없거나 쓰기/탐색 권한이 없습니다.'
[[ ! -e $output && ! -L $output ]] || fail 2 '기존 출력 파일 또는 심볼릭 링크는 사용할 수 없습니다.'
tcpdump_bin=$(type -P tcpdump) || fail 127 'tcpdump 실행 파일이 PATH에 없습니다.'
sleep_bin=$(type -P sleep) || fail 127 'sleep 실행 파일이 PATH에 없습니다.'
[[ -x $tcpdump_bin && -x $sleep_bin ]] || fail 126 '필수 명령어 실행 권한이 없습니다.'

# noclobber로 경합 시에도 기존 파일을 보호하고 열린 FD로만 기록한다.
# 소유한 신뢰 디렉토리를 요구한다. 빈 파일/부분 파일은 실패 시에도 진단용으로 남긴다.
umask 077
set -o noclobber
exec 3> "$output" || fail 2 '출력 파일을 안전하게 생성할 수 없습니다.'
set +o noclobber
child=''
requested=0
trap 'requested=130' INT
trap 'requested=143' TERM
cleanup() {
    local attempts=0
    if [[ -n $child ]]; then
        # SIGTERM은 tcpdump의 정상 버퍼 flush를 요청한다. 무응답은 2초 후 강제 종료한다.
        kill -TERM "$child" 2>/dev/null || true
        while kill -0 "$child" 2>/dev/null && (( attempts < 20 )); do
            "$sleep_bin" 0.1 || true
            attempts=$((attempts + 1))
        done
        if kill -0 "$child" 2>/dev/null; then
            printf '%s\n' '자식이 종료에 응답하지 않아 SIGKILL: 버퍼 기록 미보장' >&2
            kill -KILL "$child" 2>/dev/null || true
        fi
        wait "$child" 2>/dev/null || true
        child=''
    fi
    exec 3>&-
}
trap cleanup EXIT
# -U는 패킷 단위 기록, -w -는 예약한 FD를 사용하여 경로 재오픈/덮어쓰기를 막는다.
# DNS 조회와 promiscuous 모드를 끄며 필터는 문자열 평가 없이 별도 인자로 전달한다.
SECONDS=0
"$tcpdump_bin" -nn -p -U -i "$interface" -c "$count" -w - \
    ip and tcp and host "$target" and port "$port" >&3 3>&- &
child=$!
while kill -0 "$child" 2>/dev/null; do
    if (( requested != 0 )); then
        printf '사용자 중단: 종료 코드 %s\n' "$requested" >&2
        exit "$requested"
    fi
    if (( SECONDS >= seconds )); then
        printf '%s\n' '시간 제한 도달: 종료 코드 124' >&2
        exit 124
    fi
    if ! "$sleep_bin" 0.1; then
        (( requested == 0 )) || exit "$requested"
        fail 125 '감시용 sleep 실행 실패'
    fi
done
status=0
wait "$child" || status=$?
child=''
(( requested == 0 )) || exit "$requested"
if (( status != 0 )); then
    printf 'tcpdump 실행 실패: 종료 코드 %s (권한/인터페이스 등 stderr 확인)\n' "$status" >&2
else
    printf '%s\n' 'tcpdump 정상 종료' >&2
fi
exit "$status"
