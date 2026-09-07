#!/usr/bin/env bash
# CloudShield 네트워크 공격 시뮬레이션 스크립트
# 소유자: 네트워크 담당
#
# Why:
#   외부 공격자 관점에서 타깃 EC2 인스턴스를 대상으로 실제 위협 트래픽
#   (SSH Brute Force, Port Scanning)을 유발하고, 패킷 덤프(tcpdump) 및
#   CloudWatch Logs 적재를 검증하기 위한 안전한 모의 공격 재현 환경 제공.
#
# Constraints:
#   - 본 스크립트는 반드시 사전에 승인된 테스트베드 VPC 타깃 IP에 대해서만 실행해야 함.
#   - bash 셸 환경에서 비정상 종료 및 오류 파급 방지를 위해 엄격 모드(set -euo pipefail) 필수 적용.
#
# Side-effects / Edge-cases:
#   - Hydra 및 Nmap 도구가 시스템에 설치되어 있어야 정상 실행 가능.
#   - 잘못된 타깃 IP 입력 시 원치 않는 시스템에 트래픽이 유입될 위험 차단.

set -euo pipefail

# ==========================================
# 매개변수 유효성 검증
# ==========================================
TARGET_IP="${1:-}"
TARGET_PORT="${2:-22}"

if [[ -z "${TARGET_IP}" ]]; then
    echo "사용법: $0 <타깃_IPv4_주소> [타깃_포트(기본값: 22)]" >&2
    echo "예시:   $0 198.51.100.50 22" >&2
    exit 1
fi

# IPv4 정규식 패턴 검증
IP_REGEX="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
if [[ ! "${TARGET_IP}" =~ ${IP_REGEX} ]]; then
    echo "[오류] 유효하지 않은 IPv4 주소 형식입니다: ${TARGET_IP}" >&2
    exit 1
fi

echo "=================================================="
echo " CloudShield 공격 시뮬레이션 안내 (네트워크 담당)"
echo " 타깃 호스트 : ${TARGET_IP}:${TARGET_PORT}"
echo "=================================================="
echo ""
echo "[1] 패킷 덤프 사전 실행 안내 (별도 터미널 또는 타깃 서버):"
echo "    sudo tcpdump -i any port ${TARGET_PORT} -w /tmp/attack_simulation.pcap -c 1000"
echo ""
echo "[2] SSH 무차별 대입 공격 (Hydra) 실행 명령어 스켈레톤:"
echo "    hydra -l admin -P wordlist.txt -t 4 -V ${TARGET_IP} ssh -s ${TARGET_PORT}"
echo ""
echo "[3] L4 SYN 스텔스 포트 스캔 (Nmap) 실행 명령어 스켈레톤:"
echo "    nmap -sS -p 20-100 ${TARGET_IP}"
echo ""
echo "[알림] 네트워크 담당자는 상기 명령어를 환경에 맞게 구체화하여 공격을 재현하세요."
exit 0
