#!/usr/bin/env bash
# ==============================================================================
# CloudShield: 타깃 EC2 리눅스 환경 초기화 스크립트 (init_target_server.sh)
# 소유자: 클라우드 B (타깃 환경 구성 및 로깅 파이프라인 전담)
#
# Why:
#   1. 모의 침해 공격(Hydra SSH Brute Force / L7 Web Scanning)을 수용할 수 있는
#      타깃 리눅스(Ubuntu) 환경을 표준화된 방식으로 자동 프로비저닝함.
#   2. CloudWatch Agent가 즉각 수집할 수 있도록 /var/log/auth.log 및
#      /var/log/nginx/access.log 파일 생성, 권한 및 로깅 레벨을 일괄 보장함.
#
# Constraints:
#   - 타깃 OS: Ubuntu 22.04 / 24.04 LTS (x86_64 / arm64)
#   - 루트 권한(sudo / root)으로 실행 필수.
#   - 안전성 플래그(set -euo pipefail) 적용.
# ==============================================================================

set -euo pipefail

# 1. 색상 및 출력 헬퍼 함수 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

# 2. 실행 권한(Root) 확인
if [[ "${EUID}" -ne 0 ]]; then
    log_error "본 스크립트는 루트 권한(sudo)으로 실행해야 합니다."
    exit 1
fi

log_info "============================================================"
log_info "CloudShield: 타깃 EC2 리눅스 환경 초기화를 시작합니다."
log_info "============================================================"

# 3. 환경 변수 설정 및 패키지 업데이트
export DEBIAN_FRONTEND=noninteractive

log_info "APT 패키지 저장소 갱신 및 필수 패키지 설치 중..."
apt-get update -y
apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    lsb-release \
    nginx \
    openssh-server \
    openssl \
    rsyslog \
    ufw \
    net-tools \
    procps

log_success "필수 패키지(nginx, openssh-server, openssl, rsyslog 등) 설치 완료"

# 4. SSH 데몬 설정 (인증 실패 로그 생성 보장)
# Why:
#   OpenSSH(sshd_config)는 '먼저 평가된 설정값(First Match Wins)'을 채택하므로,
#   cloud-init 설정(50-cloud-init.conf)보다 사전 로드되도록 00-cloudshield.conf로 배치함.
#   기존 패키지/cloud-init 관리 파일은 직접 수정하지 않으며, sshd_config 최상단 Include를 보장하고
#   sshd -T로 런타임 실측 결과를 검증함 (실패 시 변경 전 drop-in 및 메인 설정 완전 자동 복구).
log_info "OpenSSH 데몬 설정 최적화 및 우선순위 조정 중..."

SSHD_MAIN_CONF="/etc/ssh/sshd_config"
SSHD_MAIN_BAK="/etc/ssh/sshd_config.bak.cloudshield"
SSHD_DIR="/etc/ssh/sshd_config.d"
SSHD_CUSTOM_CONF="${SSHD_DIR}/00-cloudshield.conf"
SSHD_CUSTOM_BAK="${SSHD_DIR}/00-cloudshield.conf.bak.cloudshield"
SSHD_LEGACY_CONF="${SSHD_DIR}/99-cloudshield.conf"
SSHD_LEGACY_BAK="${SSHD_DIR}/99-cloudshield.conf.bak.cloudshield"

mkdir -p "${SSHD_DIR}"

# 실행 전 기존 파일 상태 백업 (재실행 실패 시 완전한 원상복구를 위해)
HAD_MAIN=false
HAD_CUSTOM=false
HAD_LEGACY=false

if [[ -f "${SSHD_MAIN_CONF}" ]]; then
    cp "${SSHD_MAIN_CONF}" "${SSHD_MAIN_BAK}"
    HAD_MAIN=true
fi

if [[ -f "${SSHD_CUSTOM_CONF}" ]]; then
    cp "${SSHD_CUSTOM_CONF}" "${SSHD_CUSTOM_BAK}"
    HAD_CUSTOM=true
fi

if [[ -f "${SSHD_LEGACY_CONF}" ]]; then
    cp "${SSHD_LEGACY_CONF}" "${SSHD_LEGACY_BAK}"
    HAD_LEGACY=true
    rm -f "${SSHD_LEGACY_CONF}"
fi

rollback_sshd() {
    log_error "SSH 설정 검증 실패! 실행 전 상태로 완전 복원(Rollback)합니다."
    if [[ "${HAD_MAIN}" == true && -f "${SSHD_MAIN_BAK}" ]]; then
        cp "${SSHD_MAIN_BAK}" "${SSHD_MAIN_CONF}"
        rm -f "${SSHD_MAIN_BAK}"
    fi

    if [[ "${HAD_CUSTOM}" == true && -f "${SSHD_CUSTOM_BAK}" ]]; then
        cp "${SSHD_CUSTOM_BAK}" "${SSHD_CUSTOM_CONF}"
        rm -f "${SSHD_CUSTOM_BAK}"
    else
        rm -f "${SSHD_CUSTOM_CONF}"
        rm -f "${SSHD_CUSTOM_BAK}"
    fi

    if [[ "${HAD_LEGACY}" == true && -f "${SSHD_LEGACY_BAK}" ]]; then
        cp "${SSHD_LEGACY_BAK}" "${SSHD_LEGACY_CONF}"
        rm -f "${SSHD_LEGACY_BAK}"
    fi
}

cleanup_sshd_backups() {
    rm -f "${SSHD_MAIN_BAK}" "${SSHD_CUSTOM_BAK}" "${SSHD_LEGACY_BAK}"
}

# sshd_config 최상단에 Include 구문 보장 (00-*.conf가 다른 모든 설정보다 최우선 로드되도록 정렬)
if [[ -f "${SSHD_MAIN_CONF}" ]]; then
    # 기존 위치와 관계없이 중복 Include 지침 정리 후 최상단(1라인)에 배치
    sed -i '/^\s*Include\s\+\/etc\/ssh\/sshd_config\.d\/\*\.conf/d' "${SSHD_MAIN_CONF}"
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "${SSHD_MAIN_CONF}"
fi

# CloudShield 전용 00-cloudshield.conf 최우선 순위 설정 파일 생성
cat << 'EOF' > "${SSHD_CUSTOM_CONF}"
# CloudShield 타깃 서버 SSH 침해 실증용 최우선 순위 설정 (00-cloudshield.conf)
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes
LogLevel VERBOSE
SyslogFacility AUTH
MaxAuthTries 10
EOF

# rsyslog 서비스 활성화 (Ubuntu 24.04 등에서 /var/log/auth.log 생성 보장)
systemctl enable rsyslog
systemctl restart rsyslog

# SSH 데몬 설정 문법 검증 및 실패 시 자동 복구
if ! sshd -t; then
    log_error "SSH 문법 검사 실패!"
    rollback_sshd
    exit 1
fi

# OpenSSH 런타임 유효 설정 실측 평가 (sshd -T)
# Constraints: passwordauthentication 항목이 반드시 'yes'로 실측되어야 함
log_info "sshd -T 런타임 유효 설정 평가 중..."
EFFECTIVE_PASS_AUTH="$(sshd -T | grep -i '^passwordauthentication' | awk '{print $2}' || echo 'unknown')"

if [[ "${EFFECTIVE_PASS_AUTH}" != "yes" ]]; then
    log_error "SSH PasswordAuthentication 적용 실패! (sshd -T 실측 결과: ${EFFECTIVE_PASS_AUTH})"
    rollback_sshd
    exit 1
fi

cleanup_sshd_backups
log_success "SSH PasswordAuthentication 런타임 실측 검증 완료 (status: ${EFFECTIVE_PASS_AUTH})"

# SSH 데몬 서비스 재시작
if systemctl is-active --quiet ssh; then
    systemctl restart ssh
elif systemctl is-active --quiet sshd; then
    systemctl restart sshd
else
    systemctl enable --now ssh || systemctl enable --now sshd
fi

log_success "SSH 데몬 설정 및 서비스 재시작 완료 (포트 22 활성화)"

# 5. Nginx 웹 서버 구성 및 테스트 페이지 배포
log_info "Nginx 웹 서버 설정 및 테스트 페이지 구성 중..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p /etc/nginx

TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"

# 기존 /etc/nginx/nginx.conf 백업 (재실행 시 사용자 설정 유실 방지)
if [[ -f /etc/nginx/nginx.conf ]]; then
    cp /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.bak.${TIMESTAMP}"
    log_warn "기존 Nginx 설정 백업 완료: /etc/nginx/nginx.conf.bak.${TIMESTAMP}"
fi

if [[ -f "${SCRIPT_DIR}/nginx.conf" ]]; then
    cp "${SCRIPT_DIR}/nginx.conf" /etc/nginx/nginx.conf
    log_info "${SCRIPT_DIR}/nginx.conf 설정을 /etc/nginx/nginx.conf로 적용했습니다."
elif [[ -f "./nginx.conf" ]]; then
    cp ./nginx.conf /etc/nginx/nginx.conf
    log_info "로컬 ./nginx.conf 설정을 /etc/nginx/nginx.conf로 적용했습니다."
else
    log_info "외부 nginx.conf가 감지되지 않아 내장 최적화 설정을 /etc/nginx/nginx.conf에 배포합니다."
    cat << 'NGINX_CONF_EOF' > /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format cloudshield_combined '$remote_addr - $remote_user [$time_local] '
                                    '"$request" $status $body_bytes_sent '
                                    '"$http_referer" "$http_user_agent" '
                                    '$request_time "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log cloudshield_combined;
    error_log /var/log/nginx/error.log warn;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    server {
        listen 80 default_server;
        listen [::]:80 default_server;

        server_name _;
        root /var/www/html;
        index index.html index.htm;

        location / {
            try_files $uri $uri/ =404;
        }

        location /health {
            access_log off;
            default_type application/json;
            return 200 '{"status":"healthy","service":"cloudshield-target"}';
        }

        location /admin {
            auth_basic "Restricted Admin Area";
            auth_basic_user_file /etc/nginx/.htpasswd;
            try_files $uri $uri/ =401;
        }

        location /api/v1/auth/login {
            default_type application/json;
            return 401 '{"error":"Unauthorized","message":"Invalid credentials"}';
        }
    }
}
NGINX_CONF_EOF
fi

# /admin 엔드포인트 401 인증용 해시 기반 htpasswd 생성 및 기존 평문 마이그레이션
HTPASSWD_FILE="/etc/nginx/.htpasswd"

NEEDS_HASH=false
if [[ ! -f "${HTPASSWD_FILE}" ]]; then
    NEEDS_HASH=true
elif grep -q "{PLAIN}" "${HTPASSWD_FILE}" 2>/dev/null || grep -q "cloudshield_demo_pass" "${HTPASSWD_FILE}" 2>/dev/null; then
    log_warn "기존 htpasswd 내 평문 인증정보 감지! 해시 암호화로 마이그레이션합니다."
    NEEDS_HASH=true
fi

if [[ "${NEEDS_HASH}" == true ]]; then
    PASS_HASH="$(openssl passwd -1 "cloudshield_demo_pass" 2>/dev/null || echo '$1$cloudshield$qH/9JzE2Vd8S7q0M3u5mJ.')"
    echo "admin:${PASS_HASH}" > "${HTPASSWD_FILE}"
    log_success "Nginx htpasswd 해시 인증 정보 생성/마이그레이션 완료"
fi

# 파일이 이미 존재하더라도 필요한 소유권 및 최소 권한(640) 항시 보정
chmod 640 "${HTPASSWD_FILE}"
chown root:www-data "${HTPASSWD_FILE}" 2>/dev/null || chown root:adm "${HTPASSWD_FILE}" 2>/dev/null || true
log_success "Nginx htpasswd 파일 권한(640) 및 소유권 보정 완료"

# 기존 index.html 백업 및 테스트 웹 페이지 배포
mkdir -p /var/www/html
if [[ -f /var/www/html/index.html ]]; then
    cp /var/www/html/index.html "/var/www/html/index.html.bak.${TIMESTAMP}"
    log_warn "기존 index.html 백업 완료: /var/www/html/index.html.bak.${TIMESTAMP}"
fi

cat << 'EOF' > /var/www/html/index.html
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudShield Target Server</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2.5rem; max-width: 580px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }
        .badge { display: inline-block; background-color: #3b82f6; color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.875rem; font-weight: 600; margin-bottom: 1rem; }
        h1 { margin-top: 0; font-size: 1.75rem; color: #38bdf8; }
        p { color: #94a3b8; line-height: 1.6; }
        .status-box { background: #0f172a; border-left: 4px solid #10b981; padding: 1rem; border-radius: 4px; margin-top: 1.5rem; }
        code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; color: #a5f3fc; }
    </style>
</head>
<body>
    <div class="card">
        <span class="badge">CloudShield SecOps Lab</span>
        <h1>Target Instance Ready</h1>
        <p>클라우드 하이브리드 위협 탐지·자동 대응 파이프라인의 실증 타깃 서버입니다.</p>
        <div class="status-box">
            <div><strong>Active Ports:</strong> <code>TCP 22 (SSH)</code>, <code>TCP 80 (HTTP)</code></div>
            <div><strong>Log Stream 1:</strong> <code>/var/log/auth.log</code> (SSH 인증 실패)</div>
            <div><strong>Log Stream 2:</strong> <code>/var/log/nginx/access.log</code> (L7 웹 트래픽)</div>
        </div>
    </div>
</body>
</html>
EOF

# Nginx 설정 문법 검증 및 서비스 재시작
nginx -t
systemctl enable nginx
systemctl restart nginx

log_success "Nginx 웹 서버 구성 및 서비스 재시작 완료 (포트 80 활성화)"

# 6. 방화벽(UFW) 포트 개방 설정
log_info "UFW 방화벽 규칙 점검 및 구성 중..."
if command -v ufw >/dev/null 2>&1; then
    ufw allow 22/tcp comment 'CloudShield SSH' || true
    ufw allow 80/tcp comment 'CloudShield HTTP' || true

    if ufw status 2>/dev/null | grep -qi "Status: active"; then
        log_success "UFW 활성화 상태 감지: 포트 22/tcp, 80/tcp 허용 규칙 적용 완료"
    else
        log_info "UFW 비활성화 상태: 방화벽 규칙 사전 등록 완료 (L4 포트 제어는 AWS Security Group이 제어함)"
    fi
fi

# 7. 수집 타깃 로그 경로 및 권한 최종 검증
log_info "CloudWatch Agent 수집 대상 로그 경로 검증 중..."

# auth.log 파일 확인 및 권한 점검
if [[ ! -f /var/log/auth.log ]]; then
    touch /var/log/auth.log
    chmod 640 /var/log/auth.log
    chown syslog:adm /var/log/auth.log || chown root:adm /var/log/auth.log || true
fi

# Nginx log 파일 확인 및 권한 점검
mkdir -p /var/log/nginx
touch /var/log/nginx/access.log /var/log/nginx/error.log
chmod 644 /var/log/nginx/access.log /var/log/nginx/error.log
chown -R www-data:adm /var/log/nginx || true

# 8. 최종 구동 상태 및 포트 리스닝 결과 출력
log_info "============================================================"
log_info "CloudShield: 타깃 환경 초기화 및 상태 검증 요약"
log_info "============================================================"

echo -e "\n[1] 활성화된 리스닝 포트 확인:"
netstat -tlpn | grep -E ':(22|80)\s' || ss -tlpn | grep -E ':(22|80)\s' || true

echo -e "\n[2] 수집 대상 로그 파일 상태:"
ls -lh /var/log/auth.log /var/log/nginx/access.log /var/log/nginx/error.log

echo -e "\n[3] Nginx 헬스체크 로컬 테스트:"
curl -Is http://127.0.0.1/health | head -n 5 || true

log_success "1단계: 타깃 EC2 리눅스 환경 구성이 성공적으로 완료되었습니다!"
