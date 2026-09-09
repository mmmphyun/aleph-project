# CloudShield 단위 테스트: 타깃 EC2 환경 초기화 및 웹 서버 설정 검증
# 소유자: 클라우드 B 담당
"""타깃 EC2 초기화 스크립트(init_target_server.sh) 및 Nginx 설정(nginx.conf) 무결성 검증 테스트."""

from __future__ import annotations

from pathlib import Path


def test_init_target_server_script_integrity() -> None:
    """init_target_server.sh 셸 스크립트의 무결성 및 필수 보안/엔지니어링 플래그 검증.

    Why:
        타깃 인스턴스 프로비저닝 시 비정상 종료를 방지하고, 침해 실증에 필요한
        로깅 경로와 포트 활성화 명령이 누락 없이 포함되었는지 배포 전 정적 검증함.
    """
    script_path = Path(__file__).resolve().parents[2] / "init_target_server.sh"
    assert script_path.exists(), f"{script_path} 파일이 존재해야 합니다."

    content = script_path.read_text(encoding="utf-8")

    # 1. POSIX 셸 안전성 플래그 및 보안 수칙 검증
    assert "set -euo pipefail" in content, "안전성 플래그가 필수입니다."
    assert "EUID" in content, "루트 권한(EUID) 검증 로직이 포함되어야 합니다."
    assert "openssl passwd" in content, "htpasswd 평문 저장 금지(해시 사용 필수)."
    assert "chmod 640 /etc/nginx/.htpasswd" in content, "htpasswd 권한 640 제한 필수."

    # 2. OpenSSH 우선순위 및 백업/복구 로직 검증
    assert "00-cloudshield.conf" in content, "OpenSSH 우선순위 00-*.conf 파일 사용 필수."
    assert "sshd_config.bak" in content, "기존 sshd_config 백업/복구 로직 필수."
    assert "sshd -T" in content, "OpenSSH 런타임 실측(sshd -T) 평가 검증 필요."

    # 3. Nginx / index.html 백업 가드 및 UFW 로깅 검증
    assert "nginx.conf.bak" in content, "재실행 시 nginx.conf 백업 가드 필요."
    assert "index.html.bak" in content, "재실행 시 index.html 백업 가드 필요."
    assert "ufw status" in content, "UFW 실제 활성화 상태 감지 로직 필요."

    # 4. 수집 타깃 로그 경로 검증
    assert "/var/log/auth.log" in content, "auth.log 경로가 명시되어야 합니다."
    assert "/var/log/nginx/access.log" in content, "access.log 경로가 명시되어야 합니다."

    # 5. 문법 오류 유발 구문(단독 EOF 등) 방지
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    assert lines[-1] != "EOF", "스크립트 끝에 불필요한 단독 EOF 라인이 없어야 합니다."


def test_nginx_conf_integrity() -> None:
    """nginx.conf 설정 파일의 로깅 포맷 및 엔드포인트 명세 검증.

    Why:
        CloudWatch Agent가 L7 웹 로그를 안정적으로 인제스트할 수 있도록
        커스텀 로그 포맷(cloudshield_combined) 및 필수 필드가 정의되어 있는지 검증함.
    """
    conf_path = Path(__file__).resolve().parents[2] / "nginx.conf"
    assert conf_path.exists(), f"{conf_path} 파일이 존재해야 합니다."

    content = conf_path.read_text(encoding="utf-8")

    # 1. 커스텀 로그 포맷 및 경로 검증
    assert "log_format cloudshield_combined" in content, "커스텀 로그 포맷 정의 필요."
    assert "/var/log/nginx/access.log" in content, "access.log 경로 설정 필요."
    assert "$request_time" in content, "분석용 $request_time이 포함되어야 합니다."

    # 2. 필수 리스닝 포트 및 헬스체크 엔드포인트 검증
    assert "listen 80" in content, "HTTP 80 포트 리스닝이 명시되어야 합니다."
    assert "location /health" in content, "헬스체크 엔드포인트(/health) 필요."
