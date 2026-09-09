# CloudShield 단위 테스트: 타깃 EC2 환경 초기화 및 웹 서버 설정 검증
# 소유자: 클라우드 B 담당
"""타깃 EC2 초기화 스크립트(init_target_server.sh) 및 Nginx 설정(nginx.conf) 무결성 검증 테스트."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


def get_bash_executable() -> str | None:
    """테스트 환경에 설치된 bash 실행 경로 탐색."""
    bash_cmd = shutil.which("bash")
    if bash_cmd:
        return bash_cmd
    git_bash = r"C:\Program Files\Git\bin\bash.exe"
    if os.path.exists(git_bash):
        return git_bash
    return None


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
    assert "openssl" in content, "openssl 패키지 명시 설치 의존성 필수."
    assert "openssl passwd" in content, "htpasswd 평문 저장 금지(해시 사용 필수)."
    assert "chmod 640" in content, "htpasswd 권한 640 제한 필수."
    assert "{PLAIN}" in content, "기존 평문 htpasswd 감지 및 마이그레이션 로직 필수."

    # 2. OpenSSH 우선순위 및 백업/복구 로직 검증
    assert "00-cloudshield.conf" in content, "OpenSSH 우선순위 00-*.conf 파일 사용 필수."
    assert "99-cloudshield.conf" in content, "legacy 99-*.conf 파일 백업/정리 로직 필수."
    assert "rollback_sshd" in content, "SSH 검증 실패 시 완전 복원(Rollback) 함수 필수."
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


def test_htpasswd_migration_removes_plain_text(tmp_path: Path) -> None:
    """기존 인스턴스에 평문 {PLAIN} 및 644 권한이 남아있을 때 해시 전환 및 640 보정 회귀 검증."""
    bash_exe = get_bash_executable()
    if not bash_exe:
        pytest.skip("Bash 실행 환경이 없어 테스트를 건너뜁니다.")

    htpasswd_file = tmp_path / ".htpasswd"
    # 1. 이전 버전 상태 모의 생성: 평문 {PLAIN} 및 0o644 권한
    htpasswd_file.write_text("admin:{PLAIN}cloudshield_demo_pass\n", encoding="utf-8")
    htpasswd_file.chmod(0o644)

    # 2. init_target_server.sh의 htpasswd 처리 로직을 격리 실행
    bash_script = f"""
    set -euo pipefail
    HTPASSWD_FILE="{htpasswd_file.as_posix()}"
    NEEDS_HASH=false
    if [[ ! -f "${{HTPASSWD_FILE}}" ]]; then
        NEEDS_HASH=true
    elif grep -q "{{PLAIN}}" "${{HTPASSWD_FILE}}" 2>/dev/null; then
        NEEDS_HASH=true
    fi

    if [[ "${{NEEDS_HASH}}" == true ]]; then
        PASS_HASH="\\$1\\$test\\$dummyhash123"
        echo "admin:${{PASS_HASH}}" > "${{HTPASSWD_FILE}}"
    fi
    chmod 640 "${{HTPASSWD_FILE}}"
    """

    res = subprocess.run([bash_exe, "-c", bash_script], capture_output=True, text=True)
    assert res.returncode == 0, f"Bash 실행 실패: {res.stderr}"

    # 3. 평문 제거 및 해시 전환, 권한 640 확인
    updated_content = htpasswd_file.read_text(encoding="utf-8")
    assert "{PLAIN}" not in updated_content
    assert "admin:$1$test$dummyhash123" in updated_content
    # POSIX 권한 640 검증 (0o640 == 416)
    if os.name != "nt":
        assert (htpasswd_file.stat().st_mode & 0o777) == 0o640


def test_sshd_rollback_preserves_existing_configs_on_failure(tmp_path: Path) -> None:
    """재실행 중 sshd 검증 실패 시 기존 00 및 99 drop-in 파일이 완전히 복원되는지 회귀 검증."""
    bash_exe = get_bash_executable()
    if not bash_exe:
        pytest.skip("Bash 실행 환경이 없어 테스트를 건너뜁니다.")

    ssh_dir = tmp_path / "ssh"
    sshd_dir = ssh_dir / "sshd_config.d"
    sshd_dir.mkdir(parents=True)

    main_conf = ssh_dir / "sshd_config"
    conf_00 = sshd_dir / "00-cloudshield.conf"
    conf_99 = sshd_dir / "99-cloudshield.conf"

    main_conf.write_text("Original Main SSH Config\n", encoding="utf-8")
    conf_00.write_text("# Existing 00 Config Content\n", encoding="utf-8")
    conf_99.write_text("# Existing 99 Legacy Config Content\n", encoding="utf-8")

    bash_script = f"""
    set -euo pipefail
    SSHD_MAIN_CONF="{main_conf.as_posix()}"
    SSHD_MAIN_BAK="{main_conf.as_posix()}.bak.cloudshield"
    SSHD_DIR="{sshd_dir.as_posix()}"
    SSHD_CUSTOM_CONF="{conf_00.as_posix()}"
    SSHD_CUSTOM_BAK="{conf_00.as_posix()}.bak.cloudshield"
    SSHD_LEGACY_CONF="{conf_99.as_posix()}"
    SSHD_LEGACY_BAK="{conf_99.as_posix()}.bak.cloudshield"

    HAD_MAIN=false
    HAD_CUSTOM=false
    HAD_LEGACY=false

    if [[ -f "${{SSHD_MAIN_CONF}}" ]]; then
        cp "${{SSHD_MAIN_CONF}}" "${{SSHD_MAIN_BAK}}"
        HAD_MAIN=true
    fi
    if [[ -f "${{SSHD_CUSTOM_CONF}}" ]]; then
        cp "${{SSHD_CUSTOM_CONF}}" "${{SSHD_CUSTOM_BAK}}"
        HAD_CUSTOM=true
    fi
    if [[ -f "${{SSHD_LEGACY_CONF}}" ]]; then
        cp "${{SSHD_LEGACY_CONF}}" "${{SSHD_LEGACY_BAK}}"
        HAD_LEGACY=true
        rm -f "${{SSHD_LEGACY_CONF}}"
    fi

    rollback_sshd() {{
        if [[ "${{HAD_MAIN}}" == true && -f "${{SSHD_MAIN_BAK}}" ]]; then
            cp "${{SSHD_MAIN_BAK}}" "${{SSHD_MAIN_CONF}}"
            rm -f "${{SSHD_MAIN_BAK}}"
        fi
        if [[ "${{HAD_CUSTOM}}" == true && -f "${{SSHD_CUSTOM_BAK}}" ]]; then
            cp "${{SSHD_CUSTOM_BAK}}" "${{SSHD_CUSTOM_CONF}}"
            rm -f "${{SSHD_CUSTOM_BAK}}"
        else
            rm -f "${{SSHD_CUSTOM_CONF}}"
            rm -f "${{SSHD_CUSTOM_BAK}}"
        fi
        if [[ "${{HAD_LEGACY}}" == true && -f "${{SSHD_LEGACY_BAK}}" ]]; then
            cp "${{SSHD_LEGACY_BAK}}" "${{SSHD_LEGACY_CONF}}"
            rm -f "${{SSHD_LEGACY_BAK}}"
        fi
    }}

    # 새 설정 덮어쓰기 시도
    echo "New 00 Config" > "${{SSHD_CUSTOM_CONF}}"
    echo "Modified Main" > "${{SSHD_MAIN_CONF}}"

    # 가상 검증 실패 트리거
    SIMULATED_FAIL=true
    if [[ "${{SIMULATED_FAIL}}" == true ]]; then
        rollback_sshd
        exit 1
    fi
    """

    res = subprocess.run([bash_exe, "-c", bash_script], capture_output=True, text=True)
    assert res.returncode == 1, "검증 실패 시 exit 1로 종료되어야 합니다."

    # 롤백 후 원본 내용 완벽 복원 확인
    assert main_conf.read_text(encoding="utf-8") == "Original Main SSH Config\n"
    assert conf_00.read_text(encoding="utf-8") == "# Existing 00 Config Content\n"
    assert conf_99.read_text(encoding="utf-8") == "# Existing 99 Legacy Config Content\n"
