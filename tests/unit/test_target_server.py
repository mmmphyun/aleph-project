# CloudShield 단위 테스트: 타깃 EC2 환경 초기화 및 웹 서버 설정 검증
# 소유자: 클라우드 B 담당
"""타깃 EC2 초기화 스크립트(init_target_server.sh) 및 Nginx 설정(nginx.conf) 무결성 검증 테스트."""

from __future__ import annotations

import base64
import gzip
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from collector.cw_processor import SUBSCRIPTION_FILTER_SPECS


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
    assert "\nset -Eeuo pipefail\n" in content, "실행되는 안전성 플래그가 필수입니다."
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


ROOT = Path(__file__).resolve().parents[2]


def test_ec2_filter_contract_matches_collector() -> None:
    """Terraform 배포 필터와 수집기 명세의 이탈을 차단한다."""
    module = ROOT / "infra/terraform/modules/ec2/main.tf"
    content = module.read_text(encoding="utf-8")
    for spec in SUBSCRIPTION_FILTER_SPECS.values():
        match = re.search(
            re.escape('"' + spec["log_group_name"] + '"') + r'\s*=\s*("(?:\\.|[^"\\])*")',
            content,
        )
        assert match is not None
        assert json.loads(match.group(1)) == spec["filter_pattern"]


def script_section(start: str, end: str) -> str:
    """복제 로직 대신 실제 초기화 스크립트의 구간을 실행한다."""
    content = (ROOT / "init_target_server.sh").read_text(encoding="utf-8")
    return content[content.index(start) : content.index(end)]


def run_section(section: str, prefix: str = "") -> subprocess.CompletedProcess[str]:
    bash_exe = get_bash_executable()
    assert bash_exe, "실제 초기화 회귀 검증에 Bash가 필요합니다."
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "test-section.sh"
        script.write_text(
            "set -Eeuo pipefail\nlog_error() { :; }\nlog_warn() { :; }\nlog_success() { :; }\n"
            + prefix
            + section,
            encoding="utf-8",
            newline="\n",
        )
        return subprocess.run(
            [bash_exe, script.as_posix()],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )


@pytest.mark.parametrize("failure", [None, "random", "hash", "invalid_hash"])
def test_real_htpasswd_migration(tmp_path: Path, failure: str | None) -> None:
    target = tmp_path / ".htpasswd"
    target.write_text("admin:{PLAIN}legacy\n", encoding="utf-8")
    section = script_section("HTPASSWD_FILE=", "# 기존 index.html")
    section = section.replace('"/etc/nginx/.htpasswd"', f'"{target.as_posix()}"')
    prefix = "chown() { :; }\n"
    if failure == "random":
        prefix += 'openssl() { [[ "$1" != rand ]] && command openssl "$@"; }\n'
    elif failure == "hash":
        prefix += 'openssl() { [[ "$1" != passwd ]] && command openssl "$@"; }\n'
    elif failure == "invalid_hash":
        prefix += "openssl() { echo invalid; }\n"
    result = run_section(section, prefix)
    if failure:
        assert result.returncode != 0
        assert target.read_text(encoding="utf-8") == "admin:{PLAIN}legacy\n"
    else:
        assert result.returncode == 0, result.stderr
        assert target.read_text(encoding="utf-8").startswith("admin:$6$")
        if os.name != "nt":
            assert target.stat().st_mode & 0o777 == 0o640
        # 재실행 시 해시를 새로 만들지 않아 멱등성을 유지한다.
        before = target.read_bytes()
        assert run_section(section, prefix).returncode == 0
        assert target.read_bytes() == before


@pytest.mark.parametrize("failure", ["rsyslog", "syntax", "restart"])
def test_real_ssh_failure_restores_configs(tmp_path: Path, failure: str) -> None:
    ssh_dir = tmp_path / "ssh"
    dropins = ssh_dir / "sshd_config.d"
    dropins.mkdir(parents=True)
    files = [
        ssh_dir / "sshd_config",
        dropins / "00-cloudshield.conf",
        dropins / "99-cloudshield.conf",
    ]
    for file in files:
        file.write_text("original\n", encoding="utf-8")
    section = script_section("SSHD_MAIN_CONF=", "# 5. Nginx")
    section = section.replace("/etc/ssh", ssh_dir.as_posix())
    rsyslog_dir = tmp_path / "rsyslog"
    rsyslog_dir.mkdir()
    section = section.replace("/etc/rsyslog.d", rsyslog_dir.as_posix())
    prefix = f"""
log_info() {{ :; }}
systemctl() {{
    if [[ '{failure}' == rsyslog && "$2" == rsyslog ]]; then return 1; fi
    if [[ '{failure}' == restart && "$1" == restart && "$2" == ssh ]]; then return 1; fi
    return 0
}}
sshd() {{
    if [[ '{failure}' == syntax && "$1" == -t ]]; then return 1; fi
    echo 'passwordauthentication yes'
}}
"""
    result = run_section(section, prefix)
    assert result.returncode != 0
    for file in files:
        assert file.read_text(encoding="utf-8") == "original\n", result.stderr


@pytest.mark.parametrize("failure", ["syntax", "restart"])
def test_real_nginx_failure_restores_configuration(tmp_path: Path, failure: str) -> None:
    nginx_dir = tmp_path / "nginx"
    nginx_dir.mkdir()
    conf = nginx_dir / "nginx.conf"
    conf.write_text("original\n", encoding="utf-8")
    web_dir = tmp_path / "html"
    web_dir.mkdir()
    index = web_dir / "index.html"
    index.write_text("original page\n", encoding="utf-8")
    section = script_section("NGINX_CONF_HAD_FILE=", "# 6. 방화벽")
    section = section.replace("/etc/nginx", nginx_dir.as_posix()).replace(
        "/var/www/html", web_dir.as_posix()
    )
    prefix = f"""
SCRIPT_DIR='{tmp_path.as_posix()}'
log_info() {{ :; }}
chown() {{ :; }}
nginx() {{ [[ '{failure}' != syntax ]]; }}
systemctl() {{ [[ '{failure}' != restart || "$1" != restart ]]; }}
"""
    result = run_section(section, prefix)
    assert result.returncode != 0
    assert conf.read_text(encoding="utf-8") == "original\n"
    assert index.read_text(encoding="utf-8") == "original page\n"


def test_real_firewall_failure_is_not_suppressed() -> None:
    section = script_section("if command -v ufw", "# 7. 수집")
    result = run_section(section, "log_info() { :; }\nufw() { return 1; }\n")
    assert result.returncode != 0


def test_real_health_failure_is_not_suppressed() -> None:
    content = (ROOT / "init_target_server.sh").read_text(encoding="utf-8")
    section = content[content.index("curl --fail --show-error --silent") :]
    result = run_section(section, "curl() { return 22; }\n")
    assert result.returncode != 0


@pytest.mark.parametrize("failure", [None, "download", "install", "agent", "health"])
def test_real_agent_bootstrap(tmp_path: Path, failure: str | None) -> None:
    """압축 자산 복원과 단계별 장애 전파를 실제 user-data 템플릿으로 검증한다."""
    module = ROOT / "infra/terraform/modules/ec2"
    content = (module / "user_data.sh.tftpl").read_text(encoding="utf-8")
    assets = {
        "init_script": ROOT / "init_target_server.sh",
        "nginx_config": ROOT / "nginx.conf",
        "agent_config": ROOT / "src/collector/amazon-cloudwatch-agent.json",
    }
    for name, path in assets.items():
        packed = base64.b64encode(gzip.compress(path.read_bytes())).decode("ascii")
        content = content.replace("${" + name + "}", packed)
    assert len(content.encode("ascii")) <= 16384
    asset_dir = tmp_path / "assets"
    content = content.replace("/opt/cloudshield", asset_dir.as_posix())
    content = content.replace(
        "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl", "agent_ctl"
    )
    marker = tmp_path / "calls"
    prefix = f"""
install() {{ mkdir -p "$4"; }}
bash() {{ echo init >> '{marker.as_posix()}'; }}
curl() {{
    if [[ "$*" == *127.0.0.1* ]]; then
        [[ '{failure}' != health ]] || return 22
        echo health >> '{marker.as_posix()}'
    else
        [[ '{failure}' != download ]] || return 22
        echo download >> '{marker.as_posix()}'
    fi
}}
dpkg() {{ [[ '{failure}' != install ]] || return 1; echo install >> '{marker.as_posix()}'; }}
agent_ctl() {{ [[ '{failure}' != agent ]] || return 1; echo agent >> '{marker.as_posix()}'; }}
systemctl() {{ :; }}
"""
    # shebang이 본문 첫 줄일 필요는 없으며 mock 외부 명령만 주입한다.
    result = run_section(content, prefix)
    if failure:
        assert result.returncode != 0
        assert "bootstrap failed" in result.stderr
        assert failure not in marker.read_text(encoding="utf-8").splitlines()
    else:
        assert result.returncode == 0, result.stderr
        assert marker.read_text(encoding="utf-8").splitlines() == [
            "init",
            "download",
            "install",
            "agent",
            "health",
        ]
    for name, path in assets.items():
        restored = {
            "init_script": "init_target_server.sh",
            "nginx_config": "nginx.conf",
            "agent_config": "amazon-cloudwatch-agent.json",
        }[name]
        assert (asset_dir / restored).read_bytes() == path.read_bytes()
