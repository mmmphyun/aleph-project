#!/usr/bin/env bash
# 평문 비밀번호는 stdin으로만 전달한다. shadow 해시는 컨테이너 삭제와 함께 제거된다.
# 후보는 별도 WRONG 접두어를 사용하므로 이 정답과 일치하지 않는다.
set -euo pipefail
umask 077
python3 - <<'PY'
import secrets
import subprocess
subprocess.run(['chpasswd'], input='hydralab:RIGHT-' + secrets.token_hex(32) + '\n',
               text=True, check=True)
PY
ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
exec /usr/sbin/sshd -D -e -f /opt/lab/hydra_sshd_config
