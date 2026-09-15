#!/usr/bin/env bash
# 개인 호스트 키를 공유하지 않고 매 컨테이너마다 독립 신원을 생성한다.
set -euo pipefail
umask 077
ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
exec /usr/sbin/sshd -D -e -f /opt/lab/sshd_config
