FROM debian:bookworm-slim
# 다운로드는 명시적 build 단계에만 허용한다. 런타임은 내부 네트워크만 사용한다.
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server openssh-client tcpdump iproute2 bash coreutils ca-certificates \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && useradd --create-home --shell /bin/bash lab && passwd -d lab \
    && install -d -m 700 -o lab -g lab /home/lab/.ssh \
    && mkdir -p /run/sshd
COPY ssh_single_connect.sh tcpdump_capture.sh /opt/network/
COPY lab/server.sh lab/sshd_config /opt/lab/
COPY lab/tcpdump.sh /usr/local/bin/tcpdump
RUN chmod 755 /usr/local/bin/tcpdump
LABEL cloudshield.network.lab="ssh-single-v1"
CMD ["sleep", "infinity"]
