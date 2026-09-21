FROM debian:bookworm-slim
# 빌드만 인터넷을 사용하며 실행은 러너가 생성한 internal bridge에 고정한다.
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server openssh-client tcpdump iproute2 bash coreutils hydra python3 \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && useradd --create-home --shell /bin/bash hydralab \
    && mkdir -p /run/sshd
COPY tcpdump_capture.sh /opt/network/
COPY lab/tcpdump.sh /usr/local/bin/tcpdump
COPY lab/hydra_server.sh lab/hydra_sshd_config lab/hydra_worker.py /opt/lab/
RUN chmod 755 /usr/local/bin/tcpdump
LABEL cloudshield.network.lab="hydra-fail-v1"
CMD ["sleep", "infinity"]
