FROM debian:bookworm-slim
# 다운로드는 명시적 build에서만 수행한다. 실행은 소유 internal bridge에 고정한다.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 iproute2 ethtool tcpdump bash coreutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY tcpdump_capture.sh /opt/network/tcpdump_capture.sh
COPY lab/tcpdump.sh /usr/local/bin/tcpdump
COPY lab/packet_worker.py lab/netem_worker.py /opt/lab/
RUN chmod 755 /usr/local/bin/tcpdump && mkdir -p /run/evidence
LABEL cloudshield.network.netem-lab="netem-v1"
CMD ["sleep", "infinity"]
