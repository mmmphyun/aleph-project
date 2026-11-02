FROM debian:bookworm-slim
# 런타임은 internal bridge에 한정한다. 다운로드는 명시적 build에서만 수행한다.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 curl iptables iproute2 tcpdump bash coreutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY tcpdump_capture.sh /opt/network/tcpdump_capture.sh
COPY lab/tcpdump.sh /usr/local/bin/tcpdump
COPY lab/packet_worker.py /opt/lab/packet_worker.py
RUN chmod 755 /usr/local/bin/tcpdump && mkdir -p /run/evidence
LABEL cloudshield.network.packet-lab="packet-v1"
CMD ["sleep", "infinity"]
