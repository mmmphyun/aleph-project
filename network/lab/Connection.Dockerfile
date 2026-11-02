FROM debian:bookworm-slim
# 빌드에서만 패키지를 받는다. 실험은 소유 internal bridge와 합성 소켓에 한정한다.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 iproute2 tcpdump bash coreutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY tcpdump_capture.sh /opt/network/tcpdump_capture.sh
COPY lab/tcpdump.sh /usr/local/bin/tcpdump
COPY lab/packet_worker.py lab/connection_worker.py /opt/lab/
RUN chmod 755 /usr/local/bin/tcpdump && mkdir -p /run/evidence
LABEL cloudshield.network.connection-lab="connection-v1"
CMD ["sleep", "infinity"]
