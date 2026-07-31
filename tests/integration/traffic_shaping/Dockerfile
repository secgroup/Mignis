FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iptables iperf3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/mignis

COPY mignis.py ipaddr_ext.py ./
COPY tests/integration/traffic_shaping/router.config /etc/mignis/router.config

CMD ["sleep", "infinity"]
