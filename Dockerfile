FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    tcpdump \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local /usr/local
COPY --from=builder /app /app

# Allow non-root packet capture if capability granted
RUN setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/python3.12 || true

ENTRYPOINT ["wiresniffer"]
CMD ["sniff", "--interface", "any"]
