FROM python:3.13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends wireguard-tools iproute2 iptables iputils-ping ffmpeg curl netcat-openbsd tcpdump \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
# app/ includes dashboard.html, served at /
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
