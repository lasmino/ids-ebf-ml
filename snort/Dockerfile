FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt install -y snort && \
    mkdir -p /var/log/snort

CMD ["snort", "-A", "fast", "-q", "-c", "/etc/snort/snort.conf", "-i", "eth0", "-l", "/var/log/snort"]