FROM rust:1.88-bookworm

ENV container=docker
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        dbus \
        dbus-user-session \
        iproute2 \
        libssl-dev \
        nftables \
        pkg-config \
        policykit-1 \
        procps \
        python3 \
        systemd \
        systemd-sysv \
    && rm -rf /var/lib/apt/lists/* \
    && systemctl mask \
        dev-hugepages.mount \
        sys-fs-fuse-connections.mount \
        systemd-remount-fs.service \
        getty.target \
        console-getty.service

STOPSIGNAL SIGRTMIN+3

CMD ["/sbin/init"]
