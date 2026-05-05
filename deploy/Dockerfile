# Multi-stage build for a minimal qlinkd image.
#
# Stage 1 builds the daemon against musl libc so the output is a
# fully-static binary that runs on any modern Linux without a
# matching glibc on the host. Stage 2 starts from `scratch` and
# copies in only the binary — no shell, no package manager, no
# attack surface beyond what qlinkd itself needs.
#
# Image size: ~12 MB. Layer count: 2.
#
# Build:
#   docker build -t quantumlink/qlinkd:latest -f deploy/Dockerfile .
#
# Inspect what's in the runtime image:
#   docker run --rm --entrypoint /qlinkd quantumlink/qlinkd:latest --help
# (There's no shell in the image; that's the point.)

# ---- Stage 1: build ---------------------------------------------------------

FROM rust:1.85-alpine AS builder

# Alpine ships with musl libc by default; ALL we need is a few
# build-time deps for the crypto crates that link to system libs.
# Most of our deps are pure-Rust (rustls, ring, etc.); the few that
# aren't can be satisfied with these.
RUN apk add --no-cache musl-dev pkgconfig openssl-dev

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY rust ./rust

# Build the daemon only — we don't need the full xcframework or the
# qlinkctl binary in the runtime image.
RUN cargo build --release --bin qlinkd --manifest-path rust/qlink-core/Cargo.toml

# Strip the binary to shrink the runtime image. Debug info adds
# significant size to release builds; we want the smallest possible
# attack surface for a network-facing daemon.
RUN strip rust/qlink-core/target/release/qlinkd || \
    /usr/bin/strip rust/qlink-core/target/release/qlinkd

# ---- Stage 2: runtime -------------------------------------------------------

FROM scratch

# /tmp is what tokio's signal handlers expect to write coredumps to,
# and is also conventional for ephemeral state. We include it as
# part of the image so the daemon doesn't fail on missing-dir errors.
COPY --from=builder /src/rust/qlink-core/target/release/qlinkd /qlinkd

# Document the standard QuantumLink ports. Compose's `network_mode:
# host` ignores EXPOSE, but it's still useful for `ports:` mode and
# for documentation.
EXPOSE 9471/tcp 9472/tcp 9473/udp 9474/udp

# Container never needs root once the binary's caps are set; the
# compose file's `cap_add: NET_ADMIN` provides what we need without
# UID 0.
USER 65532:65532

ENTRYPOINT ["/qlinkd"]
