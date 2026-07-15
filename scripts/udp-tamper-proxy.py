#!/usr/bin/env python3
"""
udp-tamper-proxy.py — transparent on-path UDP MITM for QuantumLink channel
attack testing. Sits between a connector and a responder's QUIC endpoint and,
in the client->responder direction, tampers or duplicates ONLY small app-frame
datagrams (the multi-KB PQC/QUIC handshake passes untouched so the session
still establishes — isolating app-frame integrity).

The responder must advertise THIS proxy's public endpoint (qlinkctl
publish-self --advertise-addr) while binding to --forward-to.

Modes: passthrough | tamper | duplicate | drop
"""
import argparse, signal, socket, sys, threading, time

ap = argparse.ArgumentParser()
ap.add_argument("--listen", required=True)      # public ip:port the connector dials
ap.add_argument("--forward-to", required=True)  # real responder bind ip:port
ap.add_argument("--mode", default="passthrough",
                choices=["passthrough", "tamper", "duplicate", "drop"])
ap.add_argument("--app-min", type=int, default=48)   # skip tiny pure-ACK packets
ap.add_argument("--app-max", type=int, default=300)  # handshake packets are >1KB
args = ap.parse_args()

lip, lport = args.listen.rsplit(":", 1)
fip, fport = args.__dict__["forward_to"].rsplit(":", 1)
forward = (fip, int(fport))

listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listen_sock.bind((lip, int(lport)))
up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

state = {"client": None}
stats = {"c2r": 0, "r2c": 0, "attacked": 0, "dropped": 0}

def is_app(n):
    return args.app_min <= n <= args.app_max

def client_to_responder():
    while True:
        data, addr = listen_sock.recvfrom(65535)
        state["client"] = addr
        stats["c2r"] += 1
        if is_app(len(data)):
            if args.mode == "tamper":
                b = bytearray(data); b[-1] ^= 0x01; data = bytes(b)
                stats["attacked"] += 1
            elif args.mode == "drop":
                stats["dropped"] += 1; continue
            elif args.mode == "duplicate":
                up.sendto(data, forward)  # send it twice
                stats["attacked"] += 1
        up.sendto(data, forward)

def responder_to_client():
    while True:
        data, _ = up.recvfrom(65535)
        c = state["client"]
        if c:
            listen_sock.sendto(data, c)
            stats["r2c"] += 1

threading.Thread(target=client_to_responder, daemon=True).start()
threading.Thread(target=responder_to_client, daemon=True).start()

def dump(*_):
    print(f"proxy_stats mode={args.mode} {stats}", flush=True)

def bye(*_):
    dump(); sys.exit(0)

signal.signal(signal.SIGTERM, bye)
signal.signal(signal.SIGINT, bye)
print(f"proxy listen={args.listen} forward={args.__dict__['forward_to']} "
      f"mode={args.mode} app=[{args.app_min},{args.app_max}]", flush=True)
while True:
    time.sleep(2); dump()
