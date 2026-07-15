#!/usr/bin/env python3
"""
tcp-relay-tamper-proxy.py — on-path MITM for the QuantumLink RELAY path.

The relay is a newline-delimited JSON TCP protocol; app frames ride as
`payload_base64` inside {"type":"datagram", ...} lines. This proxy sits between
a relay client (connector or resident node) and the real relay, and for small
app frames only (the multi-KB PQC handshake datagrams pass untouched so the
mesh session still establishes) it flips a byte or duplicates the line.

Threat model: a fully-compromised relay operator. End-to-end PQC frame
protection must defend against the relay itself.

Usage:
  tcp-relay-tamper-proxy.py --listen 0.0.0.0:9473 --forward-to 127.0.0.1:9472 \
      --mode passthrough|tamper|duplicate [--app-max 256]
"""
import argparse, base64, json, socket, threading, sys

def parse_hostport(s):
    h, p = s.rsplit(":", 1)
    return (h, int(p))

STATS = {"c2r": 0, "r2c": 0, "attacked": 0}

def maybe_attack(line: bytes, mode: str, app_max: int):
    """Return a list of lines to forward for one inbound line."""
    s = line.strip()
    if not s:
        return [line]
    try:
        msg = json.loads(s)
    except Exception:
        return [line]
    if msg.get("type") != "datagram" or "payload_base64" not in msg:
        return [line]
    try:
        raw = base64.b64decode(msg["payload_base64"])
    except Exception:
        return [line]
    if len(raw) > app_max:          # handshake frame — leave intact
        return [line]
    if mode == "tamper":
        raw = bytearray(raw)
        if raw:
            raw[-1] ^= 0x01
        msg["payload_base64"] = base64.b64encode(bytes(raw)).decode()
        STATS["attacked"] += 1
        return [(json.dumps(msg) + "\n").encode()]
    if mode == "duplicate":
        STATS["attacked"] += 1
        out = (json.dumps(msg) + "\n").encode()
        return [out, out]
    return [line]

def pump(src, dst, direction, mode, app_max):
    buf = b""
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line += b"\n"
                # Only tamper client->relay (app frames flow that way from the
                # connector). relay->client carries responder handshake only.
                outs = maybe_attack(line, mode, app_max) if direction == "c2r" else [line]
                STATS[direction] += 1
                for o in outs:
                    dst.sendall(o)
    except OSError:
        pass
    finally:
        try: dst.shutdown(socket.SHUT_WR)
        except OSError: pass

def handle(client, target, mode, app_max):
    try:
        relay = socket.create_connection(target)
    except OSError:
        client.close(); return
    threading.Thread(target=pump, args=(client, relay, "c2r", mode, app_max), daemon=True).start()
    threading.Thread(target=pump, args=(relay, client, "r2c", mode, app_max), daemon=True).start()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True)
    ap.add_argument("--forward-to", required=True)
    ap.add_argument("--mode", default="passthrough", choices=["passthrough", "tamper", "duplicate"])
    ap.add_argument("--app-max", type=int, default=256)
    a = ap.parse_args()
    lhost, lport = parse_hostport(a.listen)
    target = parse_hostport(a.forward_to)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((lhost, lport)); srv.listen(64)
    print(f"tcp-relay-proxy listen={a.listen} forward={a.forward_to} mode={a.mode} app_max={a.app_max}", flush=True)
    try:
        while True:
            c, _ = srv.accept()
            threading.Thread(target=handle, args=(c, target, a.mode, a.app_max), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        print(f"tcp_relay_proxy_stats mode={a.mode} {STATS}", flush=True)

if __name__ == "__main__":
    main()
