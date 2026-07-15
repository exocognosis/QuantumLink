# QuantumLink Connection Security — Test Results (Plain English)

**Date:** July 14, 2026
**What this covers:** whether QuantumLink's secure connection can be spied on, tampered with, or disrupted by someone sitting in the middle of it.

---

## The short version

We set up a real QuantumLink connection between a computer here and a rented
server in **Helsinki, Finland**, and sent data back and forth across the open
internet. Then we played the role of an attacker with a front-row seat — someone
positioned directly in the middle of the connection who could see and touch
every piece of data as it went by.

**The attacker could not read the data, could not change it, and could not
duplicate it. In every case the connection either delivered the correct data or
delivered nothing at all — it never accepted anything the attacker touched.**

---

## What we set up

Think of QuantumLink as a private, armored tunnel between two points. For this
test:

- One end was a computer on our desk.
- The other end was a real server we rented in Finland — about 1,500 miles away.
- The two talked to each other over the normal public internet, exactly like a
  real user would.

This was **not** a lab simulation. It was the real software running over the
real internet.

---

## What we tested, and what happened

We asked three questions an attacker would ask. To make it a fair fight, we gave
the attacker the strongest possible position: **directly in the path**, able to
see and modify everything.

### 1. "Can I read what's being sent?" — No.

We sent a message containing a secret marker word and recorded every scrap of
data that crossed the wire. Then we searched all of it for that marker word.

**Result:** the marker word appeared **nowhere**. Everything was scrambled from
end to end. To anyone watching the connection, the traffic is meaningless noise.

### 2. "Can I secretly change what's being sent?" — No.

We inserted a middleman that quietly altered messages as they passed through —
the digital equivalent of steaming open an envelope and changing the letter
inside.

**Result:** we sent 20 messages and the attacker altered them in transit. The
receiving end accepted **zero** of them. It recognized every tampered message as
"not authentic" and threw it away. Importantly, the connection didn't crash or
get tricked — it simply refused the bad data and kept running.

### 3. "Can I copy a message and send it again?" — No.

Some attacks work by capturing a legitimate message and re-sending it — for
example, replaying a "transfer approved" instruction twice. Our middleman
duplicated every single message.

**Result:** we sent 10 messages; the attacker turned them into 20 on the wire.
The receiving end still delivered exactly **10** — each message once. Every
duplicate was recognized and discarded.

---

## Results at a glance

| What the attacker tried | What we expected | What happened |
|---|---|---|
| Read the private data | Should see only scrambled noise | ✅ Secret marker never appeared |
| Secretly alter messages | Altered messages rejected | ✅ 0 of 20 tampered messages accepted |
| Duplicate messages | Duplicates ignored | ✅ 10 sent, 10 delivered (not 20) |
| Normal use (no attack) | Works reliably | ✅ All messages delivered |

---

## What this means

Even an attacker with the best possible seat — sitting inside the connection
with full control over the traffic — **could not read the conversation, could
not change it, and could not replay it.** The connection is built to fail safe:
when something is wrong, it delivers nothing rather than delivering something
untrustworthy.

## What this does *not* claim

To be straight about the boundaries: this test was about the **security of the
connection itself** as data travels between two points. It does not, on its own,
measure things like the safety of a lost or stolen device, the security of the
apps at either end, or human factors like someone being tricked into sharing a
password. Those are separate questions.

---

*Prepared from live testing against a real remote server. The underlying
measurements and technical details are recorded separately in the project's
engineering notes.*
