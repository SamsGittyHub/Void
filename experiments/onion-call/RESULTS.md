# Onion-to-onion voice probe — measured results

Run 2026-09-02, macOS, residential connection, one geographic location.
Three calls, each building a fresh circuit to the same ephemeral onion service.

## Method

`onion-call-probe listen` bootstraps Arti, publishes an ephemeral v3 onion
service, and echoes every packet it receives. `onion-call-probe call <addr>`
connects and sends 1,500 packets — one every 20 ms, 52 bytes each — which is
Opus's frame cadence at roughly 16 kbit/s. Round-trip is measured per packet
against a process-local monotonic clock, so no clock synchronisation is
involved. Echoes are read on a separate task, because a call does not stop
speaking to wait for the other side.

Mean latency is not the number that matters. A call is listenable when the
jitter buffer absorbs the spread between fast and slow packets, and that
buffer's depth is added to every packet's delay. So the probe reports the
distribution, and derives mouth-to-ear as `one-way p50 + p95 jitter + 20 ms`.

## Results

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| connect ("ring") | 2.8 s | 4.1 s | 4.7 s |
| packets echoed | 1500/1500 | 1500/1500 | 1500/1500 |
| loss | 0.0% | 0.0% | 0.0% |
| RTT min | 256 ms | 228 ms | 313 ms |
| RTT p50 | 528 ms | 376 ms | 497 ms |
| RTT p95 | 1112 ms | 635 ms | 983 ms |
| RTT p99 | 1312 ms | 1160 ms | 1187 ms |
| RTT max | 1493 ms | 1303 ms | 1442 ms |
| one-way p50 | 264 ms | 188 ms | 248 ms |
| jitter buffer (p95) | 584 ms | 259 ms | 487 ms |
| **mouth-to-ear** | **868 ms** | **467 ms** | **755 ms** |
| longest late run | 25 pkts (500 ms) | 45 pkts (900 ms) | 23 pkts (460 ms) |

## What this says

**Zero loss across 4,500 packets.** Tor's TCP delivered everything. Nothing was
dropped, which is more than a UDP voice path would promise.

**Latency alone would almost be tolerable; jitter is what breaks it.** Minimum
round-trip sat at 228–313 ms, so one-way floor is around 115–155 ms — inside
G.114's "good" band. The p95 runs two to four times the minimum, and that
spread forces a 259–584 ms jitter buffer that every packet then pays.

**Head-of-line blocking is real and visible.** Runs of 23–45 consecutive late
packets mean 460–900 ms of audio arriving in a clump rather than a stream. That
exceeds the p95 buffer depth, so it is audible as a gap followed by a rush —
this is the failure mode UDP voice transports exist to avoid, and TCP-only Tor
cannot avoid it.

**Mouth-to-ear landed at 467–868 ms, median ~755 ms.** ITU-T G.114 calls
anything over 400 ms unacceptable for interactive conversation. For comparison,
a geostationary satellite call runs about 550 ms round trip; this is in that
territory and somewhat worse.

## Verdict

Sub-second and lossless is far better than the 6–20 s the relay-mediated path
would give, and good enough for turn-taking speech. It is not good enough for
full-duplex conversation with interruption: at 750 ms both parties start
talking over each other constantly.

**This is a walkie-talkie, and a decent one. It is not a phone call.**

## Caveats this does not cover

- One machine, one network, one country, at one time of day. Circuit quality
  varies enormously with all four.
- No competing traffic. Void's constant-rate scheduler would be running
  alongside a real call and would make this worse.
- Wired connection. A mobile network adds its own jitter on top.
- A real implementation adds encoder lookahead and OS audio buffers on both
  ends — figure another 50–100 ms beyond the numbers above.
