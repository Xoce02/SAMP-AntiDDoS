# SAMP-AntiDDoS

XDP/eBPF filter for SA-MP and open.mp servers.

This is the public Lite version of the SA-MP filtering work I use around Hostly. The goal is simple: reject bad UDP early, validate the SA-MP connection cookie, and keep obviously invalid traffic away from the game process.

**Developed by Xoce, member of Hostly US, LLC.**

Hostly: https://hostly.network/

> **SAMP-AntiDDoS Lite**
>
> Standalone XDP/eBPF filtering for SA-MP/open.mp.
> The extended Hostly stack adds Hostly Edge, multi-service dispatching,
> query caching and additional filtering layers.

---

## At a glance

- Runs at XDP before packets reach the game process
- Validates the SA-MP/open.mp connection cookie
- Tracks established flows
- Drops malformed and unknown UDP
- Filters SA-MP queries
- Uses a short retry cooldown for pending handshakes
- No blanket rate limit on established gameplay traffic
- Designed as a single-port standalone filter

---

## Quick Start

Clone the repository:

```bash
git clone https://github.com/Xoce02/SAMP-AntiDDoS.git
cd SAMP-AntiDDoS
```

Install the required packages on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev iproute2 linux-headers-$(uname -r)
```

Find your network interface:

```bash
ip -br link
```

Attach the filter to UDP/7777 using native XDP:

```bash
sudo bash scripts/load.sh eth0 7777 drv
```

Verify that XDP is attached:

```bash
ip -details link show dev eth0
```

If your server uses another interface such as `ens18` or `enp1s0`, replace `eth0` with the correct name.

---

## Status / Scope

This repository is the public Lite version.

It is intended to stay small enough to read, modify and deploy on a single SA-MP/open.mp service without requiring Hostly's full network stack.

The Lite build focuses on:

- handshake and cookie validation;
- flow tracking;
- malformed/unknown UDP filtering;
- basic query filtering;
- simple standalone deployment.

The Hostly implementation adds the parts that make sense at network/hosting scale, including Hostly Edge, multiple service mappings, dispatcher logic, cached query replies and centralized rule management.

---

## What the Lite filter does

The filter attaches to a Linux network interface and protects one UDP destination port.

It handles:

- IPv4 and UDP length checks;
- malformed packet drops;
- IPv4 fragment drops on the protected port;
- basic bogon/reflection-source filtering;
- SA-MP/open.mp 4-byte connection handshake validation;
- cookie challenge before a new flow is accepted;
- a short cooldown when the same pending handshake is repeated;
- established-flow tracking;
- basic SA-MP query validation;
- drops for unsupported/malformed query opcodes;
- fast drops for UDP that does not belong to a validated flow.

There is no blanket PPS limit on established gameplay traffic.

### Connection validation

A new client does not immediately get normal access to the game server.

```text
client
  |
  |  SA-MP handshake
  v
XDP
  |
  |-- invalid --------------------------> DROP
  |
  |-- valid ----------------------------> cookie challenge
  |                                         |
  |<----------------------------------------'
  |
  |  valid cookie
  v
ESTABLISHED
  |
  v
SA-MP / open.mp
```

For example, repeatedly sending the same initial 4-byte packet is not enough to become an established flow.

The first valid handshake gets a challenge. Fast repeats of the same pending handshake are dropped during the retry cooldown instead of generating a new reply every time.

---

## Queries

Lite checks the structure of SA-MP queries.

```text
valid i / p query  -> PASS
r / c / d / x      -> DROP
malformed query    -> DROP
unknown opcode     -> DROP
```

Valid `i` and `p` queries still reach SA-MP/open.mp in the Lite version.

---

## What Lite does not do

Lite is not the complete Hostly filter and it is not meant to be one.

### Valid query floods still reach the backend

Because Lite passes valid `i` and `p` queries, a flood made entirely of correctly formed queries can still consume resources in the game server.

The full Hostly SA-MP profile can answer cached public queries before they reach the SA-MP process.

### A bot that completes the cookie is no longer just a spoofed flood

If a bot completes the cookie correctly and continues far enough into the protocol for SA-MP/open.mp to create connection state or reserve a player slot, Lite does not try to decide whether that client is human.

That requires additional connection/session logic and, depending on the protection being used, server-side integration.

Those controls belong to the full Hostly stack, not this public Lite filter.

### One port, one standalone filter

Lite does not include Hostly's service dispatcher.

It does not provide:

- multiple IP:port mappings in one profile;
- per-service profile assignment;
- centralized firewall rules;
- Firewall Manager integration;
- Hostly Edge policy management;
- query cache/refresher logic;
- hosting-node telemetry.

### XDP cannot fix a saturated uplink

XDP runs after traffic reaches the Linux host.

If an attack fills the physical uplink before packets reach XDP, the host cannot recover that bandwidth by dropping packets locally.

That is one of the reasons the complete Hostly setup also uses **Hostly Edge** and upstream DDoS capacity.

---

## Lite vs Hostly

| Feature | Lite | Hostly |
| --- | :---: | :---: |
| XDP/eBPF filtering | Basic | Advanced |
| SA-MP/open.mp cookie validation | Yes | Advanced |
| Established-flow tracking | Basic | Advanced |
| Handshake retry cooldown | Yes | Tuned / profile-based |
| Malformed UDP filtering | Yes | Advanced |
| Bogon / reflection filtering | Basic | Extended |
| Query validation | Basic | Advanced |
| Cached query replies from XDP | No | XDP-cached |
| Valid query flood isolation | No | Backend-isolated |
| Multiple protected IP:port services | No | Multi-service |
| Service/profile dispatcher | No | XDP dispatcher |
| Per-service firewall rules | No | Per-service policies |
| Firewall Manager integration | No | Centralized |
| Hostly Edge filtering / routing | No | Edge-managed |
| Post-cookie / session controls | No | Extended / deployment-specific |

The Lite version is useful for a single SA-MP/open.mp service and for people who want a small XDP filter they can read and modify.

The Hostly version is built around hosting infrastructure where several protected services can share the same network and filtering stack.

---

## How the Hostly path is different

Hostly does not rely on a single filter running on the customer's server.

The main filtering layer can live at **Hostly Edge**, before traffic is routed to the protected node or service.

A simplified path looks like this:

```text
Internet
   |
   v
Upstream / Scrubbing
   |
   v
Hostly Edge
   |
   |-- XDP dispatcher
   |-- SA-MP / open.mp profile
   |-- Minecraft / RakNet profile
   |-- FiveM profile
   |-- Generic UDP/TCP profiles
   |-- Etc.
   |
   v
Routing
   |
   v
Hostly Nodes
   |
   `-- local XDP as second layer
          |
          v
Game Servers / VPS / Dedicated Servers
```

At Hostly Edge, the dispatcher can select a protection profile based on the service being protected before the traffic is routed to the backend.

For SA-MP/open.mp, that profile can include:

- cookie and flow validation;
- query filtering and cached query replies;
- XDP_TX responses;
- per-service rules;
- multiple protected IP:port mappings;
- connection-state controls;
- centralized Firewall Manager integration.

A local XDP program on the destination node can still be used as an additional layer, but it is not the only place where filtering can happen.

The public Lite version in this repository is intentionally much simpler:

```text
Internet
   |
   v
Linux server
   |
   v
xdp_samp.c
   |
   v
SA-MP / open.mp
```

More information:

**https://hostly.network/**

---

## Requirements

Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev iproute2 linux-headers-$(uname -r)
```

Native/driver XDP is preferred when the NIC and driver support it.

---

## Find your network interface

The interface name is different on every system.

Common examples:

```text
eth0
ens3
ens18
enp1s0
enp39s0
```

List interfaces:

```bash
ip -br link
```

To see which interface Linux normally uses for outbound traffic:

```bash
ip route get 1.1.1.1
```

Look for `dev <interface>`.

Example:

```text
1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.10
```

Here the interface is `eth0`.

---

## Install

Protect UDP/7777 using native XDP:

```bash
sudo bash scripts/load.sh eth0 7777 drv
```

Another server might use `ens18`:

```bash
sudo bash scripts/load.sh ens18 7777 drv
```

Generic XDP fallback:

```bash
sudo bash scripts/load.sh eth0 7777 generic
```

Remove the filter:

```bash
sudo bash scripts/unload.sh eth0
```

Check the interface:

```bash
ip -details link show dev eth0
```

Compile only:

```bash
make PORT=7777
```

The port can be changed at build/load time. It is not hardcoded to 7777.

---

## Files

```text
xdp_samp.c          XDP filter
Makefile            build file
scripts/load.sh     build + attach helper
scripts/unload.sh   detach helper
LICENSE             license
```

---

## Troubleshooting

### Native XDP does not attach

Some virtual NICs and network drivers do not support native XDP.

Try generic mode:

```bash
sudo bash scripts/load.sh eth0 7777 generic
```

### Wrong interface

List the interfaces:

```bash
ip -br link
```

Or check the route Linux normally uses:

```bash
ip route get 1.1.1.1
```

Use the interface shown after `dev`.

### An XDP program is already attached

The loader refuses to replace another XDP program automatically.

Check the interface first:

```bash
ip -details link show dev eth0
```

Detach only if you know the existing program can be removed:

```bash
sudo bash scripts/unload.sh eth0
```

Then load SAMP-AntiDDoS again.

---

## Notes

The loader refuses to silently replace an XDP program that is already attached to the selected interface.

Performance depends on the CPU, NIC, driver, RSS/queue distribution, packet size and attack pattern. There is intentionally no fixed PPS or Gbps claim in this repository.

Test the filter on your own setup before putting it on a live game server.

---

## License

MIT License.

Copyright (c) 2026 Xoce.

Original project by **Xoce, member of Hostly US, LLC.**

Hostly Network: https://hostly.network/
