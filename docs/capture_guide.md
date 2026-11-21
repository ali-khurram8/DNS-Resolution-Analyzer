# Capture guide: what each trace shows and how to annotate it

The traces are made by `python scripts/capture_evidence.py` and saved in `captures/evidence/`. Annotated Wireshark screenshots of every trace, made with the filters below, are in `captures/screenshots/wireshark/`. To take more by hand:

1. Open the trace in Wireshark.
2. Apply the filter given below.
3. Select the key packet and expand the fields named below.
4. Take a screenshot and add arrows or boxes and a short label (Windows Snipping Tool or any image editor works).

For DoT and DoH, open the `*_with_keys.pcapng` copy. It carries the TLS secrets, so Wireshark decrypts it automatically. To show the "before" view, open the plain file, or remove the key log in *Edit → Preferences → Protocols → TLS*.

| # | File | Display filter | Packets to highlight | Fields to expand and annotate |
|---|---|---|---|---|
| 1 | `01_icmp_ping_traceroute` | `icmp` | Echo request/reply; Time Exceeded from 10.10.3.1 (R2) and 10.10.2.1 (R1); Port Unreachable from 10.10.1.10 | IP TTL (64 → 62 at the root: two routers), ICMP type/code |
| 2 | `02_iterative_do53_udp` | `dns` | 3 query/response pairs: client → .10 → .11 → .12 | UDP src port (ephemeral) / dst port 53; Transaction ID; Flags: QR, **RD=0**, **AA=0** in referrals and **AA=1** in the final answer; Authority NS + Additional glue A |
| 3 | `03_missing_glue_sublookup` | `dns` | Referral for `noglue.lab` with **Additional RRs: 0**; queries for `ns.example.lab`; final answer | Answer/Authority/Additional counts; NS `ns.example.lab` without an A record |
| 4 | `04_truncation_tcp53_fallback` | `dns \|\| tcp.port==53` | UDP reply with **TC=1**; TCP SYN/SYN-ACK/ACK to port 53; TCP response with length prefix | Flags.Truncated; TCP flags; "Length" field of DNS over TCP |
| 5 | `05_recursive_do53_client_unbound` | `dns` | Query RD=1 and response RA=1 between 10.10.3.10 and 10.10.4.10 | Plaintext query name and answer address, readable on the path |
| 5b | `05b_unbound_upstream_recursion` | `dns` | Unbound's own queries to .10, .11, .12 after the cache flush | Shows the recursive resolver doing the iteration for the client |
| 6 | `06_dot_tls13_port853` (+`_with_keys`) | `tcp.port==853` | SYN/SYN-ACK/ACK, ClientHello, ServerHello, Application Data | TLS version 1.3 (supported_versions), cipher suite; plain file shows only "Application Data"; keyed file shows **DNS** inside |
| 7 | `07_doh_tls13_http2_port443` (+`_with_keys`) | `tcp.port==443` | TCP handshake, ClientHello with ALPN `h2`, HTTP/2 SETTINGS, HEADERS, DATA | `:method POST`, `:path /dns-query`, `content-type: application/dns-message`; DNS in the DATA frame |
| 8 | `08_loss_udp_retry_vs_tcp_retransmit` | `dns.retransmission \|\| tcp.analysis.retransmission` | DNS query resent after the 1 s UDP timeout (same ID); TCP retransmissions in the DoT session | `dns.retransmit_request`, `dns.time`; TCP "Retransmission" expert info |

## Useful Wireshark views

* *Statistics → Conversations → IPv4/UDP/TCP*: bytes per transport (the bytes-per-query metric).
* *Statistics → Flow Graph* with "Limit to display filter": a ladder diagram of the iterative path and of the TLS handshake round trips.
* Column suggestions: add `dns.flags.authoritative`, `dns.flags.truncated`, `dns.id` and `tcp.stream` as columns (right-click the field → *Apply as Column*).
* Name resolution off (*View → Name Resolution*) so that IP addresses are shown.

## Experiment captures

Each experiment run is also captured as `captures/experiments/<condition>_run<N>.pcapng`, with its key log in `captures/experiments/keys/`. `experiments/measure.py` analyses these files with tshark:

* bytes per session;
* the SYN → first DNS query interval, divided by the SYN → SYN-ACK RTT, which gives the handshake round trips;
* the packets up to the first DNS response;
* the wire time of each iterative lookup, which cross-checks the resolver's own timer.
