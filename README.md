# WIP: flowlat

This project aims to measure the latency of TCP connections
(specifically SYN-SYN/ACK) to provide an alternative to plain ICMP ping
monitoring.

Flowlat makes use of eBPF for identifying packets on ingress and egress
of the Linux networking stack.
