#include <stdint.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("classifier")
int probe(struct __sk_buff *skb) {
  if (bpf_skb_pull_data(skb, 0) < 0) {
    return TC_ACT_OK;
  }

  uint8_t *head = (uint8_t *)(long)skb->data;
  uint8_t *tail = (uint8_t *)(long)skb->data_end;

  if (head + sizeof(struct ethhdr) > tail) {
    return TC_ACT_OK;
  }

  struct ethhdr *eth = (void *)head;

  uint32_t offset;

  switch (bpf_ntohs(eth->h_proto)) {
  case ETH_P_IP:
    offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (head + offset > tail) {
      return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)head + sizeof(struct ethhdr);
    if (ip->protocol != IPPROTO_TCP) {
      return TC_ACT_OK;
    }
    break;
  case ETH_P_IPV6:
    offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

    if (head + offset > tail) {
      return TC_ACT_OK;
    }

    struct ipv6hdr *ip6 = (void *)head + sizeof(struct ethhdr);
    if (ip6->nexthdr != IPPROTO_TCP) {
      return TC_ACT_OK;
    }
    break;
  default:
    return TC_ACT_OK;
  }

  if (head + offset + sizeof(struct tcphdr) > tail) {
    return TC_ACT_OK;
  }

  struct tcphdr *tcp = (void *)head + offset;

  if (tcp->syn) {
    bpf_printk("GOT SYN\n");
  } else if (tcp->ack) {
    bpf_printk("GOT ACK\n");
  }
  return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
