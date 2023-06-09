#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// Simple BPF program that prints a message when a packet is received
SEC("filter")
int bpf_filter(struct __sk_buff *skb) {
    bpf_trace_printk("Packet received\n");
    return XDP_PASS;
}
