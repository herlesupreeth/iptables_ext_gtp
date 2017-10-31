
/*
 * GTPu klm for Linux/iptables
 *
 * Copyright (c) 2010-2011 Polaris Networks
 * Author: Pradip Biswas <pradip_biswas@polarisnetworks.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/route.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/inet_sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#if 0
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#endif

#include "xt_GTPU.h"

#if !(defined KVERSION)
#error "Kernel version is not defined!!!! Exiting."
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pradip Biswas <pradip_biswas@polarisnetworks.net>");
MODULE_DESCRIPTION("GTPu Data Path extension on netfilter");


struct gtpuhdr
{
    char flags;
    char msgtype;
    u_int16_t length;
    u_int32_t tunid;
};

#define GTPU_HDR_PNBIT 1
#define GTPU_HDR_SBIT 1 << 1
#define GTPU_HDR_EBIT 1 << 2
#define GTPU_ANY_EXT_HDR_BIT (GTPU_HDR_PNBIT | GTPU_HDR_SBIT | GTPU_HDR_EBIT)

#define GTPU_FAILURE 1
#define GTPU_SUCCESS !GTPU_FAILURE

#define GTPU_PORT 2152

static bool _gtpu_route_packet(struct sk_buff *skb, const struct xt_gtpu_target_info *info)
{
    int err = 0;
    struct rtable *rt = skb_rtable(skb);
    struct net *init_net = dev_net(rt->dst.dev);
    struct iphdr *iph = ip_hdr(skb);

    struct flowi4 fl;
    __be32 daddr, saddr;

    u32 mark = IP4_REPLY_MARK(init_net, skb->mark);
    daddr = iph->saddr;
    //saddr = fib_compute_spec_dst(skb);

    memset(&fl, 0, sizeof(fl));
    fl.daddr = daddr;
    //fl.saddr = saddr;
    fl.flowi4_mark = mark;
    fl.flowi4_tos = RT_TOS(iph->tos);
    fl.flowi4_oif = l3mdev_master_ifindex(skb->dev);

    // struct flowi4 fl = {
    //     .daddr = daddr,
    //     .saddr = saddr,
    //     .__fl_common.flowic_tos = RT_TOS(iph->tos),
    //     .__fl_common.flowic_scope = RT_SCOPE_UNIVERSE,
    // };

#if 0
    pr_info("GTPU(%d): Routing packet. 0x%08x --> 0x%08x. Proto: %d, Len: %d\n",
            info->action, ntohl(iph->saddr), ntohl(iph->daddr), iph->protocol, ntohs(iph->tot_len));
#endif

    /* Get the route using the standard routing table. */
    // err = ip_route_output_key(init_net, &fl);

    // if (err != 0)
    // {
    //     pr_info("GTPU: Failed to route packet to dst 0x%x. Error: (%d)", fl.daddr, err);
    //     return GTPU_FAILURE;
    // }

    /* Get the route using the standard routing table. */
    rt = ip_route_output_key(init_net, &fl);

    if (IS_ERR(rt))
    {
        pr_info("GTPU: Failed to route packet to dst 0x%x", fl.daddr);
        return GTPU_FAILURE;
    }

#if 0
    if (rt->u.dst.dev)
    {
        pr_info("GTPU: dst dev name %s\n", rt->u.dst.dev->name);
    }
    else
    {
        pr_info("GTPU: dst dev NULL\n");
    }
#endif

    /*if (info->action == PARAM_GTPU_ACTION_ADD)*/
    {
// #if (KVERSION > 28)
    skb_dst_drop(skb);
    // skb_dst_set(skb, &rt->u.dst);
    skb_dst_set(skb, &rt->dst);
    skb->dev      = skb_dst(skb)->dev;
// #else
//     if (skb->dst)
//     {
//         dst_release(skb->dst);
//         skb->dst = 0UL;
//     }
//     skb->dst = &rt->u.dst;
//     skb->dev = skb->dst->dev;
// #endif
    }

    skb->protocol = htons(ETH_P_IP);

    /* Send the GTPu message out...gggH */
    // err = dst_output(skb, );
    err = dst_output(init_net, skb->sk, skb);

    if (err == 0)
    {
        return GTPU_SUCCESS;
    }
    else
    {
        return GTPU_FAILURE;
    }
}

static unsigned int
_gtpu_target_add(struct sk_buff *skb, const struct xt_gtpu_target_info *tgi)
{
    struct iphdr *iph = ip_hdr(skb);
    struct udphdr *udph = NULL;
    struct gtpuhdr *gtpuh = NULL;
    struct sk_buff *new_skb = NULL;
    int headroom_reqd =  sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtpuhdr);
    int orig_iplen = 0, udp_len = 0, ip_len = 0;

    /* Keep the length of the source IP packet */
    orig_iplen = ntohs(iph->tot_len);

    /* Create a new copy of the original skb...can't avoid :-( */
    new_skb = skb_copy_expand(skb, headroom_reqd + skb_headroom(skb), skb_tailroom(skb), GFP_ATOMIC);
    if (new_skb == NULL)
    {
        return NF_ACCEPT;
    }

    /* Add GTPu header */
    gtpuh = (struct gtpuhdr*)skb_push(new_skb, sizeof(struct gtpuhdr));
    gtpuh->flags = 0x38; /* v1 and Protocol-type=GTP */
    gtpuh->msgtype = 0xff; /* T-PDU */
    gtpuh->length = htons(orig_iplen);
    gtpuh->tunid = htonl(tgi->rtun);

    /* Add UDP header */
    udp_len = sizeof(struct udphdr) + sizeof(struct gtpuhdr) + orig_iplen;
    udph = (struct udphdr*)skb_push(new_skb, sizeof(struct udphdr));
    udph->source = htons(GTPU_PORT);
    udph->dest = htons(GTPU_PORT);
    udph->len = htons(udp_len);
    udph->check = 0;
    udph->check = csum_tcpudp_magic(tgi->laddr, tgi->raddr, udp_len, IPPROTO_UDP, csum_partial((char*)udph, udp_len, 0));
    skb_set_transport_header(new_skb, 0);

    /* Add IP header */
    ip_len = udp_len + sizeof(struct iphdr);
    iph = (struct iphdr*)skb_push(new_skb, sizeof(struct iphdr));
    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 0;
    iph->tot_len  = htons(ip_len);
    iph->id       = 0;
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check    = 0;
    iph->saddr    = (tgi->laddr);
    iph->daddr    = (tgi->raddr);
    iph->check    = ip_fast_csum((unsigned char *)iph, iph->ihl);
    skb_set_network_header(new_skb, 0);

    /* Route the packet */
    if (_gtpu_route_packet(new_skb, tgi) == GTPU_SUCCESS)
    {
        /* Succeeded. Drop the original packet */
        return NF_DROP;
    }
    else
    {
        kfree_skb(new_skb);
        return NF_ACCEPT; /* What should we do here ??? ACCEPT seems to be the best option */
    }
}

static unsigned int
_gtpu_target_rem(struct sk_buff *orig_skb, const struct xt_gtpu_target_info *tgi)
{
    struct iphdr *iph = ip_hdr(orig_skb);
    struct gtpuhdr *gtpuh = NULL;
    struct sk_buff *skb = NULL;

    /* Create a new copy of the original skb...can't avoid :-( */
    skb = skb_copy(orig_skb, GFP_ATOMIC);
    if (skb == NULL)
    {
        return NF_ACCEPT;
    }

#if 0
    pr_info("GTPU(%d): Routing packet. 0x%08x --> 0x%08x. Proto: %d, Len: %d\n",
            tgi->action, ntohl(iph->saddr), ntohl(iph->daddr), iph->protocol, ntohs(iph->tot_len));
#endif

    /* Remove IP header */
    skb_pull(skb, (iph->ihl << 2));

    /* Remove UDP header */
    gtpuh = (struct gtpuhdr*)skb_pull(skb, sizeof(struct udphdr));

    /* Remove GTPu header */
    skb_pull(skb, sizeof(struct gtpuhdr));

    /* If additional fields are present in header, remove them also */
    if (gtpuh->flags & GTPU_ANY_EXT_HDR_BIT)
    {
        skb_pull(skb, sizeof(short) + sizeof(char) + sizeof(char)); /* #Seq, #N-PDU, #ExtHdr Type */
    }
    skb_set_network_header(skb, 0);
    skb_set_transport_header(skb, 0);

    /* Route the packet */
    _gtpu_route_packet(skb, tgi);

    return NF_DROP;
}

static unsigned int
xt_gtpu_target(struct sk_buff *skb, const struct xt_action_param *par)
{
    const struct xt_gtpu_target_info *tgi = par->targinfo;
    int result = NF_ACCEPT;

    if (tgi == NULL)
    {
        return result;
    }

    if (tgi->action == PARAM_GTPU_ACTION_ADD)
    {
        result = _gtpu_target_add(skb, tgi);
    }
    else if (tgi->action == PARAM_GTPU_ACTION_REM)
    {
        result = _gtpu_target_rem(skb, tgi);
    }
    else if (tgi->action == PARAM_GTPU_ACTION_TRANSPORT)
    {
    }

    return result;
}

static struct xt_target xt_gtpu_reg __read_mostly =
{
    .name           = "GTPU",
    .family         = AF_INET,
    .table          = "mangle",
    .target         = xt_gtpu_target,
    .targetsize     = sizeof(struct xt_gtpu_target_info),
    .me             = THIS_MODULE,
};

static int __init xt_gtpu_init(void)
{
    pr_info("GTPU: Initializing module (KVersion: %d)\n", KVERSION);
    pr_info("GTPU: Copyright Polaris Networks 2010-2011\n");
    return xt_register_target(&xt_gtpu_reg);
}

static void __exit xt_gtpu_exit(void)
{
    xt_unregister_target(&xt_gtpu_reg);
    pr_info("GTPU: Unloading module\n");
}

module_init(xt_gtpu_init);
module_exit(xt_gtpu_exit);

