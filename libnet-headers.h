/*
 *  $Id: libnet-headers.h,v 1.14 2004/03/11 18:50:20 mike Exp $
 *
 *  libnet-headers.h - Network routine library headers header file
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef __LIBNET_HEADERS_H
#define __LIBNET_HEADERS_H
/**
 * @file libnet-headers.h
 * @brief libnet header information
 */

/**
 * Libnet defines header sizes for every builder function exported.
 */
#define LIBNET_802_1Q_H         0x12    /**< 802.1Q header:       18 bytes */
#define LIBNET_802_1X_H         0x04    /**< 802.1X header:        4 bytes */
#define LIBNET_802_2_H          0x03    /**< 802.2 LLC header:     3 bytes */
#define LIBNET_802_2SNAP_H      0x08    /**< 802.2 LLC/SNAP header:8 bytes */
#define LIBNET_802_3_H          0x0e    /**< 802.3 header:        14 bytes */
#define LIBNET_ARP_H            0x08    /**< ARP header w/o addrs: 8 bytes */
#define LIBNET_ARP_ETH_IP_H     0x1c    /**< ARP w/ ETH and IP:   28 bytes */
#define LIBNET_BGP4_HEADER_H    0x13    /**< BGP header:          19 bytes */
#define LIBNET_BGP4_OPEN_H      0x0a    /**< BGP open header:     10 bytes */
#define LIBNET_BGP4_UPDATE_H    0x04    /**< BGP open header:      4 bytes */
#define LIBNET_BGP4_NOTIFICATION_H 0x02 /**< BGP notif. header:    2 bytes */
#define LIBNET_CDP_H            0x08    /**< CDP header base:      8 bytes */
#define LIBNET_DHCPV4_H         0xf0    /**< DHCP v4 header:     240 bytes */
#define LIBNET_UDP_DNSV4_H      0x0c    /**< UDP DNS v4 header:   12 bytes */
#define LIBNET_TCP_DNSV4_H      0x0e    /**< TCP DNS v4 header:   14 bytes */
#define LIBNET_ETH_H            0x0e    /**< Ethernet header:     14 bytes */
#define LIBNET_FDDI_H           0x15    /**< FDDI header:         21 bytes */
#define LIBNET_ICMPV4_H         0x04    /**< ICMP header base:     4 bytes */
#define LIBNET_ICMPV4_ECHO_H    0x08    /**< ICMP_ECHO header:     8 bytes */
#define LIBNET_ICMPV4_MASK_H    0x0c    /**< ICMP_MASK header:    12 bytes */
#define LIBNET_ICMPV4_UNREACH_H  0x08   /**< ICMP_UNREACH header:  8 bytes */
#define LIBNET_ICMPV4_TIMXCEED_H 0x08   /**< ICMP_TIMXCEED header: 8 bytes */
#define LIBNET_ICMPV4_REDIRECT_H 0x08   /**< ICMP_REDIRECT header: 8 bytes */
#define LIBNET_ICMPV4_TS_H      0x14    /**< ICMP_TIMESTAMP headr:20 bytes */
#define LIBNET_ICMPV6_H         0x08    /**< ICMP6 header base:    8 bytes */
#define LIBNET_IGMP_H           0x08    /**< IGMP header:          8 bytes */
#define LIBNET_IPV4_H           0x14    /**< IPv4 header:         20 bytes */
#define LIBNET_IPV6_H           0x28    /**< IPv6 header:         40 bytes */
#define LIBNET_IPV6_FRAG_H      0x08    /**< IPv6 frag header:     8 bytes */
#define LIBNET_IPV6_ROUTING_H   0x04    /**< IPv6 frag header base:4 bytes */
#define LIBNET_IPV6_DESTOPTS_H  0x02    /**< IPv6 dest opts base:  2 bytes */
#define LIBNET_IPV6_HBHOPTS_H   0x02    /**< IPv6 hop/hop opt base:2 bytes */
#define LIBNET_IPSEC_ESP_HDR_H  0x0c    /**< IPSEC ESP header:    12 bytes */
#define LIBNET_IPSEC_ESP_FTR_H  0x02    /**< IPSEC ESP footer:     2 bytes */
#define LIBNET_IPSEC_AH_H       0x10    /**< IPSEC AH header:     16 bytes */
#define LIBNET_ISL_H            0x1a    /**< ISL header:          26 bytes */
#define LIBNET_GRE_H            0x04    /**< GRE header:           4 bytes */
#define LIBNET_GRE_SRE_H        0x04    /**< GRE SRE header:       4 bytes */
#define LIBNET_MPLS_H           0x04    /**< MPLS header:          4 bytes */
#define LIBNET_OSPF_H           0x10    /**< OSPF header:         16 bytes */
#define LIBNET_OSPF_HELLO_H     0x18    /**< OSPF hello header:   24 bytes */
#define LIBNET_OSPF_DBD_H       0x08    /**< OSPF DBD header:      8 bytes */
#define LIBNET_OSPF_LSR_H       0x0c    /**< OSPF LSR header:     12 bytes */
#define LIBNET_OSPF_LSU_H       0x04    /**< OSPF LSU header:      4 bytes */
#define LIBNET_OSPF_LSA_H       0x14    /**< OSPF LSA header:     20 bytes */
#define LIBNET_OSPF_AUTH_H      0x08    /**< OSPF AUTH header:     8 bytes */
#define LIBNET_OSPF_CKSUM       0x10    /**< OSPF CKSUM header:   16 bytes */
#define LIBNET_OSPF_LS_RTR_H    0x10    /**< OSPF LS RTR header:  16 bytes */
#define LIBNET_OSPF_LS_NET_H    0x08    /**< OSPF LS NET header:   8 bytes */
#define LIBNET_OSPF_LS_SUM_H    0x0c    /**< OSPF LS SUM header:  12 bytes */
#define LIBNET_OSPF_LS_AS_EXT_H 0x10    /**< OSPF LS AS header:   16 bytes */
#define LIBNET_NTP_H            0x30    /**< NTP header:          48 bytes */
#define LIBNET_RIP_H            0x18    /**< RIP header base:     24 bytes */
#define LIBNET_RPC_CALL_H       0x28    /**< RPC header:          40 bytes
                                         * (assuming 8 byte auth header)
                                         */
#define LIBNET_RPC_CALL_TCP_H   0x2c    /**< RPC header:          44 bytes
                                         * (with record marking)
                                         */
#define LIBNET_SEBEK_H          0x30    /* sebek header:          48 bytes */   
#define LIBNET_STP_CONF_H       0x23    /**< STP conf header:     35 bytes */
#define LIBNET_STP_TCN_H        0x04    /**< STP tcn header:       4 bytes */
#define LIBNET_TOKEN_RING_H     0x16    /**< Token Ring header:   22 bytes */
#define LIBNET_TCP_H            0x14    /**< TCP header:          20 bytes */
#define LIBNET_UDP_H            0x08    /**< UDP header:           8 bytes */
#define LIBNET_VRRP_H           0x08    /**< VRRP header:          8 bytes */
#define ETHER_ADDR_LEN 6
/**
 * IEEE 802.1Q (Virtual Local Area Network) VLAN header, static header 
 * size: 18 bytes
 */

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

#ifndef ETHERTYPE_PUP
#define ETHERTYPE_PUP           0x0200  /* PUP protocol */
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP           0x0806  /* addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP        0x8035  /* reverse addr. resolution protocol */
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN          0x8100  /* IEEE 802.1Q VLAN tagging */
#endif
#ifndef ETHERTYPE_EAP
#define ETHERTYPE_EAP           0x888e  /* IEEE 802.1X EAP authentication */
#endif
#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS          0x8847  /* MPLS */
#endif
#ifndef ETHERTYPE_LOOPBACK
#define ETHERTYPE_LOOPBACK      0x9000  /* used to test interfaces */
#endif

struct libnet_ether_addr
{
    u_int8_t  ether_addr_octet[6];        /* Ethernet address */
};

/*
 *  Fiber Distributed Data Interface header
 *
 *  Static header size: 21 bytes (LLC and 48-bit address addr only)
 *
 *  Note: Organization field is 3 bytes which throws off the
 *        alignment of type.  Therefore fddi_type (19 bytes in) 
 *        is specified as two u_int8_ts.
 */

struct libnet_ipv4_hdr
{
/*
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      // header length 
           ip_v:4;         //version
#endif
*/
//#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
//#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/*
 *  IP options
 */
#ifndef IPOPT_EOL
#define IPOPT_EOL       0   /* end of option list */
#endif
#ifndef IPOPT_NOP
#define IPOPT_NOP       1   /* no operation */
#endif   
#ifndef IPOPT_RR
#define IPOPT_RR        7   /* record packet route */
#endif
#ifndef IPOPT_TS
#define IPOPT_TS        68  /* timestamp */
#endif
#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY  130 /* provide s,c,h,tcc */   
#endif
#ifndef IPOPT_LSRR
#define IPOPT_LSRR      131 /* loose source route */
#endif
#ifndef IPOPT_SATID
#define IPOPT_SATID     136 /* satnet id */
#endif
#ifndef IPOPT_SSRR
#define IPOPT_SSRR      137 /* strict source route */
#endif

struct libnet_in6_addr
{
    union
    {
        u_int8_t   __u6_addr8[16];
        u_int16_t  __u6_addr16[8];
        u_int32_t  __u6_addr32[4];
    } __u6_addr;            /* 128-bit IP6 address */
};
#define libnet_s6_addr __u6_addr.__u6_addr8

/*
 *  IPv6 header
 *  Internet Protocol, version 6
 *  Static header size: 40 bytes
 */
struct libnet_ipv6_hdr
{
    u_int8_t ip_flags[4];     /* version, traffic class, flow label */
    u_int16_t ip_len;         /* total length */
    u_int8_t ip_nh;           /* next header */
    u_int8_t ip_hl;           /* hop limit */
    struct libnet_in6_addr ip_src, ip_dst; /* source and dest address */

};

/*
 *  IPv6 frag header
 *  Internet Protocol, version 6
 *  Static header size: 8 bytes
 */
#define LIBNET_IPV6_NH_FRAGMENT 44
struct libnet_ipv6_frag_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_reserved;    /* reserved */
    u_int16_t ip_frag;       /* fragmentation stuff */
    u_int32_t ip_id;         /* id */
};

/*
 *  IPv6 routing header
 *  Internet Protocol, version 6
 *  Base header size: 4 bytes
 */
#define LIBNET_IPV6_NH_ROUTING  43
struct libnet_ipv6_routing_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    u_int8_t ip_rtype;       /* routing type */
    u_int8_t ip_segments;    /* segments left */
    /* routing information allocated dynamically */
};

/*
 *  IPv6 destination options header
 *  Internet Protocol, version 6
 *  Base header size: 2 bytes
 */
#define LIBNET_IPV6_NH_DESTOPTS 60
struct libnet_ipv6_destopts_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    /* destination options information allocated dynamically */
};

/*
 *  IPv6 hop by hop options header
 *  Internet Protocol, version 6
 *  Base header size: 2 bytes
 */
#define LIBNET_IPV6_NH_HBH      0
struct libnet_ipv6_hbhopts_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    /* destination options information allocated dynamically */
};

/*
 *  ICMP6 header
 *  Internet Control Message Protocol v6
 *  Base header size: 8 bytes
 */
#ifndef IPPROTO_ICMP6
#define IPPROTO_ICMP6   0x3a
#endif
struct libnet_icmpv6_hdr
{
    u_int8_t icmp_type;       /* ICMP type */
#ifndef ICMP6_ECHO
#define ICMP6_ECHO          128
#endif
#ifndef ICMP6_ECHOREPLY
#define ICMP6_ECHOREPLY     129
#endif
#ifndef ICMP6_UNREACH
#define ICMP6_UNREACH       1
#endif
#ifndef ICMP6_PKTTOOBIG
#define ICMP6_PKTTOOBIG     2
#endif
#ifndef ICMP6_TIMXCEED
#define ICMP6_TIMXCEED      3
#endif
#ifndef ICMP6_PARAMPROB
#define ICMP6_PARAMPROB     4
#endif
    u_int8_t icmp_code;       /* ICMP code */
    u_int16_t icmp_sum;       /* ICMP Checksum */
    u_int16_t id;             /* ICMP id */
    u_int16_t seq;            /* ICMP sequence number */
};

/*
 *  RPC headers
 *  Remote Procedure Call
 */
#define LIBNET_RPC_CALL  0
#define LIBNET_RPC_REPLY 1
#define LIBNET_RPC_VERS  2
#define LIBNET_RPC_LAST_FRAG 0x80000000

/*
 *  Portmap defines
 */
#define LIBNET_PMAP_PROGRAM          100000
#define LIBNET_PMAP_PROC_NULL        0
#define LIBNET_PMAP_PROC_SET         1
#define LIBNET_PMAP_PROC_UNSET       2
#define LIBNET_PMAP_PROC_GETADDR     3
#define LIBNET_PMAP_PROC_DUMP        4
#define LIBNET_PMAP_PROC_CALLIT      5
#define LIBNET_PMAP_PROC_BCAST       5 /* Not a typo */
#define LIBNET_PMAP_PROC_GETTIME     6
#define LIBNET_PMAP_PROC_UADDR2TADDR 7
#define LIBNET_PMAP_PROC_TADDR2UADDR 8
#define LIBNET_PMAP_PROC_GETVERSADDR 9
#define LIBNET_PMAP_PROC_INDIRECT    10
#define LIBNET_PMAP_PROC_GETADDRLIST 11
#define LIBNET_PMAP_PROC_GETSTAT     12

/* There will be more to add... */


/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */

#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};
#endif  /* __LIBNET_HEADERS_H */

/* EOF */
