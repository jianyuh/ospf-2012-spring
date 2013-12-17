/* 
 * File:   libnet.h
 * Author: root
 *
 * Created on May 12, 2012, 3:05 PM
 */



#ifndef LIBNET_H
#define	LIBNET_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdint.h>
#include <netinet/in.h>
    
/* used internally for checksum stuff */
#define LIBNET_CKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

/* used interally for OSPF stuff */
#define LIBNET_OSPF_AUTHCPY(x, y) \
    memcpy((uint8_t *)x, (uint8_t *)y, sizeof(y))
#define LIBNET_OSPF_CKSUMBUF(x, y) \
    memcpy((uint8_t *)x, (uint8_t *)y, sizeof(y))  
    

#define LIBNET_LIL_ENDIAN 1
    
/**
 * Used for libnet's name resolution functions, specifies that no DNS lookups
 * should be performed and the IP address should be kept in numeric form.
 */
#define LIBNET_DONT_RESOLVE 0    
    
    
/**
 * Used for libnet's name resolution functions, specifies that a DNS lookup
 * can be performed if needed to resolve the IP address to a canonical form.
 */
#define LIBNET_RESOLVE      1
    
    
#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF    89  /* not everyone's got this */
#endif
#define IPPROTO_OSPF_LSA    890     /* made this up.  Hope it's unused */
#define LIBNET_MODX         4102    /* used in LSA checksum */    
    
    
/**
 * The biggest an IP packet can be -- 65,535 bytes.
 */
#define LIBNET_MAX_PACKET   0xffff
#ifndef IP_MAXPACKET
#define IP_MAXPACKET        0xffff
#endif
    
#define STD_IPV4_H           0x14    /**< IPv4 header:         20 bytes */
    
#define STD_OSPF_H           0x10    /**< OSPF header:         16 bytes */
#define STD_OSPF_HELLO_H     0x18    /**< OSPF hello header:   24 bytes */
#define STD_OSPF_DBD_H       0x08    /**< OSPF DBD header:      8 bytes */
#define STD_OSPF_LSR_H       0x0c    /**< OSPF LSR header:     12 bytes */
#define STD_OSPF_LSU_H       0x04    /**< OSPF LSU header:      4 bytes */
#define STD_OSPF_LSA_H       0x14    /**< OSPF LSA header:     20 bytes */
#define STD_OSPF_AUTH_H      0x08    /**< OSPF AUTH header:     8 bytes */
#define STD_OSPF_CKSUM       0x10    /**< OSPF CKSUM header:   16 bytes */
#define STD_OSPF_LS_RTR_H    0x10    /**< OSPF LS RTR header:  16 bytes */
#define STD_OSPF_LS_NET_H    0x08    /**< OSPF LS NET header:   8 bytes */
#define STD_OSPF_LS_SUM_H    0x0c    /**< OSPF LS SUM header:  12 bytes */
#define STD_OSPF_LS_AS_EXT_H 0x10    /**< OSPF LS AS header:   16 bytes */
    
    
/* context queue macros and constants */
#define STD_LABEL_SIZE   64
#define STD_LABEL_DEFAULT "cardshark"
#define CQ_LOCK_UNLOCKED    (u_int)0x00000000
#define CQ_LOCK_READ        (u_int)0x00000001
#define CQ_LOCK_WRITE       (u_int)0x00000002
    
    
    

/**
 * The libnet error buffer is 256 bytes long.
 */ 
#define STD_ERRBUF_SIZE      0x100
    
    
    
/*
 *  Libnet ptags are how we identify specific protocol blocks inside the
 *  list.
 */
typedef int32_t std_ptag_t;
#define STD_PTAG_INITIALIZER         0    
    

#define STD_DO_PAYLOAD(l, p)                                              \
if (payload_s && !payload)                                                   \
{                                                                            \
    snprintf(l->err_buf, STD_ERRBUF_SIZE,                                 \
            "%s(): payload inconsistency\n", __func__);                      \
    goto bad;                                                                \
}                                                                            \
if (payload_s)                                                               \
{                                                                            \
    n = std_pblock_append(l, p, payload, payload_s);                      \
    if (n == (uint32_t) - 1)                                                 \
    {                                                                        \
        goto bad;                                                            \
    }                                                                        \
}                                                                            \

/*
 *  Libnet generic protocol block memory object.  Sort of a poor man's mbuf.
 */
struct std_protocol_block
{
    uint8_t *buf;                      /* protocol buffer */
    uint32_t b_len;                    /* length of buf */
    uint16_t h_len;                    /* header length */
       /* Passed as last argument to std_do_checksum(). Not necessarily used
        * by that function, it is essentially a pblock specific number, passed
        * from _builder to the _do_checksum
        *
        * Unused for IPV4_H block types.
        *
        * For protocols that sit on top of IP, it should be the the amount of
        * buf that will be included in the checksum, starting from the beginning
        * of the header.
        */
    uint32_t copied;                   /* bytes copied - the amount of data copied into buf */
       /* Used and updated by std_pblock_append(). */
    uint8_t type;                      /* type of pblock */
/* this needs to be updated every time a new packet builder is added */
/* std_diag_dump_pblock_type() also needs updating for every new pblock tag */
#define LIBNET_PBLOCK_ARP_H             0x01    /* ARP header */
#define LIBNET_PBLOCK_DHCPV4_H          0x02    /* DHCP v4 header */
#define LIBNET_PBLOCK_DNSV4_H           0x03    /* DNS v4 header */
#define LIBNET_PBLOCK_ETH_H             0x04    /* Ethernet header */
#define LIBNET_PBLOCK_ICMPV4_H          0x05    /* ICMP v4 base header */
#define LIBNET_PBLOCK_ICMPV4_ECHO_H     0x06    /* ICMP v4 echo header */
#define LIBNET_PBLOCK_ICMPV4_MASK_H     0x07    /* ICMP v4 mask header */
#define LIBNET_PBLOCK_ICMPV4_UNREACH_H  0x08    /* ICMP v4 unreach header */
#define LIBNET_PBLOCK_ICMPV4_TIMXCEED_H 0x09    /* ICMP v4 exceed header */
#define LIBNET_PBLOCK_ICMPV4_REDIRECT_H 0x0a    /* ICMP v4 redirect header */
#define LIBNET_PBLOCK_ICMPV4_TS_H       0x0b    /* ICMP v4 timestamp header */
#define LIBNET_PBLOCK_IGMP_H            0x0c    /* IGMP header */
#define LIBNET_PBLOCK_IPV4_H            0x0d    /* IP v4 header */
#define LIBNET_PBLOCK_IPO_H             0x0e    /* IP v4 options */
#define LIBNET_PBLOCK_IPDATA            0x0f    /* IP data */
#define LIBNET_PBLOCK_OSPF_H            0x10    /* OSPF base header */
#define STD_PBLOCK_OSPF_HELLO_H      0x11    /* OSPF hello header */
#define LIBNET_PBLOCK_OSPF_DBD_H        0x12    /* OSPF dbd header */
#define LIBNET_PBLOCK_OSPF_LSR_H        0x13    /* OSPF lsr header */
#define LIBNET_PBLOCK_OSPF_LSU_H        0x14    /* OSPF lsu header */
#define LIBNET_PBLOCK_OSPF_LSA_H        0x15    /* OSPF lsa header */
#define LIBNET_PBLOCK_OSPF_AUTH_H       0x16    /* OSPF auth header */
#define LIBNET_PBLOCK_OSPF_CKSUM        0x17    /* OSPF checksum header */
#define LIBNET_PBLOCK_LS_RTR_H          0x18    /* linkstate rtr header */
#define LIBNET_PBLOCK_LS_NET_H          0x19    /* linkstate net header */
#define LIBNET_PBLOCK_LS_SUM_H          0x1a    /* linkstate as sum header */
#define LIBNET_PBLOCK_LS_AS_EXT_H       0x1b    /* linkstate as ext header */
#define LIBNET_PBLOCK_NTP_H             0x1c    /* NTP header */
#define LIBNET_PBLOCK_RIP_H             0x1d    /* RIP header */
#define LIBNET_PBLOCK_TCP_H             0x1e    /* TCP header */
#define LIBNET_PBLOCK_TCPO_H            0x1f    /* TCP options */
#define LIBNET_PBLOCK_TCPDATA           0x20    /* TCP data */
#define LIBNET_PBLOCK_UDP_H             0x21    /* UDP header */
#define LIBNET_PBLOCK_VRRP_H            0x22    /* VRRP header */
#define LIBNET_PBLOCK_DATA_H            0x23    /* generic data */
#define LIBNET_PBLOCK_CDP_H             0x24    /* CDP header */
#define LIBNET_PBLOCK_IPSEC_ESP_HDR_H   0x25    /* IPSEC ESP header */
#define LIBNET_PBLOCK_IPSEC_ESP_FTR_H   0x26    /* IPSEC ESP footer */
#define LIBNET_PBLOCK_IPSEC_AH_H        0x27    /* IPSEC AH header */
#define LIBNET_PBLOCK_802_1Q_H          0x28    /* 802.1q header */
#define LIBNET_PBLOCK_802_2_H           0x29    /* 802.2 header */
#define LIBNET_PBLOCK_802_2SNAP_H       0x2a    /* 802.2 SNAP header */
#define LIBNET_PBLOCK_802_3_H           0x2b    /* 802.3 header */
#define LIBNET_PBLOCK_STP_CONF_H        0x2c    /* STP configuration header */
#define LIBNET_PBLOCK_STP_TCN_H         0x2d    /* STP TCN header */
#define LIBNET_PBLOCK_ISL_H             0x2e    /* ISL header */
#define LIBNET_PBLOCK_IPV6_H            0x2f    /* IP v6 header */
#define LIBNET_PBLOCK_802_1X_H          0x30    /* 802.1x header */
#define LIBNET_PBLOCK_RPC_CALL_H        0x31    /* RPC Call header */
#define LIBNET_PBLOCK_MPLS_H            0x32    /* MPLS header */
#define LIBNET_PBLOCK_FDDI_H            0x33    /* FDDI header */
#define LIBNET_PBLOCK_TOKEN_RING_H      0x34    /* TOKEN RING header */
#define LIBNET_PBLOCK_BGP4_HEADER_H     0x35    /* BGP4 header */
#define LIBNET_PBLOCK_BGP4_OPEN_H       0x36    /* BGP4 open header */
#define LIBNET_PBLOCK_BGP4_UPDATE_H     0x37    /* BGP4 update header */
#define LIBNET_PBLOCK_BGP4_NOTIFICATION_H 0x38  /* BGP4 notification header */
#define LIBNET_PBLOCK_GRE_H             0x39    /* GRE header */
#define LIBNET_PBLOCK_GRE_SRE_H         0x3a    /* GRE SRE header */
#define LIBNET_PBLOCK_IPV6_FRAG_H       0x3b    /* IPv6 frag header */
#define LIBNET_PBLOCK_IPV6_ROUTING_H    0x3c    /* IPv6 routing header */
#define LIBNET_PBLOCK_IPV6_DESTOPTS_H   0x3d    /* IPv6 dest opts header */
#define LIBNET_PBLOCK_IPV6_HBHOPTS_H    0x3e    /* IPv6 hop/hop opts header */
#define LIBNET_PBLOCK_SEBEK_H           0x3f    /* Sebek header */
#define LIBNET_PBLOCK_HSRP_H            0x40    /* HSRP header */
#define LIBNET_PBLOCK_ICMPV6_H          0x41    /* ICMPv6 header */
#define LIBNET_PBLOCK_ICMPV6_UNREACH_H  0x42    /* ICMPv6 unreach header */

    uint8_t flags;                             /* control flags */
#define LIBNET_PBLOCK_DO_CHECKSUM       0x01    /* needs a checksum */
    std_ptag_t ptag;                 /* protocol block tag */
    /* Chains are built from highest level protocol, towards the link level, so
     * prev traverses away from link level, and next traverses towards the
     * link level.
     */
    struct std_protocol_block *next; /* next pblock */
    struct std_protocol_block *prev; /* prev pblock */
};
typedef struct std_protocol_block std_pblock_t;


/* libnet statistics structure */
struct std_stats
{
#if (!defined(__WIN32__) || (__CYGWIN__))
    u_int64_t packets_sent;             /* packets sent */
    u_int64_t packet_errors;            /* packets errors */
    u_int64_t bytes_written;            /* bytes written */
#else
    __int64 packets_sent;               /* packets sent */
    __int64 packet_errors;              /* packets errors */
    __int64 bytes_written;              /* bytes written */
#endif
};



#define LIBNET_LINK     0x00            /* link-layer interface */
#define STD_RAW4     0x01            /* raw socket interface (ipv4) */
#define LIBNET_RAW6     0x02            /* raw socket interface (ipv6) */
/* the following should actually set a flag in the flags variable above */
#define LIBNET_LINK_ADV 0x08            /* advanced mode link-layer */
#define LIBNET_RAW4_ADV 0x09            /* advanced mode raw socket (ipv4) */
#define LIBNET_RAW6_ADV 0x0a            /* advanced mode raw socket (ipv6) */
#define LIBNET_ADV_MASK 0x08            /* mask to determine adv mode */



    
    
/*
 *  Libnet context
 *  Opaque structure.  Nothing in here should ever been touched first hand by
 *  the applications programmer.
 */
struct std_context
{
#if ((__WIN32__) && !(__CYGWIN__)) 
    SOCKET fd;
    LPADAPTER  lpAdapter;
#else
    int fd;                             /* file descriptor of packet device */
#endif
    int injection_type;                 /* raw (ipv4 or ipv6) or link */

    std_pblock_t *protocol_blocks;   /* protocol headers / data */
    std_pblock_t *pblock_end;        /* last node in list */
    u_int32_t n_pblocks;                /* number of pblocks */

    int link_type;                      /* link-layer type */
    int link_offset;                    /* link-layer header size */
    int aligner;                        /* used to align packets */
    char *device;                       /* device name */

    struct std_stats stats;          /* statistics */
    std_ptag_t ptag_state;           /* state holder for pblock tag */
    char label[STD_LABEL_SIZE];      /* textual label for cq interface */

    char err_buf[STD_ERRBUF_SIZE];   /* error buffer */
    u_int32_t total_size;               /* total size */
};
typedef struct std_context std_t;    
    
    
/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct std_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
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
 *  OSPF hello header
 *  Open Shortest Path First
 *  Static header size: 28 bytes
 */
struct std_ospf_hello_hdr
{
    struct in_addr hello_nmask; /* netmask associated with the interface */
    u_int16_t hello_intrvl;       /* num of seconds between routers last packet */
    u_int8_t hello_opts;          /* Options for HELLO packets (look above) */
    u_int8_t hello_rtr_pri;       /* router's priority (if 0, can't be backup) */
    u_int hello_dead_intvl;     /* # of secs a router is silent till deemed down */
    struct in_addr hello_des_rtr;   /* Designated router on the network */
    struct in_addr hello_bkup_rtr;  /* Backup router */
    struct in_addr hello_nbr;       /* neighbor router, memcpy more as needed */
};


/*
 *  OSPF hello header
 *  Open Shortest Path First
 *  Static header size: 28 bytes
 */
struct std_ospf_helloraw_hdr
{
    struct in_addr hello_nmask; /* netmask associated with the interface */
    u_int16_t hello_intrvl;       /* num of seconds between routers last packet */
    u_int8_t hello_opts;          /* Options for HELLO packets (look above) */
    u_int8_t hello_rtr_pri;       /* router's priority (if 0, can't be backup) */
    u_int hello_dead_intvl;     /* # of secs a router is silent till deemed down */
    struct in_addr hello_des_rtr;   /* Designated router on the network */
    struct in_addr hello_bkup_rtr;  /* Backup router */
};
    

/*
 *  OSPFv2 header
 *  Open Shortest Path First
 *  Static header size: 16 bytes
 */
struct std_ospf_hdr
{
    u_int8_t ospf_v;          /* version */
#define OSPFVERSION         2
    u_int8_t ospf_type;       /* type */
#define  LIBNET_OSPF_UMD    0   /* UMd monitoring packet */
#define  STD_OSPF_HELLO  1   /* HELLO packet */
#define  STD_OSPF_DBD    2   /* dataBase description packet */
#define  STD_OSPF_LSR    3   /* link state request packet */
#define  STD_OSPF_LSU    4   /* link state Update Packet */
#define  LIBNET_OSPF_LSA    5   /* link state acknowledgement packet */
    u_int16_t   ospf_len;     /* length */
    struct in_addr ospf_rtr_id; /* source router ID */
    struct in_addr ospf_area_id;/* roam ID */
    u_int16_t ospf_sum;         /* checksum */
    u_int16_t ospf_auth_type;     /* authentication type */
#define STD_OSPF_AUTH_NULL   0   /* null password */
#define LIBNET_OSPF_AUTH_SIMPLE 1   /* simple, plaintext, 8 int8_t password */
#define LIBNET_OSPF_AUTH_MD5    2   /* MD5 */
};

/*
 *  Link State Update header
 */
struct std_lsu_hdr
{
    u_int lsu_num;              /* number of LSAs that will be broadcasted */
};

/*
 *  Link State Request header
 */
struct std_lsr_hdr
{
    u_int lsr_type;             /* type of LS being requested */
    u_int lsr_lsid;             /* link state ID */
    struct in_addr lsr_adrtr;   /* advertising router (memcpy more as needed) */
};




/*
 *  Database Description header.
 */
struct std_dbd_hdr
{
    u_int16_t dbd_mtu_len;    /* max length of IP dgram that this 'if' can use */
    u_int8_t dbd_opts;        /* DBD packet options (from above) */
    u_int8_t dbd_type;        /* type of exchange occurring */
#define LIBNET_DBD_IBI      0x01    /* init */
#define LIBNET_DBD_MBIT     0x02    /* more DBD packets are to come */
#define LIBNET_DBD_MSBIT    0x04    /* If 1, sender is the master in the exchange */
    u_int  dbd_seq;         /* DBD sequence number */
};


/*
 *  Link State Acknowledgement header.
 */
struct std_lsa_hdr
{
    u_int16_t lsa_age;        /* time in seconds since the LSA was originated */
    u_int8_t lsa_opts;        /* look above for OPTS_* */
    u_int8_t lsa_type;        /* look below for LS_TYPE_* */
    u_int lsa_id;           /* link State ID */
    struct in_addr lsa_adv; /* router ID of Advertising router */
    u_int lsa_seq;          /* LSA sequence number to detect old/bad ones */
    u_int16_t lsa_sum;      /* "Fletcher Checksum" of all fields minus age */
    u_int16_t lsa_len;        /* length in bytes including the 20 byte header */
};
    
std_pblock_t *
std_pblock_probe(std_t *l, std_ptag_t ptag, uint32_t b_len, uint8_t type);

int
std_pblock_append(std_t *l, std_pblock_t *p, const uint8_t *buf,
            uint32_t len);

void
std_pblock_delete(std_t *l, std_pblock_t *p);

static void std_pblock_remove_from_list(std_t *l, std_pblock_t *p);

std_t *
std_init(int injection_type, const char *device, char *err_buf);

void
std_destroy(std_t *l);

std_ptag_t
std_pblock_update(std_t *l, std_pblock_t *p, uint32_t h_len, uint8_t type);

std_ptag_t
std_build_ospfv2_lsu(uint32_t num, const uint8_t *payload, uint32_t payload_s,
std_t *l, std_ptag_t ptag);


std_ptag_t
std_build_data(const uint8_t *payload, uint32_t payload_s, std_t *l,
std_ptag_t ptag);


std_ptag_t
std_build_ospfv2(uint16_t len, uint8_t type, uint32_t rtr_id, 
uint32_t area_id, uint16_t sum, uint16_t autype, const uint8_t *payload, 
uint32_t payload_s, std_t *l, std_ptag_t ptag);


std_ptag_t
std_build_ipv4(uint16_t ip_len, uint8_t tos, uint16_t id, uint16_t frag,
uint8_t ttl, uint8_t prot, uint16_t sum, uint32_t src, uint32_t dst,
const uint8_t *payload, uint32_t payload_s, std_t *l, std_ptag_t ptag);


int
std_write(std_t *l);

int
std_pblock_coalesce(std_t *l, uint8_t **packet, uint32_t *size);

static int calculate_ip_offset(std_t* l, std_pblock_t* q);

int
std_inet_checksum(std_t *l, uint8_t *iphdr, int protocol, int h_len, const uint8_t *beg, const uint8_t * end);

int
std_in_cksum(uint16_t *addr, int len);

std_ptag_t
std_build_ospfv2_dbd(uint16_t dgram_len, uint8_t opts, uint8_t type,
uint32_t seqnum, const uint8_t *payload, uint32_t payload_s, std_t *l,
std_ptag_t ptag);

uint32_t
std_name2addr4(std_t *l, char *host_name, uint8_t use_name);

std_ptag_t
std_build_ospfv2_lsr(uint32_t type, uint lsid, uint32_t advrtr, 
const uint8_t *payload, uint32_t payload_s, std_t *l, std_ptag_t ptag);

char *
std_geterror(std_t *l);

std_ptag_t
std_build_ospfv2_lsa(uint16_t age, uint8_t opts, uint8_t type, uint lsid,
uint32_t advrtr, uint32_t seqnum, uint16_t sum, uint16_t len,
const uint8_t *payload, uint32_t payload_s, std_t *l, std_ptag_t ptag);


std_pblock_t *
std_pblock_new(std_t *l, uint32_t b_len);

std_pblock_t *
std_pblock_find(std_t *l, std_ptag_t ptag);

int
std_open_raw4(std_t *l);

void
std_clear_packet(std_t *l);

void
std_pblock_setflags(std_pblock_t *p, uint8_t flags);

int
std_pblock_swap(std_t *l, std_ptag_t ptag1, std_ptag_t ptag2);

int
std_pblock_insert_before(std_t *l, std_ptag_t ptag1,
        std_ptag_t ptag2);

int
std_write_raw_ipv4(std_t *l, const uint8_t *packet, uint32_t size);

int
std_pblock_p2p(uint8_t type);

static int pblock_is_ip(std_pblock_t* p);

static int check_ip_payload_size(std_t*l, const uint8_t *iphdr, int ip_hl, int h_len, const uint8_t * end, const char* func);

static void* zmalloc(std_t* l, uint32_t size, const char* func);

std_ptag_t
std_build_ospfv2_lsa(uint16_t age, uint8_t opts, uint8_t type, uint lsid,
uint32_t advrtr, uint32_t seqnum, uint16_t sum, uint16_t len,
const uint8_t *payload, uint32_t payload_s, std_t *l, std_ptag_t ptag);

#ifdef	__cplusplus
}
#endif

#endif	/* LIBNET_H */

