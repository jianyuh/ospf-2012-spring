#ifndef PKT_H_INCLUDED
#define PKT_H_INCLUDED

#include <net/ethernet.h>
#include <stdint.h>
#include <deque>
#include <map>

#include "stdnet.h"

using namespace std;

#define RT_MAX 100

#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */

#define PKT_ETH_LEN 16

#define HELLO_INTERVAL 10
#define ROUTERDEADINTERVAL 40
#define RXMTINTERVAL 10


#define PKT_HEADER_SIZE         24
#define PKT_AUTH_SIMPLE_SIZE     8
#define PKT_AUTH_MD5_SIZE       16

//define the 5 types of packet
#define	OSPF_TYPE_HELLO         1	// Hello
#define	OSPF_TYPE_DD            2	// Database Description
#define	OSPF_TYPE_LS_REQ        3	// Link State Request Message
#define	OSPF_TYPE_LS_UPDATE     4	// Link State Update Message
#define	OSPF_TYPE_LS_ACK        5	// Link State Acknoledgement


#define OSPF_OPTION_T	0x01	/* T bit: TOS support	*/
#define OSPF_OPTION_E	0x02	/* E bit: External routes advertised	*/
#define	OSPF_OPTION_MC	0x04	/* MC bit: Multicast capable */
#define	OSPF_OPTION_NP	0x08	/* N/P bit: NSSA capable */
#define	OSPF_OPTION_EA	0x10	/* EA bit: External Attribute capable */
#define	OSPF_OPTION_L	0x10	/* L bit: Packet contains LLS data block */
#define	OSPF_OPTION_DC	0x20	/* DC bit: Demand circuit capable */
#define	OSPF_OPTION_O	0x40	/* O bit: Opaque LSA capable */
#define	OSPF_OPTION_DN	0x80	/* DN bit: Up/Down Bit capable - draft-ietf-ospf-2547-dnbit-04 */

/* ls_type	*/
#define	LS_TYPE_ROUTER		1   /* router link */
#define	LS_TYPE_NETWORK		2   /* network link */
#define	LS_TYPE_SUM_IP		3   /* summary link */
#define	LS_TYPE_SUM_ABR		4   /* summary area link */
#define	LS_TYPE_ASE		5   /* ASE  */

/* db_flags	*/
#define	OSPF_DB_INIT		0x04
#define	OSPF_DB_MORE		0x02
#define	OSPF_DB_MASTER      0x01

//link type
#define LINK_TYPE_PTP     1   /* Point-To-Point */
#define LINK_TYPE_TRANS   2   /* Connection to a "transit network" */
#define LINK_TYPE_STUB    3   /* Connectin to a "stub network" */
#define LINK_TYPE_VRTL   4   /* connects to a "virtual link" */



/* IP header */
struct ip_pkt
{
    u_char vhl;		/* version << 4 | header length >> 2 */
    u_char tos;		/* type of service */
    u_short len;		/* total length */
    u_short id;		/* identification */
    u_short offset;		/* fragment offset field */
    u_char ttl;		/* time to live */
    u_char pro;		/* protocol */
    u_short sum;		/* checksum */
    struct in_addr src,dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->vhl) & 0x0f)
#define IP_V(ip)		(((ip)->vhl) >> 4)


//OSPF Hello body format
struct hello_hdr
{
    struct in_addr mask;
    u_int16_t hello_interval;
    u_char opts;
    u_char rtr_prirority;
    u_int32_t rtr_dead_interval;
    struct in_addr d_rtr;
    struct in_addr bd_rtr;
    struct in_addr neighbors[1];
};

//OSPF Database Description body format
struct db_dscrp_hdr
{
    u_int16_t iface_mtu;
    u_char opts;
    u_char bits;
    u_int32_t dd_seq_num;
};


/* link state advertisement header */
struct lsa_hdr
{
    u_int16_t ls_age;
    u_int8_t ls_options;
    u_int8_t ls_type;
    struct in_addr lsa_id;
    
    struct in_addr ls_router;
    u_int32_t ls_seq;
    u_int16_t ls_chksum;
    u_int16_t ls_length;
};

struct tos_metric
{
    u_int8_t tos_type;
    u_int8_t reserved;
    u_int16_t tos_metric;
};
struct tos_link
{
    u_int8_t link_type;
    u_int8_t link_tos_count;
    u_int16_t tos_metric;
};
union un_tos
{
    struct tos_link link;
    struct tos_metric metrics;
};

/* link state advertisement */
struct lsa
{
    struct lsa_hdr ls_hdr;

    /* Link state types */
    union
    {
        /* Router links advertisements */
        struct
        {
            u_int8_t rla_flags;
            u_int8_t rla_zero[1];
            u_int16_t rla_count;
            struct rlalink
            {
                struct in_addr link_id;
                struct in_addr link_data;
                union un_tos un_tos;
            } rla_link[1];
        } un_rla;

        /* Network links advertisements */
        struct
        {
            struct in_addr nla_mask;
            struct in_addr nla_router[5];
        } un_nla;

        /* Summary links advertisements */
        struct
        {
            struct in_addr sla_mask;
            u_int32_t sla_tosmetric[1];
        } un_sla;

        /* AS external links advertisements */
        struct
        {
            struct in_addr asla_mask;
            struct aslametric
            {
                u_int32_t asla_tosmetric;
                struct in_addr asla_forward;
                struct in_addr asla_tag;
            } asla_metric[1];
        } un_asla;
    } lsa_un;
};


#define ntoh_16(p) ((u_int16_t)ntohs(*(const u_int16_t *)(p)))
#define ntos_32(p) ((u_int32_t)ntohl(*(const u_int32_t *)(p)))
#define ntoh_64(p) ((u_int64_t)(((u_int64_t)ntohl(*((const u_int32_t *)(p) + 0))) << 32 | ((u_int64_t)ntohl(*((const u_int32_t *)(p) + 1))) << 0))

#define ntoh_16it(t) t=(ntoh_16(&(t)))
#define ntos_32it(t) t=(ntos_32(&(t)))
#define ntos_64it(t) t=(ntoh_64(&(t)))

#define	ospf_hello	ospf_un.un_hello
#define	ospf_db		ospf_un.un_db
#define	ospf_lsr	ospf_un.un_lsr
#define	ospf_lsu	ospf_un.un_lsu
#define	ospf_lsa	ospf_un.un_lsa

struct lsaforLsu
{
    struct std_lsa_hdr ls_hdr;

    /* Link state types */
    union
    {
        /* Router links advertisements */
        struct
        {
            u_int8_t rla_flags;
            u_int8_t rla_zero[1];
            u_int16_t rla_count;
            struct rlalink
            {
                struct in_addr link_id;
                struct in_addr link_data;
                union un_tos un_tos;
            } rla_link[1];
        } un_rla;

        /* Network links advertisements */
        struct
        {
            struct in_addr nla_mask;
            struct in_addr nla_router[5];
        } un_nla;

        /* Summary links advertisements */
        struct
        {
            struct in_addr sla_mask;
            u_int32_t sla_tosmetric[1];
        } un_sla;

        /* AS external links advertisements */
        struct
        {
            struct in_addr asla_mask;
            struct aslametric
            {
                u_int32_t asla_tosmetric;
                struct in_addr asla_forward;
                struct in_addr asla_tag;
            } asla_metric[1];
        } un_asla;
    } lsa_un;
};

#define OSPF_AUTH_SIZE 8

#define DD_I 0x04
#define DD_M 0x02
#define DD_MS 0x01

struct ospfhdr_dd_st
{
    u_int16_t db_ifmtu;
    u_int8_t db_options;
    u_int8_t db_flags;
    u_int32_t db_seq;
    struct lsa_hdr db_lshdr[1];
};

struct ospfhdr
{
    u_int8_t ospf_version;
    u_int8_t ospf_type;
    u_int16_t ospf_len;
    struct in_addr ospf_routerid;
    struct in_addr ospf_areaid;
    //u_int32_t ospf_routerid;
    //u_int32_t ospf_areaid;
    u_int16_t ospf_chksum;
    u_int16_t ospf_authtype;
    u_int8_t ospf_authdata[OSPF_AUTH_SIZE];
    union
    {
        /* Hello packet */
        struct
        {
            struct in_addr hello_mask;
            u_int16_t hello_helloint;
            u_int8_t hello_options;
            u_int8_t hello_priority;
            u_int32_t hello_deadint;
            struct in_addr hello_dr;
            struct in_addr hello_bdr;
            struct in_addr hello_neighbor[1];
        } un_hello;

        /* Database Description packet */
        struct ospfhdr_dd_st un_db;

        /* Link State Request */
        struct lsr
        {
            u_int32_t ls_type;
            union
            {
                struct in_addr ls_stateid;
                struct   /* 这里先不考虑 opaque LSAs，所以可以不用这个field */
                {
                    u_int8_t opaque_type;
                    u_int8_t opaque_id[3];
                } opaque_field;
            } un_ls_stateid;
            struct in_addr ls_router;
        } un_lsr;

        /* Link State Update */
        struct
        {
            u_int32_t lsu_count;
            struct lsa lsu_lsa[1];
        } un_lsu;

        /* Link State Acknowledgement */
        struct
        {
            struct lsa_hdr lsa_lshdr[1];
        } un_lsa ;
    } ospf_un ;
};


extern char outlsdbfile[100];
extern char outfile[100];

extern uint32_t rtrRtrCnnt[RT_MAX][RT_MAX];

extern deque<struct area *> areaDeque;
extern deque<struct inf_struct *> infDeque;
extern struct Rt_struct nowRt;
extern map <int,int> cnctMap;


extern char Rn[10];

//hello.cpp
char * inet_ntostr(u_int32_t addrnet);
struct std_lsa_hdr * parselsahdr(struct lsdb_struct * lsa);
std_ptag_t ospf_helloseen(uint32_t netmask, uint16_t interval, uint8_t opts, uint8_t priority, uint32_t dead_int, uint32_t des_rtr, uint32_t bkup_rtr, const uint8_t *payload, uint32_t payload_s, std_t *l, std_ptag_t ptag,uint32_t neighbor);
void * sendHelloPkt(void * nowInf);
void * sendHelloSeen(void * nowInf,u_int32_t seenNbr);
void * keep(void * none);
void recv_hello(const u_char * packet);
void * DRdetect(void * none);


//dd.cpp

struct lsdb_struct * lsainLsdb(struct area *area, u_int32_t seq);
void ddsrand();
u_int32_t gen1stDDSeq();
void * send_db_description(void * nowInf, struct nbr_struct * nbrStct, struct std_lsa_hdr * pLsaSend, bool initBool,bool moreBool,bool msBool);
void recv_db_description(const u_char * packet);

//lsr.cpp
void * send_ls_req(void * nowInf, struct nbr_struct * nbrStct, uint lsa_typeF, uint lsa_idF, uint32_t lsa_advs_addrF);
void recv_ls_req(const u_char * packet);



//lsu.cpp
void * send_ls_update(void * nowInf, u_int32_t sendToIp, struct lsdb_struct * lsaSent ,struct std_lsa_hdr * pLsaSend);
void recv_ls_update(const u_char * packet);


//lsack.cpp
void * send_ls_ack(void * nowInf, struct std_lsa_hdr * pLsaAck);
void recv_ls_ack(const u_char * packet);

//pkt.cpp
void * recvPkt(void * none);
void recv_packet(u_char *args,const struct pcap_pkthdr * header,const u_char * packet);


//init.cpp
void init();

//out.cpp
void * printLsdb(void * none);


//genrt.cpp
int addRouteIterm(uint32_t dstIp, uint32_t mask, uint32_t nextHop, char* infName);


#endif // PKT_H_INCLUDED
