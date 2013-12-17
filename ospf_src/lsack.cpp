#include <stdio.h>
#include <stdlib.h>

#include "global.h"
#include "stdnet.h"
#include "pkt.h"

using namespace std;

void * send_ls_ack(void * nowInf, struct std_lsa_hdr * pLsaAck)
{
    struct inf_struct * interfaceNow=(struct inf_struct *)nowInf;

    int c;
    std_t *l;
    std_ptag_t t;
    u_int32_t src, dst;
    u_char auth[8] = {0,0,0,0,0,0,0,0};
    char errbuf[STD_ERRBUF_SIZE];

    l = std_init(STD_RAW4, NULL, errbuf);

    if (l == NULL)
    {
        fprintf(stderr, "std_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    /* Too lazy to check for error */
    src = interfaceNow->ip;
    dst = std_name2addr4(l, "224.0.0.5", LIBNET_DONT_RESOLVE);


    t = std_build_ospfv2_lsa(
pLsaAck->lsa_age,0, pLsaAck->lsa_type, pLsaAck->lsa_id, pLsaAck->lsa_adv.s_addr, pLsaAck->lsa_seq,0xffff,STD_OSPF_LSA_H, NULL,0, l, 0); 
    if (t == -1)
    {
        fprintf(stderr, "Can't build LSA header: %s\n", std_geterror(l));
        goto bad;
    }

    /* authentication data */
    t = std_build_data(
            auth,                                       /* auth data */
            STD_OSPF_AUTH_H,                         /* payload size */
            l,                                          /* libnet handle */
            0);                                         /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build OSPF AUTH header: %s\n", std_geterror(l));
        goto bad;
    }

    t = std_build_ospfv2(
            STD_OSPF_LSA_H + STD_OSPF_AUTH_H,                       /* OSPF packet length */
            LIBNET_OSPF_LSA,                            /* OSPF packet type */
            htonl(nowRt.router_id),                          /* router id */
            htonl(interfaceNow->areain->areaId),                          /* area id */
            0,                                          /* checksum */
            STD_OSPF_AUTH_NULL,                      /* auth type */
            NULL,                                       /* payload */
            0,                                          /* payload size */
            l,                                          /* libnet handle */
            0);                                         /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build OSPF header: %s\n", std_geterror(l));
        goto bad;
    }

    t = std_build_ipv4(
            STD_IPV4_H + STD_OSPF_H + STD_OSPF_AUTH_H +
            STD_OSPF_LSA_H,   /* packet total length */
            0,                                          /* TOS */
            101,                                        /* IP iD */
            IP_DF,                                      /* IP frag */
            254,                                        /* TTL */
            IPPROTO_OSPF,                               /* protocol */
            0,                                          /* checksum */
            src,                                        /* source IP */
            dst,                                        /* destination IP */
            NULL,                                       /* payload */
            0,                                          /* payload size */
            l,                                          /* libnet handle */
            0);                                         /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build IP header: %s\n", std_geterror(l));
        goto bad;
    }

    c = std_write(l);
    if (c == -1)
    {
        fprintf(stderr, "Write error: %s\n", std_geterror(l));
        goto bad;
    }
    else
    {
        printf("SEND %d BYTE OSPF LSACK PACKET.................\n\n",
               c);
    }


    std_destroy(l);
    return NULL;
bad:
    std_destroy(l);
    return (NULL);
}



void recv_ls_ack(const u_char * packet)
{
    struct ip_pkt* ip = (struct ip_pkt*)(packet + PKT_ETH_LEN);
    
    int sizeIp=IP_HL(ip)*4;

    struct ospfhdr * op=(struct ospfhdr *)(packet+PKT_ETH_LEN+sizeIp);
    op->ospf_routerid.s_addr=ntos_32(&(op->ospf_routerid.s_addr));
    op->ospf_areaid.s_addr=ntos_32(&(op->ospf_areaid.s_addr));
    
    ntoh_16it(op->ospf_lsa.lsa_lshdr[0].ls_age);
    ntoh_16it(op->ospf_lsa.lsa_lshdr[1].ls_age);
    ntos_32it(op->ospf_lsa.lsa_lshdr[0].ls_router.s_addr);
    ntos_32it(op->ospf_lsa.lsa_lshdr[1].ls_router.s_addr);
    ntos_32it(op->ospf_lsa.lsa_lshdr[0].ls_seq);
    ntos_32it(op->ospf_lsa.lsa_lshdr[1].ls_seq);
    ntoh_16it(op->ospf_lsa.lsa_lshdr[0].ls_chksum);
    ntoh_16it(op->ospf_lsa.lsa_lshdr[1].ls_chksum);
    ntoh_16it(op->ospf_lsa.lsa_lshdr[0].ls_length);
    ntoh_16it(op->ospf_lsa.lsa_lshdr[1].ls_length);
    ntos_32it(op->ospf_lsa.lsa_lshdr[0].lsa_id.s_addr);
    ntos_32it(op->ospf_lsa.lsa_lshdr[1].lsa_id.s_addr);

    printf("RECV LSAck FROM %d: ACK %d\n",op->ospf_lsa.lsa_lshdr[0].ls_router.s_addr,op->ospf_lsa.lsa_lshdr[0].lsa_id.s_addr);

}
