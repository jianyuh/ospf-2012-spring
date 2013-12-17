#include<stdio.h>
#include<arpa/inet.h>
#include<unistd.h>

#include "global.h"
#include "stdnet.h"
#include "pkt.h"

using namespace std;


void * send_ls_req(void * nowInf, struct nbr_struct * nbrStct, uint lsa_typeF, uint lsa_idF, uint32_t lsa_advs_addrF)
{
    struct inf_struct * tmpnowInf=(struct inf_struct *)nowInf;
    std_t *l;
    char errbuf[STD_ERRBUF_SIZE];
    u_char auth[8] = {0,0,0,0,0,0,0,0};


    l=std_init(STD_RAW4, tmpnowInf->name, errbuf);

    if (l==NULL)
    {
        fprintf(stderr, "std_init() failed: %s", errbuf);
    }

    u_int32_t src, dst;
    src = tmpnowInf->ip;
    dst = nbrStct->inf_ip;

    std_ptag_t t = std_build_ospfv2_lsr(lsa_typeF,lsa_idF,lsa_advs_addrF,NULL,0,l,0);

    t = std_build_data(auth, STD_OSPF_AUTH_H, l,  0); 

    t = std_build_ospfv2( STD_OSPF_LSR_H + STD_OSPF_AUTH_H, STD_OSPF_LSR, htonl(nowRt.router_id), htonl(tmpnowInf->areain->areaId), 0, STD_OSPF_AUTH_NULL, NULL, 0, l, 0);

    t = std_build_ipv4( STD_IPV4_H + STD_OSPF_H + STD_OSPF_LSR_H + STD_OSPF_AUTH_H, 0, 101, IP_DF, 254, IPPROTO_OSPF, 0, src,dst, NULL,0,l,0);

    int c=-1;
    while (c==-1)
    {
        c = std_write(l);
        printf("SEND %d BYTE OSPF LSR PACKET.................\n", c);
    }


    std_destroy(l);

}


void recv_ls_req(const u_char * packet)
{
    struct ip_pkt* ip = (struct ip_pkt*)(packet + PKT_ETH_LEN);
    
    int sizeIp=IP_HL(ip)*4;

    struct ospfhdr * op=(struct ospfhdr *)(packet+PKT_ETH_LEN+sizeIp);
    op->ospf_routerid.s_addr=ntos_32(&(op->ospf_routerid.s_addr));
    op->ospf_areaid.s_addr=ntos_32(&(op->ospf_areaid.s_addr));
    
    ntos_32it(op->ospf_lsr.ls_router.s_addr);
    ntos_32it(op->ospf_lsr.un_ls_stateid.ls_stateid.s_addr);

    bool shouldPrcs=false;

    deque<struct area *>::iterator itArea;
    //对area循环
    for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
    {
        //deque<struct interface_struct *>::iterator itItf;
        struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
        //对area中到interface进行循环
        for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
        {

            //同一个网段
            if ((ip->dst.s_addr)==(infDequeInArea->inf->ip))
            {
                shouldPrcs=true;
                break;
            }
        }
        if (shouldPrcs)
        {
            break;
        }
    }

    //ip -> "self"
    if (shouldPrcs)
    {

        int lsTypeF=htonl(((op->ospf_lsr)).ls_type);
        u_int32_t lsaIdF=((op->ospf_lsr).un_ls_stateid.ls_stateid.s_addr);
        u_int32_t lsRouterF=(op->ospf_lsr).ls_router.s_addr;

        deque<struct area *>::iterator itArea;
        //对area循环
        for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
        {
            if ((*itArea)->areaId==op->ospf_areaid.s_addr)
            {
                printf("LSR IN AREA %d\n",op->ospf_areaid.s_addr);

                struct area * areaP=*itArea;

                deque<struct lsdb_struct *>::iterator itLsaScan=areaP->lsaDequeInArea.begin();
                struct lsdb_struct * lsaFound=NULL;
                for (; itLsaScan!=areaP->lsaDequeInArea.end(); itLsaScan++)
                {
                    //由ls_router确定是哪一个router
                    //然后ls_type, ls_id在一个路由器上唯一确定一个LSA
                    if ((((*itLsaScan)->ls_type) == lsTypeF)&&
                            (((*itLsaScan)->ls_id) == lsaIdF)&&
                            (((*itLsaScan)->bornRtId) == lsRouterF))
                    {
                        printf("find one lsa(lsr repley)\n");
                        //找到了LSA
                        lsaFound=(*itLsaScan);

                        //找到接收到的interface
                        struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
                        //对area中的interface进行循环
                        for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
                        {
                            if (infDequeInArea->inf->ip==ip->dst.s_addr)
                            {
                                break;
                            }
                        }

                        //找到了要回送的LSA
                        //发送LSU报文
                        if (infDequeInArea!=NULL)
                        {
                            if (lsaFound!=NULL)
                            {
                                printf("LSU: %s",inet_ntostr(infDequeInArea->inf->ip));
                                printf("->%s, %d\n",inet_ntoa(ip->src),lsaFound->seq);

                                sleep(0);
                                send_ls_update(infDequeInArea->inf,ip->src.s_addr,lsaFound,
                                        (parselsahdr(lsaFound)));
                            }
                            else
                            {
                                printf("err: lsaFound is NULL!\n");
                            }
                        }
                        else
                        {
                            printf("WRONG interface when sending LSU\n");
                        }
                    }
                }
            }
        }
    }

}
