#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <map>
#include <deque>


#include "global.h"
#include "stdnet.h"
#include "pkt.h"

using namespace std;

void * send_ls_update(void * nowInf, u_int32_t sendToIp, struct lsdb_struct * lsaSent ,struct std_lsa_hdr * pLsaSend)
{
    struct inf_struct * tmpNowInf=(struct inf_struct *)nowInf;
    std_t *l;
    char errbuf[STD_ERRBUF_SIZE];
    u_char auth[8] = {0,0,0,0,0,0,0,0};

    l=std_init(STD_RAW4, tmpNowInf->name, errbuf);

    if (l==NULL)
    {
        fprintf(stderr, "std_init() failed: %s", errbuf);
    }

    u_int32_t src, dst;
    src = tmpNowInf->ip;
    dst = sendToIp;


    std_ptag_t t;

    if (lsaSent->ls_type==1)
    {

    }
    else if (lsaSent->ls_type==2)
    {
        
    }


    pLsaSend->lsa_len=htons(lsaSent->ls_type==2?28:36);
    pLsaSend->lsa_id=htonl(lsaSent->ls_id);
    pLsaSend->lsa_age=htons(lsaSent->bornTime);

    struct lsaforLsu * lsaPayload=new struct lsaforLsu;
    lsaPayload->ls_hdr=*pLsaSend;
    if (lsaSent->ls_type==1)
    {
        lsaPayload->lsa_un.un_rla.rla_flags=lsaPayload->lsa_un.un_rla.rla_zero[0]=0;
        lsaPayload->lsa_un.un_rla.rla_count=htons(1);
        lsaPayload->lsa_un.un_rla.rla_link[0].link_id.s_addr=lsaSent->lsa_un.un_rla.link_id.s_addr;
        lsaPayload->lsa_un.un_rla.rla_link[0].link_data.s_addr=lsaSent->lsa_un.un_rla.link_data.s_addr;
        lsaPayload->lsa_un.un_rla.rla_link[0].un_tos.link.link_type=lsaSent->lsa_un.un_rla.link.link_type;

        lsaPayload->lsa_un.un_rla.rla_link[0].un_tos.link.link_tos_count=lsaSent->lsa_un.un_rla.link.link_tos_count;

        {
            lsaPayload->lsa_un.un_rla.rla_link[0].un_tos.link.tos_metric=htons(lsaSent->lsa_un.un_rla.link.tos_metric);
        }
    }
    else
    {
        lsaPayload->ls_hdr.lsa_len=htons(lsaSent->length);
        lsaPayload->lsa_un.un_nla.nla_mask.s_addr=inet_addr("255.255.255.0");
        lsaPayload->lsa_un.un_nla.nla_router[0].s_addr=htonl(lsaSent->lsa_un.un_nla.nla_router[0].s_addr);
        lsaPayload->lsa_un.un_nla.nla_router[1].s_addr=htonl(lsaSent->lsa_un.un_nla.nla_router[1].s_addr);
        lsaPayload->lsa_un.un_nla.nla_router[2].s_addr=htonl(lsaSent->lsa_un.un_nla.nla_router[2].s_addr);
        lsaPayload->lsa_un.un_nla.nla_router[3].s_addr=htonl(lsaSent->lsa_un.un_nla.nla_router[3].s_addr);
        lsaPayload->lsa_un.un_nla.nla_router[4].s_addr=htonl(lsaSent->lsa_un.un_nla.nla_router[4].s_addr);
    }

    t = std_build_ospfv2_lsu(1, (u_int8_t *)lsaPayload, pLsaSend==NULL?0:sizeof(struct lsaforLsu), l,0);

    t = std_build_data(auth, STD_OSPF_AUTH_H, l, 0); 

    t = std_build_ospfv2(pLsaSend==NULL?0:sizeof(struct lsaforLsu )+STD_OSPF_LSU_H + STD_OSPF_AUTH_H, STD_OSPF_LSU, htonl(nowRt.router_id), htonl(tmpNowInf->areain->areaId), 0, STD_OSPF_AUTH_NULL, NULL, 0, l, 0); 

    t = std_build_ipv4(STD_IPV4_H + STD_OSPF_H + pLsaSend==NULL?0:sizeof(struct lsaforLsu )+STD_OSPF_LSU_H + STD_OSPF_AUTH_H, 0, 101, IP_DF, 254, IPPROTO_OSPF, 0,src, dst,NULL,0, l, 0); 

    int c = std_write(l);
    printf("SEND %d BYTE OSPF LSU PACKET.................\n", c);

    std_destroy(l);
}

void recv_ls_update(const u_char * packet)
{
    struct ip_pkt* ip = (struct ip_pkt*)(packet + PKT_ETH_LEN);
    
    int sizeIp=IP_HL(ip)*4;

    struct ospfhdr * op=(struct ospfhdr *)(packet+PKT_ETH_LEN+sizeIp);
    op->ospf_routerid.s_addr=ntos_32(&(op->ospf_routerid.s_addr));
    op->ospf_areaid.s_addr=ntos_32(&(op->ospf_areaid.s_addr));
    
    ntos_32it(op->ospf_lsu.lsu_count);
    ntoh_16it(op->ospf_lsu.lsu_lsa[0].ls_hdr.ls_age);
    ntoh_16it(op->ospf_lsu.lsu_lsa[1].ls_hdr.ls_age);
    ntos_32it(op->ospf_lsu.lsu_lsa[0].ls_hdr.ls_router.s_addr);
    ntos_32it(op->ospf_lsu.lsu_lsa[1].ls_hdr.ls_router.s_addr);
    ntos_32it(op->ospf_lsu.lsu_lsa[0].ls_hdr.ls_seq);
    ntos_32it(op->ospf_lsu.lsu_lsa[1].ls_hdr.ls_seq);
    ntoh_16it(op->ospf_lsu.lsu_lsa[0].ls_hdr.ls_chksum);
    ntoh_16it(op->ospf_lsu.lsu_lsa[1].ls_hdr.ls_chksum);
    ntoh_16it(op->ospf_lsu.lsu_lsa[0].ls_hdr.ls_length);
    ntoh_16it(op->ospf_lsu.lsu_lsa[1].ls_hdr.ls_length);
    ntos_32it(op->ospf_lsu.lsu_lsa[0].ls_hdr.lsa_id.s_addr);
    ntos_32it(op->ospf_lsu.lsu_lsa[1].ls_hdr.lsa_id.s_addr);

    for (int i=0; i<op->ospf_lsu.lsu_count; i++)
    {
        //need to check
        struct lsa * lsaPt=((struct lsa *)(op->ospf_lsu.lsu_lsa))+i;

        /*
        compare it with own LSDB,if it's newer:
            1. push the new lsa
            2. flooding it
            3. send back a lsuAck
        */
        deque<struct area *>::iterator itArea;
        struct lsdb_struct * oldLsaFound=NULL;

        for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
        {
            if (op->ospf_areaid.s_addr==(*itArea)->areaId)
            {
                        
                oldLsaFound = lsainLsdb((*itArea),lsaPt->ls_hdr.ls_seq);
                break;
            }
        }

        //whether it's newer
        bool newerFlag=false;


        bool type2Flag=true;
        struct lsdb_struct * newLsaP=new struct lsdb_struct;

        if ((oldLsaFound==NULL)||
                (lsaPt->ls_hdr.ls_type==LS_TYPE_NETWORK))
        {
            /*
            construct a new lsaDequeStruct deal to the packet
            */
            newLsaP->bornRtId=(lsaPt->ls_hdr.ls_router.s_addr);
            newLsaP->bornTime=(lsaPt->ls_hdr.ls_age);
            newLsaP->ls_type=lsaPt->ls_hdr.ls_type;
            newLsaP->seq=(lsaPt->ls_hdr.ls_seq);
            newLsaP->ls_id=(lsaPt->ls_hdr.lsa_id.s_addr);
            newLsaP->length=(lsaPt->ls_hdr.ls_length);

            printf("NEW LSA SEQ: %s\n",inet_ntostr(newLsaP->seq));

            //根据不同LSA类型分类
            if (lsaPt->ls_hdr.ls_type==LS_TYPE_ROUTER)
            {
                newLsaP->lsa_un.un_rla.link_id.s_addr=(lsaPt->lsa_un.un_rla.rla_link[0].link_id.s_addr);
                newLsaP->lsa_un.un_rla.link_data.s_addr=(lsaPt->lsa_un.un_rla.rla_link[0].link_data.s_addr);
                newLsaP->lsa_un.un_rla.link.link_type=lsaPt->lsa_un.un_rla.rla_link[0].un_tos.link.link_type;
                newLsaP->lsa_un.un_rla.link.link_tos_count=lsaPt->lsa_un.un_rla.rla_link[0].un_tos.link.link_tos_count;
                newLsaP->lsa_un.un_rla.link.tos_metric=ntohs(lsaPt->lsa_un.un_rla.rla_link[0].un_tos.link.tos_metric);
            }
            else if (lsaPt->ls_hdr.ls_type==LS_TYPE_NETWORK)
            {
                newLsaP->lsa_un.un_nla.nla_mask.s_addr=(lsaPt->lsa_un.un_nla.nla_mask.s_addr);
                newLsaP->lsa_un.un_nla.nla_router[0].s_addr=(lsaPt->lsa_un.un_nla.nla_router[0].s_addr);
                newLsaP->lsa_un.un_nla.nla_router[1].s_addr=(lsaPt->lsa_un.un_nla.nla_router[1].s_addr);
                newLsaP->lsa_un.un_nla.nla_router[2].s_addr=(lsaPt->lsa_un.un_nla.nla_router[2].s_addr);
                newLsaP->lsa_un.un_nla.nla_router[3].s_addr=(lsaPt->lsa_un.un_nla.nla_router[3].s_addr);
                newLsaP->lsa_un.un_nla.nla_router[4].s_addr=(lsaPt->lsa_un.un_nla.nla_router[4].s_addr);
            }
            else if (lsaPt->ls_hdr.ls_type==LS_TYPE_SUM_IP)
            {
            }
            else if (lsaPt->ls_hdr.ls_type==LS_TYPE_SUM_ABR)
            {
            }
            else if (lsaPt->ls_hdr.ls_type==LS_TYPE_ASE)
            {
            }
        }
        else
        {
            free(newLsaP);
        }

        if (oldLsaFound==NULL)
        {
//                usleep((getDDFirstRndSeq()/8000.)*10000);
            (*itArea)->lsaDequeInArea.push_back(newLsaP);
        }
        else if (lsaPt->ls_hdr.ls_type==LS_TYPE_NETWORK)
        {
            printf("network lsu flooding?: %d-%d\n",(oldLsaFound->length),(newLsaP->length));
            type2Flag=(oldLsaFound->length)<(newLsaP->length);
            *oldLsaFound=*newLsaP;
        }




        //=======Step 2: flooding
        if ( (oldLsaFound==NULL) ||
                (lsaPt->ls_hdr.ls_type==LS_TYPE_NETWORK&&type2Flag))
        {
            /*
            send a lsu to 224.0.0.5,
            except the src interface
            */
//                if (infDequeInArea!=NULL)
            struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
            //对area中的interface进行循环
            for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
            {
                if (cnctMap[infDequeInArea->inf->ip]!=ip->src.s_addr)
                {
                    sleep(0);
                    send_ls_update(infDequeInArea->inf,inet_addr("224.0.0.5"),newLsaP,
                            (parselsahdr(newLsaP)));
                }
            }

        }

        //========Step 3: send back a lsuAck
        if (ip->dst.s_addr!=inet_addr("224.0.0.5")&&ip->dst.s_addr!=inet_network("224.0.0.5"))
            //not a broadcast lsu
        {
            //找到接收到的interface
            struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
            //对area中的interface进行循环
            for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
            {
                if (infDequeInArea->inf->ip==ip->dst.s_addr)
                    if (infDequeInArea->inf->ip==ip->dst.s_addr)
                    {
                        break;
                    }
            }
//            if (infDequeInArea!=NULL&&newLsaP!=NULL)
            {
                printf("SEND LSACK TO %s\n",inet_ntoa(ip->src));
                if (newLsaP!=NULL)
                {
                    sleep(0);
                    send_ls_ack(infDequeInArea->inf,
                              parselsahdr(newLsaP));
                }
                else
                {
                    printf("err: newLsaP is NULL when lsack\n");
                }
            }
        }
    }
}




