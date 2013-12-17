#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<arpa/inet.h>

#include "global.h"
#include "stdnet.h"
#include "pkt.h"

using namespace std;


void * send_db_description(void * nowInf, struct nbr_struct * nbrStct, struct std_lsa_hdr * pLsaSend, bool initBool,bool moreBool,bool msBool)
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

    std_ptag_t t = std_build_ospfv2_dbd(0, 0x00, (initBool?DD_I:0x00)|(moreBool?DD_M:0x00)|(msBool?DD_MS:0x00), nbrStct->seqNum, (u_int8_t *)pLsaSend, pLsaSend==NULL?0:sizeof(struct lsa_hdr), l, 0);        

    t = std_build_data(auth, STD_OSPF_AUTH_H, l, 0);

    t = std_build_ospfv2(STD_OSPF_DBD_H + STD_OSPF_AUTH_H+(pLsaSend==NULL?0:sizeof(struct lsa_hdr)), STD_OSPF_DBD, htonl(nowRt.router_id), htonl(tmpnowInf->areain->areaId), 0, STD_OSPF_AUTH_NULL, NULL, 0, l, 0);

    t = std_build_ipv4(STD_IPV4_H + STD_OSPF_H +STD_OSPF_DBD_H + STD_OSPF_AUTH_H+(pLsaSend==NULL?0:sizeof(struct lsa_hdr)), 0, 101, IP_DF, 254, IPPROTO_OSPF, 0, src, dst, NULL, 0, l, 0);

    int c = std_write(l);
    printf("SEND %d BYTE OSPF DD PACKET....................\n", c);

    std_destroy(l);

}

void recv_db_description(const u_char * packet)
{
    struct ip_pkt* ip = (struct ip_pkt*)(packet + PKT_ETH_LEN);
    
    int sizeIp=IP_HL(ip)*4;

    struct ospfhdr * op=(struct ospfhdr *)(packet+PKT_ETH_LEN+sizeIp);
    op->ospf_routerid.s_addr=ntos_32(&(op->ospf_routerid.s_addr));
    op->ospf_areaid.s_addr=ntos_32(&(op->ospf_areaid.s_addr));
    
    ntoh_16it(op->ospf_db.db_ifmtu);
    ntos_32it(op->ospf_db.db_seq);
    //struct lsa_hdr
    ntoh_16it(op->ospf_db.db_lshdr[0].ls_age);
    ntoh_16it(op->ospf_db.db_lshdr[1].ls_age);
    ntos_32it(op->ospf_db.db_lshdr[0].ls_router.s_addr);
    ntos_32it(op->ospf_db.db_lshdr[1].ls_router.s_addr);
    ntos_32it(op->ospf_db.db_lshdr[0].ls_seq);
    ntos_32it(op->ospf_db.db_lshdr[1].ls_seq);
    ntoh_16it(op->ospf_db.db_lshdr[0].ls_chksum);
    ntoh_16it(op->ospf_db.db_lshdr[1].ls_chksum);
    ntoh_16it(op->ospf_db.db_lshdr[0].ls_length);
    ntoh_16it(op->ospf_db.db_lshdr[1].ls_length);
    ntos_32it(op->ospf_db.db_lshdr[0].lsa_id.s_addr);
    ntos_32it(op->ospf_db.db_lshdr[1].lsa_id.s_addr);

    printf("RECV  DB DESCRIPTION....................\n");

    //which neighbor machine?
    
    for(int i = 0; i < areaDeque.size(); i++)
    {
        
        struct infDeque * infDequeInArea=areaDeque[i]->infDequeInArea;
        //对area中的interface进行循环
        for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
        {
            
            for(int j = 0; j < infDequeInArea->inf->nbrDeque.size(); j++)
            {
                printf("NBR BELONG: %s-",inet_ntostr((infDequeInArea->inf->nbrDeque[j])->inf_ip));
                printf("%s\n",inet_ntoa(ip->src));
                //which neighbor machine
                if ((infDequeInArea->inf->nbrDeque[j])->inf_ip==(ip->src.s_addr))
                {
                    //whether the first DD packet
                    if ((op->ospf_db.db_flags==0x7))
                    {
                        printf("RECV FIRST DD\n");
                        
                        //routerID bigger ->>>>DR
                        if ((nowRt.router_id)>ntohl(op->ospf_routerid.s_addr))
                        {

                            printf("the Master1: %s\n",inet_ntostr(nowRt.router_id));
                            //(infDequeInArea->infNode->nbrDeque[j])->seqNum不变
                            (infDequeInArea->inf->nbrDeque[j])->master=1;
//                            ((infDequeInArea->infNode->nbrDeque[j])->seqNum)++;
                            (infDequeInArea->inf->nbrDeque[j])->startSeqNum=(infDequeInArea->inf->nbrDeque[j])->seqNum;
                        }
                        else
                        {
                            printf("the Master2: %s\n",inet_ntostr(htonl(op->ospf_routerid.s_addr)));
                            (infDequeInArea->inf->nbrDeque[j])->seqNum=(op->ospf_db.db_seq);
                            (infDequeInArea->inf->nbrDeque[j])->startSeqNum=(infDequeInArea->inf->nbrDeque[j])->seqNum;
                            (infDequeInArea->inf->nbrDeque[j])->master=0;
                            (infDequeInArea->inf->nbrDeque[j])->xchg=true;

                            //slave send the first DD packet

                            struct lsdb_struct * pLsaSend=NULL;
                            int betweenval=(infDequeInArea->inf->nbrDeque[j])->seqNum - (infDequeInArea->inf->nbrDeque[j])->startSeqNum;
//                            betweenval/=2;
                            
                            
                            for(int k = 0; k < (areaDeque[i]->lsaDequeInArea).size();k++)
                            {
                                //在这里根据seqNum和startSeqNum相减得到要发送到LSA编号
                                if (betweenval==0)
                                {
                                    pLsaSend=areaDeque[i]->lsaDequeInArea[k];
                                    break;
                                }
                                betweenval--;
                            }

                            printf("Exchange a DD packet..................\n");
                            if (pLsaSend!=NULL)
                            {
                                (infDequeInArea->inf->nbrDeque[j])->xchg=true;
                                printf("SEND ONE MORE DD..................\n");
                                //没有发送完LSA
                                send_db_description(infDequeInArea->inf,
                                            (infDequeInArea->inf->nbrDeque[j]),
                                            parselsahdr(pLsaSend),
                                            false,true,false);
                            }
                            else 
                            {
                                (infDequeInArea->inf->nbrDeque[j])->xchg=true;
                                printf("NO MORE DD..............\n");
                                send_db_description(infDequeInArea->inf,
                                            (infDequeInArea->inf->nbrDeque[j]),
                                            NULL,
                                            false,false,false);
                            }
//                            (infDequeInArea->infNode->nbrDeque[j])->seqNum+=2;
                            (infDequeInArea->inf->nbrDeque[j])->seqNum+=1;
                        }
                    }
                    else if ((op->ospf_db.db_flags==0x0))
                    {

                        (infDequeInArea->inf->nbrDeque[j])->xchg=true;
                        printf("LAST DD\n");
                        
                        //this is the last DD from nbr,
                        //sent all own LSA head by DD once,
                        //and, send a end packet(flags==0x0)

                        struct lsdb_struct * pLsaSend=(struct lsdb_struct *)(1);
                        while (pLsaSend!=NULL)
                        {
                            //decide the contents of sending DD
                            pLsaSend=NULL;
                            int betweenval=(infDequeInArea->inf->nbrDeque[j])->seqNum - (infDequeInArea->inf->nbrDeque[j])->startSeqNum;
                            betweenval/=1;
                            
                            for(int k = 0; k < (areaDeque[i]->lsaDequeInArea).size();k++)
                            {
                                //在这里根据seqNum和startSeqNum相减得到要发送到LSA编号
                                if (betweenval==0)
                                {
                                    pLsaSend=areaDeque[i]->lsaDequeInArea[k];
                                    break;
                                }
                                betweenval--;
                            }

                            if (pLsaSend==NULL)
                            {

                                break;
                            }
                            else
                            {
                                send_db_description(infDequeInArea->inf, (infDequeInArea->inf->nbrDeque[j]), parselsahdr(pLsaSend), false,true,false);
                                (infDequeInArea->inf->nbrDeque[j])->seqNum+=1;
                            }
                        }
                    }
                    else
                    {
                        // NOT THE FIRST, NOR THE LAST
                        (infDequeInArea->inf->nbrDeque[j])->xchg=true;
                        /*
                        不是第一个DD报文
                        */
                        //决定发送LSA的内容
                        struct lsdb_struct * pLsaSend=NULL;
                        int betweenval=(infDequeInArea->inf->nbrDeque[j])->seqNum - (infDequeInArea->inf->nbrDeque[j])->startSeqNum;
                        betweenval/=1;
                        
                        for(int k = 0; k < (areaDeque[i]->lsaDequeInArea).size();k++)
                        {
                            //在这里根据seqNum和startSeqNum相减得到要发送到LSA编号
                            if (betweenval==0)
                            {
                                pLsaSend=areaDeque[i]->lsaDequeInArea[k];
                                break;
                            }
                            betweenval--;
                        }

                        if (pLsaSend!=NULL)
                        {
                            send_db_description(infDequeInArea->inf, (infDequeInArea->inf->nbrDeque[j]),parselsahdr(pLsaSend),false,true,false);
                        }
                        else  
                        {
                            send_db_description(infDequeInArea->inf, (infDequeInArea->inf->nbrDeque[j]), NULL, false,false,false);
                        }
                        (infDequeInArea->inf->nbrDeque[j])->seqNum+=1;
                    }

                    //check whether need LSR

                    if(lsainLsdb(areaDeque[i],op->ospf_db.db_seq))    
                    {
                        //do nothing
                    }
                    else
                    {
                        if ((op->ospf_db.db_flags!=0x0))
                        {
                            //发送LSR报文
                            if (((op->ospf_db.db_lshdr)[0]).ls_type>=1&&
                                    ((op->ospf_db.db_lshdr)[0]).ls_type<=5)
                            {
                                send_ls_req(infDequeInArea->inf, (infDequeInArea->inf->nbrDeque[j]), (((op->ospf_db.db_lshdr)[0]).ls_type), (((op->ospf_db.db_lshdr)[0]).ls_type==2)?(((op->ospf_db.db_lshdr)[0]).lsa_id.s_addr):(((op->ospf_db.db_lshdr)[0]).ls_router.s_addr), ((op->ospf_db.db_lshdr)[0]).ls_router.s_addr);
                            }
                        }
                    }
                }
            }
        }

    }

}

struct lsdb_struct * lsainLsdb(struct area *area, u_int32_t seq)
{
    for(int i = 0; i < (area->lsaDequeInArea).size(); i++)
    {
        if(((area->lsaDequeInArea[i])->seq)==seq)
            return(area->lsaDequeInArea[i]);
    }
    return NULL;
}


void ddsrand()
{
    srand(time(NULL)*(nowRt.router_id+1));
}

u_int32_t gen1stDDSeq()
{
    return rand() % 8000;
}
