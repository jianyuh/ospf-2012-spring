#include<stdio.h>
#include<arpa/inet.h>
#include<string.h>
#include<unistd.h>
#include<map>
#include<deque> 
#include<time.h>

#include "stdnet.h"
#include "precv.h"
#include "pkt.h"
#include "global.h"

using namespace std;


//send hello packet
std_ptag_t ospf_helloseen(uint32_t netmask, uint16_t interval, uint8_t opts, uint8_t priority, uint32_t dead_int, uint32_t des_rtr, uint32_t bkup_rtr, const uint8_t *payload, uint32_t payload_s, std_t *l, std_ptag_t ptag,uint32_t neighbor)
{
    uint32_t n, h;
    std_pblock_t *p;
    struct std_ospf_hello_hdr hello_hdr;

    if (l == NULL)
    {
        return (-1);
    }

    n = STD_OSPF_HELLO_H + payload_s;
    h = 0;

    p = std_pblock_probe(l, ptag, n, STD_PBLOCK_OSPF_HELLO_H);
    if (p == NULL)
    {
        return (-1);
    }

    memset(&hello_hdr, 0, sizeof(hello_hdr));
    hello_hdr.hello_nmask.s_addr    = netmask;  //Netmask
    hello_hdr.hello_intrvl          = htons(interval);	// # seconds since last packet sent 
    hello_hdr.hello_opts            = opts;     //OSPF_* options
    hello_hdr.hello_rtr_pri         = priority; // If 0, can't be backup
    hello_hdr.hello_dead_intvl      = htonl(dead_int); // Time til router is deemed down
    hello_hdr.hello_des_rtr.s_addr  = des_rtr;	// Networks designated router
    hello_hdr.hello_bkup_rtr.s_addr = bkup_rtr; // Networks backup router
    hello_hdr.hello_nbr.s_addr      = htonl(neighbor);

    n = std_pblock_append(l, p, (uint8_t *)&hello_hdr, STD_OSPF_HELLO_H);
    if (n == -1)
    {
        goto bad;
    }

    return (ptag ? ptag : std_pblock_update(l, p, h, STD_PBLOCK_OSPF_HELLO_H));
bad:
    std_pblock_delete(l, p);
    return (-1);
}


std_ptag_t ospf_helloraw(uint32_t netmask, uint16_t interval, uint8_t opts, uint8_t priority, uint32_t dead_int, uint32_t des_rtr, uint32_t bkup_rtr, const uint8_t *payload, uint32_t payload_s, std_t *l, std_ptag_t ptag)
{
    uint32_t n, h;
    std_pblock_t *p;
    struct std_ospf_helloraw_hdr hello_hdr;

    if (l == NULL)
    {
        return (-1);
    }

    n = STD_OSPF_HELLO_H + payload_s;
    h = 0;

    p = std_pblock_probe(l, ptag, n, STD_PBLOCK_OSPF_HELLO_H);
    if (p == NULL)
    {
        return (-1);
    }

    memset(&hello_hdr, 0, sizeof(hello_hdr));
    hello_hdr.hello_nmask.s_addr    = netmask;  //Netmask
    hello_hdr.hello_intrvl          = htons(interval);	// # seconds since last packet sent 
    hello_hdr.hello_opts            = opts;     //OSPF_* options
    hello_hdr.hello_rtr_pri         = priority; // If 0, can't be backup
    hello_hdr.hello_dead_intvl      = htonl(dead_int); // Time til router is deemed down
    hello_hdr.hello_des_rtr.s_addr  = des_rtr;	// Networks designated router
    hello_hdr.hello_bkup_rtr.s_addr = bkup_rtr; // Networks backup router

    n = std_pblock_append(l, p, (uint8_t *)&hello_hdr, STD_OSPF_HELLO_H);
    if (n == -1)
    {
        goto bad;
    }

    return (ptag ? ptag : std_pblock_update(l, p, h, STD_PBLOCK_OSPF_HELLO_H));
bad:
    std_pblock_delete(l, p);
    return (-1);
}



char * inet_ntostr(u_int32_t addrnet)
{
    in_addr t;
    t.s_addr=addrnet;
    return inet_ntoa(t);
}


struct std_lsa_hdr * parselsahdr(struct lsdb_struct * lsa)
{
    if (lsa==NULL)
    {
        return NULL;
    }

    //struct std_lsa_hdr *lsa_hdr=(struct std_lsa_hdr *)malloc(sizeof(struct std_lsa_hdr));
    struct std_lsa_hdr *lsa_hdr=new struct std_lsa_hdr;

    memset(lsa_hdr, 0, sizeof(lsa_hdr));

    lsa_hdr->lsa_age         = htons(lsa->bornTime);
    lsa_hdr->lsa_opts        = 0;
    lsa_hdr->lsa_type        = lsa->ls_type;

    lsa_hdr->lsa_id          = htonl(lsa->ls_id);
    lsa_hdr->lsa_adv.s_addr  = htonl(lsa->bornRtId);
    lsa_hdr->lsa_seq         = htonl(lsa->seq);
    lsa_hdr->lsa_sum         = 0;
    lsa_hdr->lsa_len         = htons(lsa->ls_type==2?32:36);

    return lsa_hdr;
}



void * sendHelloPkt(void * nowInf)
{
    struct inf_struct * tmpNowInf=(struct inf_struct *)nowInf;
    std_t *l;
    char errbuf[STD_ERRBUF_SIZE];
    u_char auth[8] = {0,0,0,0,0,0,0,0};

    while (1)
    {
        l=std_init(STD_RAW4, tmpNowInf->name, errbuf);
        if (l==NULL)
        {
            fprintf(stderr, "std_init() failed: %s", errbuf);
        }
        u_int32_t src, dst;
        src = tmpNowInf->ip;
        dst = std_name2addr4(l, "224.0.0.5", LIBNET_DONT_RESOLVE);

        //std_ptag_t t = ospf_helloseen(tmpNowInf->mask, HELLO_INTERVAL, 0x00, 0x01, ROUTERDEADINTERVAL, tmpNowInf->dr, tmpNowInf->bdr, NULL, 0, l, 0,0xffffffff);
        std_ptag_t t = ospf_helloraw(tmpNowInf->mask, HELLO_INTERVAL, 0x00, 0x01, ROUTERDEADINTERVAL, tmpNowInf->dr, tmpNowInf->bdr, NULL, 0, l, 0);

        t = std_build_data(auth,STD_OSPF_AUTH_H,l,0);

        t = std_build_ospfv2(STD_OSPF_HELLO_H-4 + STD_OSPF_AUTH_H, STD_OSPF_HELLO, htonl(nowRt.router_id), htonl(tmpNowInf->areain->areaId), 0, STD_OSPF_AUTH_NULL, NULL, 0, l, 0); 
        
        #define IP_DF 0x4000
        
        t = std_build_ipv4(STD_IPV4_H + STD_OSPF_H + STD_OSPF_HELLO_H + STD_OSPF_AUTH_H, 0, 101,IP_DF, 254, IPPROTO_OSPF, 0, src, dst, NULL, 0, l, 0);

        int c = std_write(l);
        printf("SEND %d BYTE OSPF HELLO PACKET................\n", c);

        std_destroy(l);
        sleep(HELLO_INTERVAL);
    }
}

void * sendHelloSeen(void * nowInf,u_int32_t seenNbr)
{
    struct inf_struct * tmpNowInf=(struct inf_struct *)nowInf;
    std_t *l;
    char errbuf[STD_ERRBUF_SIZE];
    u_char auth[8] = {0,0,0,0,0,0,0,0};

    for (int seenTime=0; seenTime<2; seenTime++)
    {
        l=std_init(STD_RAW4, tmpNowInf->name, errbuf);

        if (l==NULL)
        {
            fprintf(stderr, "std_init() failed: %s", errbuf);
        }

        u_int32_t src, dst;
        src = tmpNowInf->ip;
        dst = std_name2addr4(l, "224.0.0.5", LIBNET_DONT_RESOLVE);

        std_ptag_t t = ospf_helloseen(tmpNowInf->mask, HELLO_INTERVAL,0x00,0x01, ROUTERDEADINTERVAL,tmpNowInf->dr, tmpNowInf->bdr, NULL, 0, l,  0,seenNbr);                         

        t = std_build_data(auth, STD_OSPF_AUTH_H, l, 0); 

        t = std_build_ospfv2( STD_OSPF_HELLO_H + STD_OSPF_AUTH_H, STD_OSPF_HELLO, htonl(nowRt.router_id), htonl(tmpNowInf->areain->areaId), 0, STD_OSPF_AUTH_NULL,  NULL, 0, l, 0); 

        t = std_build_ipv4(STD_IPV4_H + STD_OSPF_H +  STD_OSPF_HELLO_H + STD_OSPF_AUTH_H, 0, 101, IP_DF, 254, IPPROTO_OSPF, 0, src, dst, NULL, 0, l, 0); 

        int c = std_write(l);
        printf("SEND %d BYTE OSPF HELLO SEEN PACKET....................\n", c);

        sleep(HELLO_INTERVAL);

        std_destroy(l);
    }
}



void * keep(void * none)
{
    while (1)
    {
        deque<struct area *>::iterator itArea;
        for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
        {
            struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
            //对area中的interface进行循环
            for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
            {
                //检查live时间
                deque<struct nbr_struct *>::iterator itNbr=infDequeInArea->inf->nbrDeque.begin();
                for (; itNbr!=infDequeInArea->inf->nbrDeque.end(); itNbr++)
                {
                    long timeNowT=time(NULL);
                    if ((timeNowT-((*itNbr)->lastHelloTime))>40)
                    {
                        printf("MORE THAN 40s-->DEAD");
                    }
                }
            }

        }
        sleep(HELLO_INTERVAL);
    }
}




bool listenInterval=true;
bool firstAfterInterval=true;

void recv_hello(const u_char * packet)
{
    struct ip_pkt* ip = (struct ip_pkt*)(packet + PKT_ETH_LEN);
    
    int sizeIp=IP_HL(ip)*4;

    struct ospfhdr * op=(struct ospfhdr *)(packet+PKT_ETH_LEN+sizeIp);
    op->ospf_routerid.s_addr=ntos_32(&(op->ospf_routerid.s_addr));
    op->ospf_areaid.s_addr=ntos_32(&(op->ospf_areaid.s_addr));
    
    ntos_32it(op->ospf_hello.hello_mask.s_addr);
    ntoh_16it(op->ospf_hello.hello_helloint);
    ntos_32it(op->ospf_hello.hello_deadint);
    ntos_32it(op->ospf_hello.hello_dr.s_addr);
    ntos_32it(op->ospf_hello.hello_bdr.s_addr);
    ntos_32it(op->ospf_hello.hello_neighbor[0].s_addr);
    ntos_32it(op->ospf_hello.hello_neighbor[1].s_addr);

    deque<struct area *>::iterator itArea;
    if (listenInterval)
    {
        //对area循环
        for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
        {
            if (op->ospf_areaid.s_addr==(*itArea)->areaId)
            {
                struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
                //对area中到interface进行循环
                for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
                {
                    //the same network
                    if (((ip->src.s_addr)&htonl(op->ospf_hello.hello_mask.s_addr))==
                            ((infDequeInArea->inf->ip&infDequeInArea->inf->mask)))
                    {
                        if (op->ospf_hello.hello_dr.s_addr!=0)
                        {
                            printf("HAS DR\n");
                            //这个网段有DR存在了
                            infDequeInArea->inf->drFlag=true;
                            infDequeInArea->inf->dr=op->ospf_hello.hello_dr.s_addr;
                            infDequeInArea->inf->bdr=op->ospf_hello.hello_bdr.s_addr;

                            //there's no necessary to listen a DR
                            listenInterval=false;
                        }
                        else if (infDequeInArea->inf->drFlag==false)     //没有DR,那么选举
                        {
                            //属于合法的选民
                            if (op->ospf_hello.hello_priority>0)
                            {
                                //比较priority
                                if ((op->ospf_hello.hello_priority) > (infDequeInArea->inf->rtmaxPri_dr))
                                {
                                    printf("%s's new DR: ",inet_ntostr(infDequeInArea->inf->ip));
                                    printf("%s\n",inet_ntoa(ip->src));

                                    //infDequeInArea->infNode->rtIdMax_dr_slct=-1;
                                    infDequeInArea->inf->rtmaxId_dr=2147483647;
                                    //这里选出的应该是一个接口地址
                                    infDequeInArea->inf->dr_slt=ip->src.s_addr;
                                    infDequeInArea->inf->rtmaxPri_dr=op->ospf_hello.hello_priority;

                                }
                                else if (op->ospf_hello.hello_priority == infDequeInArea->inf->rtmaxPri_dr)
                                {
                                    //printf("DR select_routerid: now:%s(%d)",inet_ntoa(op->ospf_routerid),op->ospf_routerid.s_addr);
                                    //printf("<---->old:%s(%d)\n", inet_ntostr(infDequeInArea->infNode->rtmaxId_dr), infDequeInArea->infNode->rtmaxId_dr);

                                    //比较router id
                                    if ((op->ospf_routerid.s_addr) < (infDequeInArea->inf->rtmaxId_dr))
                                    {
                                        printf("%s's new DR: ",inet_ntostr(infDequeInArea->inf->ip));
                                        printf("%s\n",inet_ntoa(ip->src));

                                        //这里选出的应该是一个接口地址
                                        infDequeInArea->inf->dr_slt=ip->src.s_addr;
                                        infDequeInArea->inf->rtmaxId_dr=op->ospf_routerid.s_addr;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        if (firstAfterInterval)
        {
            firstAfterInterval=false;

            for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
            {
                //deque<struct interface_struct *>::iterator itItf;
                struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
                //对area中到interface进行循环
                for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
                {
                    infDequeInArea->inf->drFlag=true;
                    infDequeInArea->inf->dr=infDequeInArea->inf->dr_slt;

                    printf("%s's DR: ",inet_ntostr(infDequeInArea->inf->ip));
                    printf("%s\n",inet_ntostr(infDequeInArea->inf->dr_slt));


                    //produce a type_1 LSA

                    struct lsdb_struct * lsaNodeTemp=new struct lsdb_struct;

                    lsaNodeTemp->bornTime=(time(NULL));

                    lsaNodeTemp->bornRtId=nowRt.router_id;

                    //in the Router LSA, the lsa id is the adv_rtr_id
                    lsaNodeTemp->ls_id=nowRt.router_id;

                    lsaNodeTemp->seq=(nowRt.router_id + (*itArea)->areaId*100 + (*itArea)->lsaDequeInArea.size());

                    //it's the router lsa
                    lsaNodeTemp->ls_type=1;

                    lsaNodeTemp->lsa_un.un_rla.link_id.s_addr=(infDequeInArea->inf->dr_slt);

                    lsaNodeTemp->lsa_un.un_rla.link_data.s_addr=(infDequeInArea->inf->ip);

                    //transit
                    lsaNodeTemp->lsa_un.un_rla.link.link_type=(2);

                    lsaNodeTemp->lsa_un.un_rla.link.tos_metric=(infDequeInArea->inf->cost);
                    printf("\tlsa metric: %d\n",lsaNodeTemp->lsa_un.un_rla.link.tos_metric);

                    ((*itArea)->lsaDequeInArea).push_back(lsaNodeTemp);
                }
            }
        }
        
        //这时候用hello报文建立邻接关系
        //检查收到的报文src是否为邻接关系，如果不是那么就回复hello建立邻接
        //是同一个网段才可以
        //src是DR
        //接收方是DR
        
        for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
        {
            if (op->ospf_areaid.s_addr==(*itArea)->areaId)
            {
                struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;

                //对area中的interface进行循环
                for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
                {
                    //每次收到时更新live时间
                    deque<struct nbr_struct *>::iterator itNbr=infDequeInArea->inf->nbrDeque.begin();
                    for (; itNbr!=infDequeInArea->inf->nbrDeque.end(); itNbr++)
                    {
                        if (((*itNbr)->router_id==op->ospf_routerid.s_addr)&&((*itNbr)->area_id==op->ospf_areaid.s_addr))
                        {
                            //更新live时间
                            (*itNbr)->lastHelloTime=time(NULL);
                            break;
                        }
                    }

                    //同一个网段
                  if (((ip->src.s_addr)&htonl(op->ospf_hello.hello_mask.s_addr))==
                            ((infDequeInArea->inf->ip&infDequeInArea->inf->mask)))
                    {
                        //3.被hello seen了
                        //2.接收方是DR
                        //1.src是DR
                        if ( ((infDequeInArea->inf->ip)==htonl(op->ospf_hello.hello_dr.s_addr)) ||
                                ((ip->src.s_addr)==htonl(op->ospf_hello.hello_dr.s_addr))
                                ||(nowRt.router_id==htonl(op->ospf_hello.hello_neighbor[0].s_addr)) )
                        {
                            //先判断是否建立了邻接（已经在邻接列表了）
                            bool inNbrDequeFlag=false;

                            itNbr=infDequeInArea->inf->nbrDeque.begin();
                            for (; itNbr!=infDequeInArea->inf->nbrDeque.end(); itNbr++)
                            {
                                if (((*itNbr)->router_id==op->ospf_routerid.s_addr)&&((*itNbr)->area_id==op->ospf_areaid.s_addr))
                                {
                                    inNbrDequeFlag=true;
                                    break;
                                }
                            }

                            if (!inNbrDequeFlag)
                            {
                                printf("%s seen ",inet_ntostr(infDequeInArea->inf->ip));
                                printf("%s\n",inet_ntoa(op->ospf_routerid));
                                //reply with hello packet(neighbor seen)
                                sleep(0);
                                sendHelloSeen(infDequeInArea->inf, op->ospf_routerid.s_addr);

                                //加入到邻接列表当中
                                //邻接属于interface
                                //其实这个时候只要和自己建立邻接（非DR）
                                //要1:n（DR）

                                struct nbr_struct * nbrTemp=new struct nbr_struct;

                                nbrTemp->router_id=htonl(op->ospf_routerid.s_addr);
                                nbrTemp->inf_ip=ip->src.s_addr;
                                nbrTemp->area_id=htonl(op->ospf_areaid.s_addr);
                                nbrTemp->lastHelloTime=time(NULL);
                                nbrTemp->startSeqNum=nbrTemp->seqNum=gen1stDDSeq();
                                nbrTemp->infNow=infDequeInArea->inf;

                                nbrTemp->exchangeNum=0;

                                nbrTemp->xchg=false;

                                infDequeInArea->inf->nbrDeque.push_back(nbrTemp);

                                printf("SEND DD: %s->",inet_ntostr(infDequeInArea->inf->ip));
                                printf("%s\n",inet_ntostr(nbrTemp->inf_ip));
                                //这里的第一个就是为了选出Master和Slave
                                send_db_description(infDequeInArea->inf,
                                            nbrTemp,
                                            parselsahdr(NULL),
                                            true,true,true
                                           );
                            }
                        }
                    }
                }
            }
        }

    }

}


void * DRdetect(void * none)
{
    recv_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    listenInterval=true;

    handle=recv_open_live("any",65535,1,-1,errbuf);
    if (handle==NULL)
    {
        printf("%s\n",errbuf);
    }

    printf("Listening DR...................................\n");
    recv_loop(handle,16,recv_packet,NULL);
    printf("END:Listening DR...............................\n");
    listenInterval=false;
}





