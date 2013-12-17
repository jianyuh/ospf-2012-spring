
#include <stdio.h>
#include <arpa/inet.h>
#include <list>
#include <map>
#include <unistd.h>

#include "precv.h"
#include "stdnet.h"
#include "global.h"
#include "pkt.h"

using namespace std;

void recv_packet(u_char *args,const struct pcap_pkthdr * header,const u_char * packet)
{

    //+16????????????
    struct ip_pkt* ip = (struct ip_pkt*)(packet + PKT_ETH_LEN);
    //printf("%d\n",ip->ip_p);

    //seize an ospf Packet
    if (ip->pro==89)
    {
        int sizeIp=IP_HL(ip)*4;
        //跳转到OSPF报文
        struct ospfhdr * ospf=(struct ospfhdr *)(packet+PKT_ETH_LEN+sizeIp);
        
        //struct ospfhdr *ospf =(struct ospfhdr *)(ip + sizeIp);

        int ospfLen;
        ospfLen=ntoh_16(&(ospf->ospf_len));

        //const u_char * ospfEnd=packet + PKT_ETH_LEN+ospfLen;
        
        
        

        ospf->ospf_routerid.s_addr=ntos_32(&(ospf->ospf_routerid.s_addr));
        ospf->ospf_areaid.s_addr=ntos_32(&(ospf->ospf_areaid.s_addr));

        //不能是本机发的
        //需要过滤掉自己的报文
        bool selfFlag=false;
        bool cnct=false;
        deque<struct area *>::iterator itArea;
        for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
        {
//            if (selfFlag)
//                break;
            if (ospf->ospf_areaid.s_addr==(*itArea)->areaId)
            {
                break;
            }
        }
        struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
        //对area中到interface进行循环
        for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
        {
            //是本机
            if ((ip->src.s_addr)==(infDequeInArea->inf->ip))
            {
                selfFlag=true;
                break;
            }
        }

        bool cnctBool=false;
        if ((ip->dst.s_addr==(inet_addr("224.0.0.5")))||true)
        {
            struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
            //对area中到interface进行循环
            for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
            {
                //have found connect bool
                if ( (cnctMap.count(ip->src.s_addr)>0&&(cnctMap[(ip->src.s_addr)]==(infDequeInArea->inf->ip)))||
                        (cnctMap.count(ntohl(ip->src.s_addr))>0&&(cnctMap[ntohl(ip->src.s_addr)]==(infDequeInArea->inf->ip)))
                   )
                {
                    cnctBool=true;
                    break;
                }
            }

        }

        sleep(0);
        char * ospfPktType[]= {"","Hello","DD","LSR","LSU","LSAck"};
        
        if ((selfFlag==false)&&(cnctBool==true))
        {
            if (ospf->ospf_type!=1)
            {
                printf("RECV OSPF PKT: %s -> ",inet_ntoa(ip->src));
                printf("%s\n",inet_ntoa(ip->dst));
                printf("OSPFv%d - TYPE: %s, len: %d\n",ospf->ospf_version,ospfPktType[(ospf->ospf_type)],ospfLen);
                printf("\tRouter ID: %s\n",inet_ntoa(ospf->ospf_routerid));
                printf("\tArea ID: %s\n",inet_ntoa(ospf->ospf_areaid));
            }

            if (ospf->ospf_type==OSPF_TYPE_HELLO)
            {
                recv_hello(packet);
            }
            else if (ospf->ospf_type==OSPF_TYPE_DD)
            {
                recv_db_description(packet);
            }
            else if (ospf->ospf_type==OSPF_TYPE_LS_REQ)
            {
                recv_ls_req(packet);
            }
            else if (ospf->ospf_type==OSPF_TYPE_LS_UPDATE)
            {
                recv_ls_update(packet);
            }
            else if (ospf->ospf_type==OSPF_TYPE_LS_ACK)
            {
                recv_ls_ack(packet);
            }
        }
        else if (selfFlag)
        {
              //errorprint(RECVPKTERRO, "RECV SELF'S PKT");
        }
        else if (cnctBool==false)
        {
              //errorprint(RECVPKTERRO, "DON'T CONNECT DIRECTLY");
        }
    }
}

void * recvPkt(void * none)
{
    recv_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle=recv_open_live("any",65535,1,-1,errbuf);
    if (handle==NULL)
    {
        printf("%s\n",errbuf);
    }

    recv_loop(handle,0,recv_packet,NULL);
}

