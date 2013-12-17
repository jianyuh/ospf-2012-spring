#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <map>
#include <deque>

#include "stdnet.h"
#include "global.h"
#include "pkt.h"

using namespace std;


#define OUT_LSDB_INTERVAL 25

#define TABLE_SIZE 50

#define UNREACH 99999

struct VertexSt
{
    int type;
    int idx;
    union
    {
        struct
        {
            uint32_t routerId;
        } rtr;

        struct
        {
            uint32_t ip;
            uint32_t mask;
        } stub;
    } un;
};


map<int,struct VertexSt *> VertexMap;
deque<struct VertexSt *> VertexDeque;

int Graph[TABLE_SIZE][TABLE_SIZE];

void addVertex_Rt(uint32_t rtridF)
{
    if (VertexMap.count(rtridF*2+1)>0)
    {
        return ;
    }

    struct VertexSt * tempVertex=new struct VertexSt;
    tempVertex->type=1;
    tempVertex->idx=VertexDeque.size();
    tempVertex->un.rtr.routerId=rtridF;

    VertexMap[rtridF*2+1]=(tempVertex);
    VertexDeque.push_back(tempVertex);

    printf("Node %d(%s):%s\n\n",
           (tempVertex)->idx,
           (tempVertex)->type==1?"router":"stub",
           (tempVertex)->type==1?inet_ntostr((tempVertex)->un.rtr.routerId):inet_ntostr((tempVertex)->un.stub.ip&(tempVertex)->un.stub.mask));
}

void addVertex_St(uint32_t ipF,uint32_t maskF)
{
    if (VertexMap.count((ipF&maskF)*2)>0)
    {
        return ;
    }

    struct VertexSt * tempVertex=new struct VertexSt;
    tempVertex->type=2;
    tempVertex->idx=VertexDeque.size();
    tempVertex->un.stub.ip=ipF;
    tempVertex->un.stub.mask=maskF;

    VertexMap[(ipF&maskF)*2]=(tempVertex);
    VertexDeque.push_back(tempVertex);

    printf("Node %d(%s):%s\n\n",
           (tempVertex)->idx,
           (tempVertex)->type==1?"router":"stub",
           (tempVertex)->type==1?inet_ntostr((tempVertex)->un.rtr.routerId):
           inet_ntostr((tempVertex)->un.stub.ip&(tempVertex)->un.stub.mask));
}

void initGraph()
{
    for (int i=0; i<TABLE_SIZE; i++)
    {
        for (int j=0; j<TABLE_SIZE; j++)
        {
            Graph[i][j]=UNREACH;
        }
    }
}

int transMetric(uint32_t ipF,uint32_t maskF, uint32_t rtrIdF, struct area * itArea)
{
    //printf("getTransMetric(%s,",inet_ntostr(ipF&maskF));
    //printf("%s)=",inet_ntostr(rtrIdF));

    deque<struct lsdb_struct *>::iterator itLsaScan=(itArea)->lsaDequeInArea.begin();
    for (; itLsaScan!=(itArea)->lsaDequeInArea.end(); itLsaScan++)
    {
        if ((*itLsaScan)->ls_type==1&&
                (*itLsaScan)->lsa_un.un_rla.link.link_type==2)
        {
            bool flag1=((*itLsaScan)->lsa_un.un_rla.link_data.s_addr&maskF)==(ipF&maskF);
            bool flag2=((*itLsaScan)->lsa_un.un_rla.link_id.s_addr&maskF)==(ipF&maskF);

            if (flag1||flag2)
            {
                printf("%d\n",(*itLsaScan)->lsa_un.un_rla.link.tos_metric);

                return (*itLsaScan)->lsa_un.un_rla.link.tos_metric;
            }
        }
    }
}


//node-node
void addEdge_NtoN(uint32_t rtrNode1,uint32_t rtrNode2,int metricFunc)
{
    printf("ADD edge1: %d-------%d-------%d\n",VertexMap[rtrNode1*2+1]->idx,metricFunc,VertexMap[rtrNode2*2+1]->idx);

    Graph[VertexMap[rtrNode1*2+1]->idx][VertexMap[rtrNode2*2+1]->idx]=metricFunc;
    Graph[VertexMap[rtrNode2*2+1]->idx][VertexMap[rtrNode1*2+1]->idx]=metricFunc;
}


//node-stub
void addEdge_NtoS(uint32_t rtrNode1,uint32_t hash1,uint32_t hash2,int metricFunc)
{
    printf("ADD edge2: %d-------%d-------%d\n", VertexMap[rtrNode1*2+1]->idx, metricFunc, VertexMap[(hash1&hash2)*2]->idx);
    Graph[VertexMap[rtrNode1*2+1]->idx][VertexMap[(hash1&hash2)*2]->idx]=metricFunc;
    Graph[VertexMap[(hash1&hash2)*2]->idx][VertexMap[rtrNode1*2+1]->idx]=metricFunc;
}

uint32_t getRtNextJump(uint32_t toRtr,uint32_t fromRtr)
{
    return rtrRtrCnnt[fromRtr&0x000f][toRtr&0x000f];
}

void * genspf()
{
    initGraph();

    FILE * spfF=fopen(outfile,"w");

    //A: get the whole graph
    deque<struct area *>::iterator itArea;
    //对area循环
    for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
    {
        deque<struct lsdb_struct *>::iterator itLsaScan=(*itArea)->lsaDequeInArea.begin();
        for (; itLsaScan!=(*itArea)->lsaDequeInArea.end(); itLsaScan++)
        {
            if ((*itLsaScan)->ls_type==2)
                //network lsa
            {
                for (int i=0; i<((*itLsaScan)->length-24)/4; i++)
                {
                    addVertex_Rt( (*itLsaScan)->lsa_un.un_nla.nla_router[i].s_addr );

                    printf("A.add vertex1: %s\n",
                           inet_ntostr((*itLsaScan)->lsa_un.un_nla.nla_router[i].s_addr));
                }
            }
            else if ((*itLsaScan)->ls_type==1)
                //rtr lsa
            {
                if ((*itLsaScan)->lsa_un.un_rla.link.link_type==1)
                    //Point To Point
                {
                    addVertex_Rt( (*itLsaScan)->lsa_un.un_rla.link_id.s_addr );
                    addVertex_Rt( (*itLsaScan)->bornRtId );

                    printf("B.add vertex1: %s\n",
                           inet_ntostr((*itLsaScan)->lsa_un.un_rla.link_id.s_addr));
                    printf("B.add vertex1: %s\n",
                           inet_ntostr((*itLsaScan)->bornRtId));
                }
                else if ((*itLsaScan)->lsa_un.un_rla.link.link_type==3)
                    //STUB
                {
                    addVertex_St( ((*itLsaScan)->lsa_un.un_rla.link_id.s_addr) , ((*itLsaScan)->lsa_un.un_rla.link_data.s_addr) );

                    printf("C.add vertex2: %s\n",
                           inet_ntostr(((*itLsaScan)->lsa_un.un_rla.link_id.s_addr)&((*itLsaScan)->lsa_un.un_rla.link_data.s_addr)));
                }
            }
        }
    }

    printf("ALL VERTEX FOUND\n");

    for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
    {
        deque<struct lsdb_struct *>::iterator itLsaScan;
        for (itLsaScan=(*itArea)->lsaDequeInArea.begin(); itLsaScan!=(*itArea)->lsaDequeInArea.end(); itLsaScan++)
        {
            if (((*itLsaScan)->ls_type)==2)
                //network lsa
            {
                for (int i=1; i<((*itLsaScan)->length-24)/4; i++)
                {
                    printf("NET edge\n");
                    int metricEdge;

                    metricEdge=transMetric((*itLsaScan)->ls_id,
                                              (*itLsaScan)->lsa_un.un_nla.nla_mask.s_addr,
                                              (*itLsaScan)->lsa_un.un_nla.nla_router[0].s_addr,
                                              *itArea);

                    addEdge_NtoN( (*itLsaScan)->lsa_un.un_nla.nla_router[0].s_addr , (*itLsaScan)->lsa_un.un_nla.nla_router[i].s_addr ,
                                metricEdge);
                }
            }
            else if (((*itLsaScan)->ls_type)==1)
                //rtr lsa
            {
                if ((*itLsaScan)->lsa_un.un_rla.link.link_type==1)
                    //Point To Point
                {
                    printf("P2P edge\n");

                    addEdge_NtoN( (*itLsaScan)->lsa_un.un_rla.link_id.s_addr , (*itLsaScan)->bornRtId ,
                                ((*itLsaScan)->lsa_un.un_rla.link.tos_metric));
                }
                else if ((*itLsaScan)->lsa_un.un_rla.link.link_type==3)
                    //STUB
                {
                    printf("STUB edge\n");

                    addEdge_NtoS( (*itLsaScan)->bornRtId,
                                ((*itLsaScan)->lsa_un.un_rla.link_id.s_addr) , ((*itLsaScan)->lsa_un.un_rla.link_data.s_addr) ,
                                ((*itLsaScan)->lsa_un.un_rla.link.tos_metric));
                }
            }
        }
    }

    printf("ALL EDGES ADDED\n");

    //B: calculate the SPF(by Dijkstra)
    int homeNode=VertexMap[nowRt.router_id*2+1]->idx;

    int dijkArr[TABLE_SIZE];
    bool okFlag[TABLE_SIZE];
    int cnnArr[TABLE_SIZE];

    deque<struct VertexSt *>::iterator itNodeDeque=VertexDeque.begin();
    for (int i=0; itNodeDeque!=VertexDeque.end(); i++,itNodeDeque++)
    {
        if (i==homeNode)
        {
            dijkArr[i]=0;
            okFlag[homeNode]=true;
            cnnArr[i]=i;
        }
        else
        {
//            dijkArr[i]=gTable[homeNode][(*itNodeDeque)->idx];
            dijkArr[i]=Graph[homeNode][i];
            okFlag[i]=false;
            if (dijkArr[i]>=UNREACH)
            {
                cnnArr[i]=-1;
            }
            else
            {
                cnnArr[i]=homeNode;
            }
        }
    }

    for (int iNum=0; iNum<VertexDeque.size()-1; iNum++)
    {
        //find the min
        int jMin=-1;
        for (int j=0; j<VertexDeque.size(); j++)
        {
            if (j!=homeNode&&(okFlag[j]==false))
            {
                if (jMin==-1)
                {
                    jMin=j;
                }
                else if (dijkArr[jMin]>dijkArr[j])
                {
                    jMin=j;
                }
            }
        }

        okFlag[jMin]=true;
        for (int k=0; k<VertexDeque.size(); k++)
        {
            if (dijkArr[jMin]+Graph[jMin][k]<dijkArr[k])
            {
                dijkArr[k]=dijkArr[jMin]+Graph[jMin][k];
                cnnArr[k]=jMin;
            }
        }
    }
    
    fprintf(spfF,"-------------SPF VERTEX--------------\n");
    fprintf(spfF,"| %2s | %6s | %15s |\n","NO","Type","IP Addr");
    map<int,struct VertexSt *> idxPtMap;
    //////////////Step 3: get the routing table
    printf("ROUTE TABLE:\n");
    itNodeDeque=VertexDeque.begin();
    for (; itNodeDeque!=VertexDeque.end(); itNodeDeque++)
    {
        idxPtMap[(*itNodeDeque)->idx]=(*itNodeDeque);
        fprintf(spfF,"| %2d | %6s | %15s |\n",
                (*itNodeDeque)->idx,
                (*itNodeDeque)->type==1?"router":"stub",
                (*itNodeDeque)->type==1?inet_ntostr((*itNodeDeque)->un.rtr.routerId):inet_ntostr((*itNodeDeque)->un.stub.ip&(*itNodeDeque)->un.stub.mask));
    }
    fprintf(spfF,"-------------SPF VERTEX--------------\n\n\n");

    
    fprintf(spfF,"--------------------------SPF TREE---------------------------\n");
    fprintf(spfF,"| %3s | %15s | %4s | %3s | %15s |\n","Dst","DstIP","Cost","Via","ViaIP");

    
    //output the SPspfF tree
    for (int i=0; i<VertexDeque.size(); i++)
    {
        fprintf(spfF,"| %3d | %15s | %4d | %3d | ",
                i,
                (idxPtMap[i])->type==1?inet_ntostr((idxPtMap[i])->un.rtr.routerId):inet_ntostr((idxPtMap[i])->un.stub.ip&(idxPtMap[i])->un.stub.mask),
                dijkArr[i],
                cnnArr[i]);
        fprintf(spfF,"%15s |\n",
                (idxPtMap[cnnArr[i]])->type==1?inet_ntostr((idxPtMap[cnnArr[i]])->un.rtr.routerId):inet_ntostr((idxPtMap[cnnArr[i]])->un.stub.ip&(idxPtMap[cnnArr[i]])->un.stub.mask));
    }
    fprintf(spfF,"--------------------------SPF TREE---------------------------\n\n\n");
    //output the routing table
    
    
    //FILE * rtF=fopen(outRTtablefile,"w");
    //FILE * rtF=F;
    
    fprintf(spfF,"----------------------------Routing Table------------------------------\n");
    
    
    
    fprintf(spfF,"| %15s | %15s | %4s | %15s |\n", "Dst IP", "Dst Mask", "Cost", "Next Hop");
    
    
    //1. routers
    //2. stub networks
    for (int i=0; i<VertexDeque.size(); i++)
    {
        if (i!=homeNode)
        {
            if (((idxPtMap[i])->type)==1)
                //the router
            {
                int nowIdx=i;
                int preIdx=i;
                while (nowIdx!=homeNode)
                {
                    preIdx=nowIdx;
                    nowIdx=cnnArr[nowIdx];
                }

                /* the next jump is preIdx */

                uint32_t nextIp;
                uint32_t dstIp;

                nextIp=getRtNextJump(((idxPtMap[preIdx])->un.rtr.routerId),((idxPtMap[homeNode])->un.rtr.routerId));

                itArea=areaDeque.begin();
                deque<struct lsdb_struct *>::iterator itLsaScan;
                for (itLsaScan=(*itArea)->lsaDequeInArea.begin(); itLsaScan!=(*itArea)->lsaDequeInArea.end(); itLsaScan++)
                {
                    if (((*itLsaScan)->ls_type)==1)
                        //rtr lsa
                    {
                        if ((*itLsaScan)->lsa_un.un_rla.link.link_type==2)
                            //trans net
                        {
                            if (((idxPtMap[i])->un.rtr.routerId)==
                                    ((*itLsaScan)->bornRtId))
                            {
                                dstIp=((*itLsaScan)->lsa_un.un_rla.link_data.s_addr);

                                fprintf(spfF,"| %15s | 255.255.255.255 | %4d | ", inet_ntostr(dstIp), dijkArr[i]);
                                fprintf(spfF,"%15s |\n", (nextIp==dstIp)?"direct":inet_ntostr(nextIp) );
                                
                                //for()
                                    
                                //    infDeque
                                if(LINUXRT)
                                {
                                /*        
                                for(int i = 0; i < areaDeque.size(); i++)
                                {
        
                                        struct areaInfDequeNode * infDequeInArea=areaDeque[i]->areaInfDeque;
                                        //对area中的interface进行循环
                                        for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
                                        {
                                            if(infDequeInArea->infNode->ip==nextIp)
                                            {
                                                addRouteIterm(dstIp,inet_addr("255.255.255.255"),nextIp,infDequeInArea->infNode->name);
                                                
                                            }
                                        }
                                }
                                */
                                
                                addRouteIterm(dstIp,inet_addr("255.255.255.255"),nextIp,INFNAME);
                                }
                               
                            }
                        }
                    }
                }
            }
            else if (((idxPtMap[i])->type)==2)
                //stub networks
            {
                int nowIdx=i;
                int preIdx=i;
                while (nowIdx!=homeNode)
                {
                    preIdx=nowIdx;
                    nowIdx=cnnArr[nowIdx];
                }

                int nextIp=getRtNextJump(((idxPtMap[preIdx])->un.rtr.routerId),((idxPtMap[homeNode])->un.rtr.routerId));

                fprintf(spfF,"| %15s | ", inet_ntostr((idxPtMap[i])->un.stub.ip) );
                fprintf(spfF,"%15s | %4d | ", inet_ntostr((idxPtMap[i])->un.stub.mask), dijkArr[i] );
                fprintf(spfF,"%15s |\n", (preIdx==i)?"direct":inet_ntostr(nextIp) );
                
                if(LINUXRT)
                {
                /*
                for(int i = 0; i < areaDeque.size(); i++)
                {
        
                        struct areaInfDequeNode * infDequeInArea=areaDeque[i]->areaInfDeque;
                        //对area中的interface进行循环
                        for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
                        {
                                if(infDequeInArea->infNode->ip==nextIp)
                                {
                                addRouteIterm((idxPtMap[i])->un.stub.ip,(idxPtMap[i])->un.stub.mask,nextIp,infDequeInArea->infNode->name);
                                                
                                }
                        }
                }
                */
                addRouteIterm((idxPtMap[i])->un.stub.ip,(idxPtMap[i])->un.stub.mask,nextIp,INFNAME);
                }
                
            }
        }

    }


    //3. trans networks
    /*
    (1) find all network lsa(type=2)
    (2) campare to get the longer one
    (3) ouput
    */
    itArea=areaDeque.begin();
    deque<struct lsdb_struct *>::iterator itLsaScan;
    for (itLsaScan=(*itArea)->lsaDequeInArea.begin(); itLsaScan!=(*itArea)->lsaDequeInArea.end(); itLsaScan++)
    {
        if (((*itLsaScan)->ls_type)==2)
            //network lsa
        {
            uint32_t ipTemp=(*itLsaScan)->ls_id;
            uint32_t maskTemp=(*itLsaScan)->lsa_un.un_nla.nla_mask.s_addr;

            int maxJumpRtrIdx=-1;
            //directly
            bool drctFlag=false;

            for (int i=0; i<((*itLsaScan)->length-24)/4; i++)
            {
                if ((*itLsaScan)->lsa_un.un_nla.nla_router[i].s_addr==nowRt.router_id)
                {
                    drctFlag=true;
                }

                if (maxJumpRtrIdx==-1)
                {
                    maxJumpRtrIdx=VertexMap[((*itLsaScan)->lsa_un.un_nla.nla_router[i].s_addr)*2+1]->idx;
                }
                else if (dijkArr[maxJumpRtrIdx]<dijkArr[VertexMap[((*itLsaScan)->lsa_un.un_nla.nla_router[i].s_addr)*2+1]->idx])
                {
                    maxJumpRtrIdx=VertexMap[((*itLsaScan)->lsa_un.un_nla.nla_router[i].s_addr)*2+1]->idx;
                }
            }

            int nowIdx=maxJumpRtrIdx;
            int preIdx=maxJumpRtrIdx;

            while (nowIdx!=homeNode)
            {
                preIdx=nowIdx;
                nowIdx=cnnArr[nowIdx];
            }

            int nextIp=getRtNextJump( ((idxPtMap[preIdx])->un.rtr.routerId) , ((idxPtMap[homeNode])->un.rtr.routerId) );

            fprintf(spfF,"| %15s | ",
                    inet_ntostr( ipTemp )
                   );
            fprintf(spfF,"%15s | %4d | ",
                    inet_ntostr( maskTemp ),   //mask
                    dijkArr[maxJumpRtrIdx]
                   );
            fprintf(spfF,"%15s |\n",
                    ( preIdx==maxJumpRtrIdx )?"direct":inet_ntostr(nextIp)
                   );
            
            if(LINUXRT)
            {
            /*
            for(int i = 0; i < areaDeque.size(); i++)
            {
                struct areaInfDequeNode * infDequeInArea=areaDeque[i]->areaInfDeque;
                //对area中的interface进行循环
                for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
                {
                        if(infDequeInArea->infNode->ip==nextIp)
                        {
                                addRouteIterm(ipTemp,maskTemp,nextIp,infDequeInArea->infNode->name);
                                                
                        }
                }
            }
            */
            addRouteIterm(ipTemp,maskTemp,nextIp,INFNAME);
            }
            
            
            
            
        }
    }
    fprintf(spfF,"----------------------------Routing Table------------------------------\n");
    //fclose(spfF);

    //printf("routing table\n");

    fclose(spfF);
}



void * printLsdb(void * none)
{
    while (1)
    {
        FILE * F=fopen(outlsdbfile,"w");
        deque<struct area *>::iterator itArea;
        //对area循环
        for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
        {
            fprintf(F,"=====area: %d====\n",(*itArea)->areaId);
            deque<struct lsdb_struct *>::iterator itLsaScan=(*itArea)->lsaDequeInArea.begin();
            for (int iNum=0; itLsaScan!=(*itArea)->lsaDequeInArea.end(); itLsaScan++)
            {
                iNum++;
                fprintf(F,"[%d]\n\tls_type:%s\n\tbornTime:%d\n\tseqNum:%d\n\tbornRouterId:%s\n\tls_id:",
                        iNum,
                        (*itLsaScan)->ls_type==1?"router lsa":((*itLsaScan)->ls_type==2?"network lsa":"UK"),
                        (*itLsaScan)->bornTime,
                        (*itLsaScan)->seq,
                        inet_ntostr((*itLsaScan)->bornRtId));
                fprintf(F,"%s\n",inet_ntostr((*itLsaScan)->ls_id));
                if ((*itLsaScan)->ls_type==1)
                {
                    fprintf(F,"**\n\tlink_id:%s\n",inet_ntoa((*itLsaScan)->lsa_un.un_rla.link_id));
                    fprintf(F,"\tlink_data:%s\n",inet_ntoa((*itLsaScan)->lsa_un.un_rla.link_data));
                    fprintf(F,"\tlink_type:%s\n",
                            ((*itLsaScan)->lsa_un.un_rla.link.link_type==1?"PTP":
                             (((*itLsaScan)->lsa_un.un_rla.link.link_type==2?"TRANS":
                               ("STUB")))));
                    fprintf(F,"\tlink_tos_count:%d\n",((*itLsaScan)->lsa_un.un_rla.link.link_tos_count));
                    fprintf(F,"\ttos_metric:%d\n",((*itLsaScan)->lsa_un.un_rla.link.tos_metric));
                }
                else if ((*itLsaScan)->ls_type==2)
                {
                    fprintf(F,"**\n\tmask:%s\n",inet_ntoa((*itLsaScan)->lsa_un.un_nla.nla_mask));
                    for (int i=0; i<((*itLsaScan)->length-24)/4; i++)
                    {
                        fprintf(F,"\trouter:%s\n",inet_ntoa((*itLsaScan)->lsa_un.un_nla.nla_router[i]));
                    }
                }
                fprintf(F,"---------------\n\n\n");
            }
        }

        fclose(F);

        printf("[GENERATE LSDB.....................]\n");

        //先判断属于哪个邻居状态机
        for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
        {
            struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
            //对area中的interface进行循环
            for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
            {
                deque<struct nbr_struct *>::iterator itNbr=infDequeInArea->inf->nbrDeque.begin();
                for (; itNbr!=infDequeInArea->inf->nbrDeque.end(); itNbr++)
                {
//                    if ((*itNbr)->seqNum==(*itNbr)->startSeqNum)
                    if ((*itNbr)->xchg==false)
                    {
                        ((*itNbr)->exchangeNum)++;
                        if (((*itNbr)->exchangeNum>1))
                        {
                            printf("\nDD wait: send a first DD again\n\n");
                            send_db_description(infDequeInArea->inf,(*itNbr),parselsahdr(NULL),true,true,true);
                        }
                    }
                }
            }
        }

       
        //find DR,1. produce type_2 LSA, and then,2. flooding

        for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
        {
            struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
            //对area中的interface进行循环
            for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
            {
                if (infDequeInArea->inf->dr==infDequeInArea->inf->ip)
                {
                    bool floodingFlag=false;

                    //find old one
                    deque<struct lsdb_struct *>::iterator iterLSA=(*itArea)->lsaDequeInArea.begin();
                    struct lsdb_struct * lsaFound=NULL;
                    for (; iterLSA!=(*itArea)->lsaDequeInArea.end(); iterLSA++)
                    {
                        if (((*iterLSA)->ls_type==2)&&
                                ((*iterLSA)->ls_id==infDequeInArea->inf->ip))
                        {
                            lsaFound=(*iterLSA);
                            break;
                        }
                    }

                    if (lsaFound!=NULL)
                    {
                        int oldLen=lsaFound->length;
                        lsaFound->length=28;
                        lsaFound->lsa_un.un_nla.nla_router[0].s_addr=nowRt.router_id;
                        lsaFound->lsa_un.un_nla.nla_mask.s_addr=inet_addr("255.255.255.0");
                        lsaFound->bornTime=time(NULL);

                        deque<struct nbr_struct *>::iterator itNbr=infDequeInArea->inf->nbrDeque.begin();
                        for (; itNbr!=infDequeInArea->inf->nbrDeque.end(); itNbr++)
                        {
                            lsaFound->lsa_un.un_nla.nla_router[(lsaFound->length-24)/4].s_addr=(*itNbr)->router_id;
                            lsaFound->length+=4;
                        }

                        if (oldLen<(lsaFound->length))
                        {
                            floodingFlag=true;
                        }
                    }
                    else
                    {
                        floodingFlag=true;
                        /*
                        add a new one
                        */
                        struct lsdb_struct * lsaNodeTemp=new struct lsdb_struct;

                        lsaNodeTemp->bornTime=(time(NULL));

                        lsaNodeTemp->bornRtId=nowRt.router_id;

                        //in the Network LSA,
                        //the lsa id is the DR interface address
                        lsaNodeTemp->ls_id=infDequeInArea->inf->ip;

                        lsaNodeTemp->seq=(nowRt.router_id + (*itArea)->areaId*100 + (*itArea)->lsaDequeInArea.size());

                        //it's the network lsa
                        lsaNodeTemp->ls_type=2;


                        lsaFound=lsaNodeTemp;

                        lsaFound->length=28;
                        lsaFound->lsa_un.un_nla.nla_router[0].s_addr=nowRt.router_id;
                        lsaFound->lsa_un.un_nla.nla_mask.s_addr=inet_addr("255.255.255.0");

                        deque<struct nbr_struct *>::iterator itNbr=infDequeInArea->inf->nbrDeque.begin();
                        for (; itNbr!=infDequeInArea->inf->nbrDeque.end(); itNbr++)
                        {
                            lsaFound->lsa_un.un_nla.nla_router[(lsaFound->length-24)/4].s_addr=(*itNbr)->router_id;
                            lsaFound->length+=4;
                        }


                        ((*itArea)->lsaDequeInArea).push_back(lsaNodeTemp);
                    }

                    if ( (floodingFlag||true)&&(lsaFound->length>30))
                    {
                        printf("flooding a network lsa\n");

                        struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
                        //对area中的interface进行循环
                        for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
                        {
                            send_ls_update(infDequeInArea->inf,inet_addr("224.0.0.5"),lsaFound,(parselsahdr(lsaFound)));
                        }
                    }
                }
            }
        }


        for (itArea=areaDeque.begin(); itArea!=areaDeque.end(); itArea++)
        {
            if ((*itArea)->lsaDequeInArea.size()>=GENSPF_NUM)
            {
                //printf("BEGIN:GEN spf tree..........................\n");
                genspf();
                //printf("END:GEN spf tree............................\n");
            }
        }

        sleep(OUT_LSDB_INTERVAL);
    }
}

