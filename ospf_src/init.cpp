#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <deque>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "pkt.h"
#include "global.h"

using namespace std;

char initlsafile[100];
char outlsdbfile[100];
char outfile[100];
char errorlogfile[100];
char outRTtablefile[100];
char Rn[10];
char settingfile[100];

deque<struct inf_struct *> infDeque;
deque<struct area *> areaDeque;
struct Rt_struct nowRt;

bool cnct[RT_MAX][RT_MAX];

map<int,int> cnctMap;

uint32_t rtrRtrCnnt[RT_MAX][RT_MAX];


void parseSetting()
{
    FILE *setting;
    char string[100];
    if((setting = fopen(settingfile,"r"))==0)
    {
        errorprint(INITERROR,"open settingFile failed!");
    }
    printf("BEGIN:SETTING............................\n");
    
    if(fscanf(setting,"%s",string)==0)
    {  
        errorprint(INITERROR,"INPUT failed");
    }
    else
    {
        printf("Now Router is: %s\n",string);
    }
    
    if(fscanf(setting,"%s",string)==0)
    {
        errorprint(INITERROR,"INPUT failed");
    }
    else
    {
        //inet_aton(string, (in_addr *)&(routerNow.router_id));
        nowRt.router_id=inet_addr(string);
        nowRt.priority=1;
    }
    
   printf("router ID: %s\n",inet_ntostr(nowRt.router_id));
   struct area * areaTemp=new struct area;
   
   
   if(fscanf(setting,"%d",&(areaTemp->areaId))==0){
        errorprint(INITERROR,"INPUT failed");        
    }
   printf("AREA ID: %d\n",areaTemp->areaId);
   
   
   areaTemp->infDequeInArea=NULL;

   
   //interfaces number
    int ifcNum;
    fscanf(setting,"%d\n",&ifcNum);
    printf("%d interfaces\n",ifcNum);

    for (int i=0; i<ifcNum; i++)
    {
        
            
//        struct ip_maskNode * ipMaskNode=(struct ip_maskNode *)malloc(sizeof(struct ip_maskNode));
        u_int32_t ipT,maskT;
        
        struct inf_struct * infTemp=new struct inf_struct;
        
        fscanf(setting,"%d",&(infTemp->idx));

        //ip string
        fscanf(setting,"%s",string);
        infTemp->ip=inet_addr(string);
        ipT=inet_addr(string);
        
        
        
        printf("%s-",string);

        //ip mask
        fscanf(setting,"%s",string);
        infTemp->mask=inet_addr(string);
        maskT=inet_addr(string);
        
        printf("%s\n",string);

        fscanf(setting,"%d",&(infTemp->cost));
        printf("cost: %d\n",infTemp->cost);

        fscanf(setting,"%s",(infTemp->name));
        printf("NIC: %s\n",infTemp->name);

        //infTemp->name="eth1";

        infTemp->type=BRDCAST;
        infTemp->drFlag=false;
        infTemp->dr_slt=-1;
        infTemp->rtmaxId_dr=-1;
        infTemp->rtmaxPri_dr=1;

        infDeque.push_back(infTemp);


        //find interfaces which belong to the area
        for (deque<struct inf_struct *>::iterator it=infDeque.begin(); it!=infDeque.end(); it++)
        {
            if (((((struct inf_struct *)(*it))->ip)&(((struct inf_struct *)(*it))->mask)) == (ipT&maskT))
            {
                struct infDeque * areaInfDequeNodeTemp=new struct infDeque;
                areaInfDequeNodeTemp->next=areaTemp->infDequeInArea;
                areaInfDequeNodeTemp->inf=((struct inf_struct *)(*it));
                areaTemp->infDequeInArea=areaInfDequeNodeTemp;
                 ((struct inf_struct *)(*it))->areain=areaTemp;
            }
        }        
    }
    areaDeque.push_back(areaTemp);
   
   fclose(setting);
   printf("END:SETTING...........................\n");
}


void parseConct()
{
    int iNum;
    FILE * F = fopen("./init/initcnnt","r");

    printf("BEGIN: CONNECT.......................\n");
    fscanf(F,"%d",&iNum);
    for (int i =0; i<iNum; i++)
    {
        int j,k;
        char lineBuf1[40];
        char lineBuf2[40];

        fscanf(F,"%s%s",lineBuf1,lineBuf2);

        j=inet_addr(lineBuf1);
        k=inet_addr(lineBuf2);

        cnctMap[j]=k;
        cnctMap[k]=j;

        printf("%s-",inet_ntostr(j));
        printf("%s\n",inet_ntostr(k));
    }

    fscanf(F,"%d",&iNum);
    for (int i = 0; i<iNum; i++)
    {
        int j,k,m;
        char lineBuf[40];

        fscanf(F,"%s",lineBuf);
        j=inet_addr(lineBuf);


        fscanf(F,"%s",lineBuf);
        k=inet_addr(lineBuf);

        fscanf(F,"%s",lineBuf);
        m=inet_addr(lineBuf);

        rtrRtrCnnt[j&0x000f][k&0x000f]=m;
    }

    fclose(F);

    printf("END:CONNECT.........................\n");
    
}

void parsePath()
{

    strcpy(outlsdbfile,"./init/");
    strcat(outlsdbfile,Rn);
    strcat(outlsdbfile,"/lsdb");

    strcpy(initlsafile,"./init/");
    strcat(initlsafile,Rn);
    strcat(initlsafile,"/initlsa");


    strcpy(outfile,"./init/");
    strcat(outfile,Rn);
    strcat(outfile,"/out");

    
    strcpy(errorlogfile,"./init/");
    strcat(errorlogfile,Rn);
    strcat(errorlogfile,"/errLog");
    
    
    strcpy(settingfile,"./init/");
    strcat(settingfile,Rn);
    strcat(settingfile,"/setting");
    
}


void genLSAs()
{
    printf("generate initial LSA............................\n");
    
    char lineBuf[50];
    FILE * F = fopen(initlsafile,"r");

    int iNum;
    fscanf(F,"%d",&iNum);
    int areaIdBelong;

    for (int i=0; i<iNum; i++)
    {
        fscanf(F,"%d",&areaIdBelong);
        deque<struct area *>::iterator itArea=areaDeque.begin();
        for (; itArea!=areaDeque.end(); itArea++)
        {
            if ((*itArea)->areaId==areaIdBelong)
            {
                break;
            }
        }

        struct lsdb_struct * lsaNodeTemp=new struct lsdb_struct;

        lsaNodeTemp->bornTime=(time(NULL));

        lsaNodeTemp->bornRtId=(nowRt.router_id);

        //in the Router LSA, the lsa id is the adv_rtr_id
        lsaNodeTemp->ls_id=(nowRt.router_id);

        lsaNodeTemp->seq=(nowRt.router_id + (*itArea)->areaId*100 + (*itArea)->lsaDequeInArea.size());

        //it's the router lsa
        lsaNodeTemp->ls_type=1;

        fscanf(F,"%s",lineBuf);
        lsaNodeTemp->lsa_un.un_rla.link_id.s_addr=(inet_addr(lineBuf));

        fscanf(F,"%s",lineBuf);
        lsaNodeTemp->lsa_un.un_rla.link_data.s_addr=(inet_addr(lineBuf));

        fscanf(F,"%d",&(lsaNodeTemp->lsa_un.un_rla.link.link_type));
        lsaNodeTemp->lsa_un.un_rla.link.link_type=(lsaNodeTemp->lsa_un.un_rla.link.link_type);

        fscanf(F,"%d",&(lsaNodeTemp->lsa_un.un_rla.link.tos_metric));
        lsaNodeTemp->lsa_un.un_rla.link.tos_metric=(lsaNodeTemp->lsa_un.un_rla.link.tos_metric);
        printf("\tinit lsa metric: %d\n",lsaNodeTemp->lsa_un.un_rla.link.tos_metric);

        //fscanf(F,"%s",lineBuf);

        ((*itArea)->lsaDequeInArea).push_back(lsaNodeTemp);
    }


    fclose(F);

    printf("End:generate lsas\n");
}

void initdr()
{
    deque<struct area *>::iterator itArea;
    for (itArea=areaDeque.begin(); 
            itArea!=areaDeque.end(); itArea++)
    {

        struct infDeque * infDequeInArea=(*itArea)->infDequeInArea;
        //对area中到interface进行循环
        for (; infDequeInArea!=NULL; infDequeInArea=infDequeInArea->next)
        {
            
            //All think self are DR
            
            infDequeInArea->inf->dr_slt=infDequeInArea->inf->ip;
            infDequeInArea->inf->rtmaxPri_dr=nowRt.priority;
            infDequeInArea->inf->rtmaxId_dr=nowRt.router_id;
        }
    }
}

void init()
{
    parsePath();  
    parseSetting();

    initdr();
    parseConct();
    ddsrand();
    genLSAs();
}











