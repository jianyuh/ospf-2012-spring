/* 
 * File:   main.cpp
 * Author: root
 *
 * Created on May 2, 2012, 9:15 PM
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pthread.h>
#include <deque>
#include <arpa/inet.h>


#include "stdnet.h"
#include "pkt.h"
#include "global.h"

using namespace std;

int main(int argc,char ** argv)
{
   
    if (argc>1)
    {
        strcpy(Rn,argv[1]);
    }
    else
    {
        //strcpy(Rn,"R1");
        printf("Error: ./ospf Rn\n");
        exit(0);
    }
    
    init();

    pthread_t array[10];
    pthread_t infarray[10];
    
    pthread_create(array,NULL,keep,NULL);
    
    //send Hello periodically
   
    //printf("flag1\n");
    for(int i=0;i<infDeque.size();i++)
    {
       pthread_create(infarray+i,NULL,sendHelloPkt,infDeque[i]);
    }
    
    //printf("flag2\n");
    
    //whether there is a DR
    pthread_create(array+1,NULL,DRdetect,NULL);
    pthread_join(array[1],NULL);
    
    //printf("flag3\n");
    pthread_create(array+2,NULL,recvPkt,NULL);
    //printf("flag4\n");
    pthread_create(array+3,NULL,printLsdb,NULL);
    //printf("flag5\n");
    for(int i=0;i<=3;i++)
        pthread_join(array[i],NULL);
    for(int i=0;i<infDeque.size();i++)
        pthread_join(infarray[i],NULL);
     
    return 0;
}

