#include <stdio.h>
#include <string.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "global.h"
#include "pkt.h"

//#include <malloc.h>

struct routingtable
{
    struct in_addr destination;
    struct in_addr mask;
    struct in_addr nexthop;
    char interface_num[5];
};
int addRouteIterm(uint32_t dstIp, uint32_t mask, uint32_t nextHop, char* infName)
{
    //struct routingtable *item = malloc(sizeof(struct routingtable));
    struct routingtable *item = new routingtable();
    item->destination.s_addr = dstIp;
    item->mask.s_addr = mask;
    item->nexthop.s_addr = nextHop;
    strcpy(item->interface_num,infName);//"eth0");
    printf("%s\n",item->interface_num);
    int sockfd;
    struct rtentry rm;
    int err;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
    {
        printf("socket is -1\n");
        return -1;
    }
    memset(&rm, 0, sizeof(rm));

    (( struct sockaddr_in*)&rm.rt_dst)->sin_family = AF_INET;
    (( struct sockaddr_in*)&rm.rt_dst)->sin_addr.s_addr = (item->destination.s_addr & item->mask.s_addr);
    (( struct sockaddr_in*)&rm.rt_dst)->sin_port = 0;
    printf("dest: %x\n", item->destination.s_addr & item->mask.s_addr);
    printf("%s\n",inet_ntostr( item->destination.s_addr & item->mask.s_addr));

    (( struct sockaddr_in*)&rm.rt_genmask)->sin_family = AF_INET;
    (( struct sockaddr_in*)&rm.rt_genmask)->sin_addr.s_addr = (item->mask.s_addr);
    (( struct sockaddr_in*)&rm.rt_genmask)->sin_port = 0;
    printf("mask: %x\n", item->mask.s_addr);
    printf("%s\n",inet_ntoa(item->mask));

    (( struct sockaddr_in*)&rm.rt_gateway)->sin_family = AF_INET;
    (( struct sockaddr_in*)&rm.rt_gateway)->sin_addr.s_addr = (item->nexthop.s_addr);
    (( struct sockaddr_in*)&rm.rt_gateway)->sin_port = 0;
    printf("gateway: %x\n", item->nexthop.s_addr);
    printf("%s\n",inet_ntoa(item->nexthop));
    rm.rt_dev = item->interface_num;

    rm.rt_flags = RTF_GATEWAY | RTF_UP;
    if ((err = ioctl(sockfd, SIOCADDRT, &rm)) < 0)
    {
        close(sockfd);
        perror("ioctl");
        perror("SIOCADDRT");
        printf("Add New Route failed, ret->%d\n", err);
        return -1;
    }
    close(sockfd);
    printf("Successfully Add New Route!\n");
    return 1;
}