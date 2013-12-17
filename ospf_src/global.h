#ifndef GLOBAL_INCLUDED
#define GLOBAL_INCLUDED

#include <netinet/in.h>
#include <deque>

using namespace std;


typedef enum {
	INITERROR,
	SENDPKTERROR,
        RECVPKTERROR
} error_type_t;

#define GENSPF_NUM 16
#define INFNAME "eth1"
#define LINUXRT 1

#define BRDCAST 0
#define NMBA 1
#define P2MP 2
#define P2P 3

struct nbr_struct
{
    struct inf_struct * infNow;
    u_int32_t seqNum;
    u_int32_t startSeqNum;
    u_int32_t router_id;
    u_int32_t area_id;
    u_int32_t inf_ip;
    u_int32_t inf_mask;
    int exchangeNum;
        //master?
    int master;
    long lastHelloTime;
    bool xchg;
};

struct lsdb_struct
{
    u_int32_t seq;
    u_int32_t bornRtId;
    u_int32_t ls_id;
    u_int16_t length;
    int ls_type;
    long bornTime;
    union
    {
        // Router links advertisements
        struct
        {
            struct in_addr link_id;
            struct in_addr link_data;
            struct
            {
                u_int8_t link_type;
                u_int8_t link_tos_count;
                u_int16_t tos_metric;
            } link;

        } un_rla;

        // Network links advertisements
        struct
        {
            struct in_addr nla_mask;
            struct in_addr nla_router[5];
        } un_nla;

        // Summary links advertisements
        struct
        {
            struct in_addr sla_mask;
            u_int32_t sla_tosmetric;
        } un_sla;

        // AS external links advertisements
        struct
        {
            struct in_addr asla_mask;
            struct aslametric
            {
                u_int32_t asla_tosmetric;
                struct in_addr asla_forward;
                struct in_addr asla_tag;
            } asla_metric[1];
        } un_asla;
    } lsa_un;
};

struct infDeque
{
    struct infDeque * next;
    struct inf_struct * inf;
};

//OSPF area structure
struct area
{
    struct infDeque * infDequeInArea;
    deque<struct lsdb_struct *> lsaDequeInArea;
    u_int32_t areaId;
};


struct Rt_struct
{
    u_int32_t router_id;
    int priority;
};

struct inf_struct
{
    deque<struct nbr_struct *> nbrDeque;
    int idx;
    u_int32_t ip;
    u_int32_t mask;
    int type;
    u_int32_t area_id;
    u_int32_t dr;
    u_int32_t bdr;
    char name[10];
    bool drFlag;
    struct area * areain;
    int cost;
    u_int32_t dr_slt;
    u_int32_t rtmaxId_dr;
    u_int32_t rtmaxPri_dr;
};


void errorprint(error_type_t errNum, char errstring[]);


#endif // GLOBAL_INCLUDED
