#include <stddef.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>

#include "stdnet.h"

using namespace std;

std_pblock_t *
std_pblock_probe(std_t *l, std_ptag_t ptag, uint32_t b_len, uint8_t type)
{
    int offset;
    std_pblock_t *p;

    if (ptag == STD_PTAG_INITIALIZER)
    {
        return std_pblock_new(l, b_len);
    }

    /*
     *  Update this pblock, don't create a new one.  Note that if the
     *  new packet size is larger than the old one we will do a malloc.
     */
    p = std_pblock_find(l, ptag);

    if (p == NULL)
    {
        /* err msg set in std_pblock_find() */
        return (NULL);
    }
    if (p->type != type)
    {
        snprintf(l->err_buf, STD_ERRBUF_SIZE,
                "%s(): ptag refers to different type than expected (0x%x != 0x%x)",
                __func__, p->type, type);
        return (NULL); 
    }
    /*
     *  If size is greater than the original block of memory, we need 
     *  to malloc more memory.  Should we use realloc?
     */
    if (b_len > p->b_len)
    {
        offset = b_len - p->b_len;  /* how many bytes larger new pblock is */
        free(p->buf);
        p->buf = (uint8_t *)malloc(b_len);
        if (p->buf == NULL)
        {
            snprintf(l->err_buf, STD_ERRBUF_SIZE,
                    "%s(): can't resize pblock buffer: %s\n", __func__,
                    strerror(errno));
            return (NULL);
        }
        memset(p->buf, 0, b_len);
        p->h_len += offset; /* new length for checksums */
        p->b_len = b_len;       /* new buf len */
        l->total_size += offset;
    }
    else
    {
        offset = p->b_len - b_len;
        p->h_len -= offset; /* new length for checksums */
        p->b_len = b_len;       /* new buf len */
        l->total_size -= offset;
    }
    p->copied = 0;      /* reset copied counter */

    return (p);
}


int
std_pblock_append(std_t *l, std_pblock_t *p, const uint8_t *buf,
            uint32_t len)
{
    if (p->copied + len > p->b_len)
    {
        snprintf(l->err_buf, STD_ERRBUF_SIZE,
                "%s(): memcpy would overflow buffer\n", __func__);
        return (-1);
    }
    memcpy(p->buf + p->copied, buf, len);
    p->copied += len;
    return (1);
}

void
std_pblock_delete(std_t *l, std_pblock_t *p)
{
    if (p)
    {
        l->total_size -= p->b_len;
        l->n_pblocks--;

        std_pblock_remove_from_list(l, p);

        if (p->buf)
        {
            free(p->buf);
            p->buf = NULL;
        }

        free(p);
    }
}

static void std_pblock_remove_from_list(std_t *l, std_pblock_t *p)
{
    if (p->prev) 
    {
        p->prev->next = p->next;
    }
    else
    {
        l->protocol_blocks = p->next;
    }

    if (p->next)
    {
        p->next->prev = p->prev;
    }
    else
    {
        l->pblock_end = p->prev;
    }
}

std_t *
std_init(int injection_type, const char *device, char *err_buf)
{
    std_t *l = NULL;

#if defined(__WIN32__)
    WSADATA wsaData;

    if ((WSAStartup(0x0202, &wsaData)) != 0)
    {
        snprintf(err_buf, STD_ERRBUF_SIZE, 
                "%s(): unable to initialize winsock 2\n", __func__);
        goto bad;
    }
#endif

    l = (std_t *)malloc(sizeof (std_t));
    if (l == NULL)
    {
        snprintf(err_buf, STD_ERRBUF_SIZE, "%s(): malloc(): %s\n", __func__,
                strerror(errno));
        goto bad;
    }
	
    memset(l, 0, sizeof (*l));

    l->injection_type   = injection_type;
    l->ptag_state       = STD_PTAG_INITIALIZER;
    l->device           = (device ? strdup(device) : NULL);
    l->fd               = -1;

    strncpy(l->label, STD_LABEL_DEFAULT, STD_LABEL_SIZE);
    l->label[sizeof(l->label)] = '\0';

    switch (l->injection_type)
    {
        case STD_RAW4:
            if (std_open_raw4(l) == -1)
            {
                snprintf(err_buf, STD_ERRBUF_SIZE, "%s", l->err_buf);
                goto bad;
            }
            break;
        default:
            snprintf(err_buf, STD_ERRBUF_SIZE,
                    "%s(): unsupported injection type\n", __func__);
            goto bad;
            break;
    }

    return (l);

bad:
    if (l)
    {
        std_destroy(l);
    }
    return (NULL);
}

void
std_destroy(std_t *l)
{
    if (l)
    {
        close(l->fd);
        free(l->device);
        std_clear_packet(l);
        free(l);
    }
}

void
std_clear_packet(std_t *l)
{
    std_pblock_t *p;

    if (!l)
    {
        return;
    }

    while((p = l->protocol_blocks))
    {
        std_pblock_delete(l, p);
    }

    /* All pblocks are deleted, so start the tag count over from 1. */
    l->ptag_state = 0;
}


std_ptag_t
std_build_ospfv2_lsu(uint32_t num, const uint8_t *payload, uint32_t payload_s,
std_t *l, std_ptag_t ptag)
{
    uint32_t n, h;
    std_pblock_t *p;
    struct std_lsu_hdr lh_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 

    n = STD_OSPF_LSU_H + payload_s;
    h = 0;

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = std_pblock_probe(l, ptag, n, LIBNET_PBLOCK_OSPF_LSU_H);
    if (p == NULL)
    {
        return (-1);
    }

    memset(&lh_hdr, 0, sizeof(lh_hdr));
    lh_hdr.lsu_num = htonl(num);   /* Number of LSAs that will be bcasted */

    n = std_pblock_append(l, p, (uint8_t *)&lh_hdr, STD_OSPF_LSU_H);
    if (n == -1)
    {
        goto bad;
    }

    /* boilerplate payload sanity check / append macro */
    STD_DO_PAYLOAD(l, p);

    return (ptag ? ptag : std_pblock_update(l, p, h, 
            LIBNET_PBLOCK_OSPF_LSU_H));
bad:
    std_pblock_delete(l, p);
    return (-1);
}


/* FIXME this won't work with TCP or IPv4 data, which is probably a bug */
std_ptag_t
std_build_data(const uint8_t *payload, uint32_t payload_s, std_t *l,
std_ptag_t ptag)
{
    uint32_t n, h;
    std_pblock_t *p;

    if (l == NULL)
    { 
        return (-1);
    } 

    n = payload_s;
    h = 0;          /* no checksum on generic block */

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = std_pblock_probe(l, ptag, n, LIBNET_PBLOCK_DATA_H);
    if (p == NULL)
    {
        return (-1);
    }

    /* boilerplate payload sanity check / append macro */
    STD_DO_PAYLOAD(l, p);

    return (ptag ? ptag : std_pblock_update(l, p, h, LIBNET_PBLOCK_DATA_H));
bad:
    std_pblock_delete(l, p);
    return (-1);
}


std_ptag_t
std_build_ospfv2(uint16_t len, uint8_t type, uint32_t rtr_id, 
uint32_t area_id, uint16_t sum, uint16_t autype, const uint8_t *payload, 
uint32_t payload_s, std_t *l, std_ptag_t ptag)
{
    uint32_t n, h;
    std_pblock_t *p;
    struct std_ospf_hdr ospf_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 
 
    n = STD_OSPF_H + payload_s;
    h = STD_OSPF_H + payload_s + len;

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = std_pblock_probe(l, ptag, n, LIBNET_PBLOCK_OSPF_H);
    if (p == NULL)
    {
        return (-1);
    }
    
    memset(&ospf_hdr, 0, sizeof(ospf_hdr));
    ospf_hdr.ospf_v               = 2;              /* OSPF version 2 */
    ospf_hdr.ospf_type            = type;           /* Type of pkt */
    ospf_hdr.ospf_len             = htons(h);       /* Pkt len */
    ospf_hdr.ospf_rtr_id.s_addr   = rtr_id;  /* Router ID */
    ospf_hdr.ospf_area_id.s_addr  = area_id; /* Area ID */
    ospf_hdr.ospf_sum             = sum;
    ospf_hdr.ospf_auth_type       = htons(autype);  /* Type of auth */

    n = std_pblock_append(l, p, (uint8_t *)&ospf_hdr, STD_OSPF_H);
    if (n == -1)
    {
        goto bad;
    }

    /* boilerplate payload sanity check / append macro */
    STD_DO_PAYLOAD(l, p);

    if (sum == 0)
    {
        /*
         *  If checksum is zero, by default libnet will compute a checksum
         *  for the user.  The programmer can override this by calling
         *  std_toggle_checksum(l, ptag, 1);
         */
        std_pblock_setflags(p, LIBNET_PBLOCK_DO_CHECKSUM);
    }
    return (ptag ? ptag : std_pblock_update(l, p, h, LIBNET_PBLOCK_OSPF_H));
bad:
    std_pblock_delete(l, p);
    return (-1);
}


/* TODO len - should be calculated if -1 */
std_ptag_t
std_build_ipv4(uint16_t ip_len, uint8_t tos, uint16_t id, uint16_t frag,
uint8_t ttl, uint8_t prot, uint16_t sum, uint32_t src, uint32_t dst,
const uint8_t *payload, uint32_t payload_s, std_t *l, std_ptag_t ptag)
{
    uint32_t n = STD_IPV4_H; /* size of memory block */
    std_pblock_t *p, *p_data, *p_temp;
    struct std_ipv4_hdr ip_hdr;
    std_ptag_t ptag_data = 0; /* used if there is ipv4 payload */
    std_ptag_t ptag_hold;

    if (l == NULL)
    { 
        return (-1);
    } 

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = std_pblock_probe(l, ptag, n, LIBNET_PBLOCK_IPV4_H);
    if (p == NULL)
    {
        return (-1);
    }

    memset(&ip_hdr, 0, sizeof(ip_hdr));
    ip_hdr.ip_v          = 4;      /* version 4 */
    ip_hdr.ip_hl         = 5;      /* 20 byte header,  measured in 32-bit words */

    /* check to see if there are IP options to include */
    if (p->prev)
    {
        if (p->prev->type == LIBNET_PBLOCK_IPO_H)
        {
            /* IPO block's length must be multiple of 4, or it's incorrectly
             * padded, in which case there is no "correct" IP header length,
             * it will too short or too long, we choose too short.
             */
            ip_hdr.ip_hl += p->prev->b_len / 4;
        }
    }
    /* Note that p->h_len is not adjusted. This seems a bug, but it is because
     * it is not used!  std_do_checksum() is passed the h_len (as `len'),
     * but for IPPROTO_IP it is ignored in favor of the ip_hl.
     */

    ip_hdr.ip_tos        = tos;                       /* IP tos */
    ip_hdr.ip_len        = htons(ip_len);             /* total length */
    ip_hdr.ip_id         = htons(id);                 /* IP ID */
    ip_hdr.ip_off        = htons(frag);               /* fragmentation flags */
    ip_hdr.ip_ttl        = ttl;                       /* time to live */
    ip_hdr.ip_p          = prot;                      /* transport protocol */
    ip_hdr.ip_sum        = (sum ? htons(sum) : 0);    /* checksum */
    ip_hdr.ip_src.s_addr = src;                       /* source ip */
    ip_hdr.ip_dst.s_addr = dst;                       /* destination ip */
    
    n = std_pblock_append(l, p, (uint8_t *)&ip_hdr, STD_IPV4_H);
    if (n == -1)
    {
        goto bad;
    }

    /* save the original ptag value */
    ptag_hold = ptag;

    if (ptag == STD_PTAG_INITIALIZER)
    {
        ptag = std_pblock_update(l, p, STD_IPV4_H, LIBNET_PBLOCK_IPV4_H);
    }

    /* find and set the appropriate ptag, or else use the default of 0 */
    /* When updating the ipv4 block, we need to find the data block, and
     * adjust our ip_offset if the new payload size is different from what
     * it used to be.
     */
    if (ptag_hold && p->prev)
    {
        p_temp = p->prev;
        while (p_temp->prev &&
              (p_temp->type != LIBNET_PBLOCK_IPDATA) &&
              (p_temp->type != LIBNET_PBLOCK_IPV4_H))
        {
            p_temp = p_temp->prev;
        }

        if (p_temp->type == LIBNET_PBLOCK_IPDATA)
        {
            ptag_data = p_temp->ptag;
        }
        else
        {
             snprintf(l->err_buf, STD_ERRBUF_SIZE,
                     "%s(): IPv4 data pblock not found\n", __func__);
        }
    }

    if (payload_s && !payload)
    {
         snprintf(l->err_buf, STD_ERRBUF_SIZE,
                 "%s(): payload inconsistency\n", __func__);
        goto bad;
    }

    if (payload_s)
    {
        /* update ptag_data with the new payload */
        /* on create:
         *    b_len = payload_s
         *    l->total_size += b_len
         *    h_len = 0
         * on update:
         *    b_len = payload_s
         *    h_len += <diff in size between new b_len and old b_len>
         *      increments if if b_len goes up, down if it goes down
         * in either case:
         *    copied = 0
	 */
        p_data = std_pblock_probe(l, ptag_data, payload_s,
                LIBNET_PBLOCK_IPDATA);
        if (p_data == NULL)
        {
            return (-1);
        }

        if (std_pblock_append(l, p_data, payload, payload_s) == -1)
        {
            goto bad;
        }

        if (ptag_data == STD_PTAG_INITIALIZER)
        {
            /* IPDATA's h_len gets set to payload_s in both branches */
            if (p_data->prev->type == LIBNET_PBLOCK_IPV4_H)
            {
                std_pblock_update(l, p_data, payload_s,
                        LIBNET_PBLOCK_IPDATA);
                /* swap pblocks to correct the protocol order */
                std_pblock_swap(l, p->ptag, p_data->ptag); 
            }
            else
            {
                /* SR - I'm not sure how to reach this code. Maybe if the first
                 * time we added an ipv4 block, there was no payload, but when
                 * we modify the block the next time, we have payload?
		 */

                /* update without setting this as the final pblock */
                p_data->type  =  LIBNET_PBLOCK_IPDATA;
                p_data->ptag  =  ++(l->ptag_state);
                p_data->h_len =  payload_s; /* TODO dead code, data blocks don't have headers */

                /* data was added after the initial construction */
                for (p_temp = l->protocol_blocks;
                        p_temp->type == LIBNET_PBLOCK_IPV4_H ||
                        p_temp->type == LIBNET_PBLOCK_IPO_H;
                        p_temp = p_temp->next)
                {
                    std_pblock_insert_before(l, p_temp->ptag, p_data->ptag);
                    break;
                }

                /* the end block needs to have its next pointer cleared */
                l->pblock_end->next = NULL;
            }

            if (p_data->prev && p_data->prev->type == LIBNET_PBLOCK_IPO_H)
            {
                std_pblock_swap(l, p_data->prev->ptag, p_data->ptag); 
            }
        }
    }
    else
    {
        p_data = std_pblock_find(l, ptag_data);
        if (p_data) 
        {
            std_pblock_delete(l, p_data);
        }
        else
        {
            /* 
             * XXX - When this completes successfully, libnet errbuf contains 
             * an error message so to come correct, we'll clear it.
             */ 
            memset(l->err_buf, 0, sizeof (l->err_buf));
        }
    }
    if (sum == 0)
    {
        /*
         *  If checksum is zero, by default libnet will compute a checksum
         *  for the user.  The programmer can override this by calling
         *  std_toggle_checksum(l, ptag, 1);
         */
        std_pblock_setflags(p, LIBNET_PBLOCK_DO_CHECKSUM);
    }

    return (ptag);
bad:
    std_pblock_delete(l, p);
    return (-1);
}


int
std_write(std_t *l)
{
    int c;
    uint32_t len;
    uint8_t *packet = NULL;

    if (l == NULL)
    { 
        return (-1);
    }

    c = std_pblock_coalesce(l, &packet, &len);
    if (c == - 1)
    {
        /* err msg set in std_pblock_coalesce() */
        return (-1);
    }

    /* assume error */
    c = -1;
    switch (l->injection_type)
    {
        case STD_RAW4:
            if (len > LIBNET_MAX_PACKET)
            {
                snprintf(l->err_buf, STD_ERRBUF_SIZE,
                        "%s(): packet is too large (%d bytes)\n",
                        __func__, len);
                goto done;
            }
            c = std_write_raw_ipv4(l, packet, len);
            break;
        default:
            snprintf(l->err_buf, STD_ERRBUF_SIZE,
                        "%s(): unsuported injection type\n", __func__);
            goto done;
    }

    /* do statistics */
    if (c == len)
    {
        l->stats.packets_sent++;
        l->stats.bytes_written += c;
    }
    else
    {
        l->stats.packet_errors++;
        /*
         *  XXX - we probably should have a way to retrieve the number of
         *  bytes actually written (since we might have written something).
         */
        if (c > 0)
        {
            l->stats.bytes_written += c;
        }
    }
done:
    /*
     *  Restore original pointer address so free won't complain about a
     *  modified chunk pointer.
     */
    if (l->aligner > 0)
    {
        packet = packet - l->aligner;
    }
    free(packet);
    return (c);
}



int
std_pblock_coalesce(std_t *l, uint8_t **packet, uint32_t *size)
{
    /*
     *  Determine the offset required to keep memory aligned (strict
     *  architectures like solaris enforce this, but's a good practice
     *  either way).  This is only required on the link layer with the
     *  14 byte ethernet offset (others are similarly unkind).
     */
    if (l->injection_type == LIBNET_LINK || 
        l->injection_type == LIBNET_LINK_ADV)
    {
        /* 8 byte alignment should work */
        l->aligner = 8 - (l->link_offset % 8);
    }
    else
    {
        l->aligner = 0;
    }

    if(!l->total_size && !l->aligner) {
        /* Avoid allocating zero bytes of memory, it perturbs electric fence. */
        *packet = (uint8_t *)malloc(1);
        **packet =1;
    } else {
        *packet = (uint8_t *)malloc(l->aligner + l->total_size);
    }
    if (*packet == NULL)
    {
        snprintf(l->err_buf, STD_ERRBUF_SIZE, "%s(): malloc(): %s\n",
                __func__, strerror(errno));
        return (-1);
    }

    memset(*packet, 0, l->aligner + l->total_size);

    if (l->injection_type == STD_RAW4 && 
        l->pblock_end->type == LIBNET_PBLOCK_IPV4_H)
    {
        std_pblock_setflags(l->pblock_end, LIBNET_PBLOCK_DO_CHECKSUM); 
    }
    
    /* additional sanity checks to perform if we're not in advanced mode */
    if (!(l->injection_type & LIBNET_ADV_MASK))
    {
    	switch (l->injection_type)
    	{
            case STD_RAW4:
                if ((l->pblock_end->type != LIBNET_PBLOCK_IPV4_H))
                {
                    snprintf(l->err_buf, STD_ERRBUF_SIZE, 
                    "%s(): packet assembly cannot find an IPv4 header\n",
                     __func__);
                    goto err;
                }
                break;
            default:
                /* we should not end up here ever */
                snprintf(l->err_buf, STD_ERRBUF_SIZE, 
                "%s(): suddenly the dungeon collapses -- you die\n",
                 __func__);
                goto err;
            break;
        }
    }

    /* Build packet from end to start. */
    {
        /*
           From top to bottom, go through pblocks pairwise:

           p   is the currently being copied pblock, and steps through every block
           q   is the prev pblock to p that needs checksumming, it will
               not step through every block as p does, it will skip any that do not
               need checksumming.
           n   offset from start of packet to beginning of block we are writing

           q is NULL on first iteration
           p is NULL on last iteration

           Checksums are done on q, to give p a chance to be copied over, since
           checksumming q can require a lower-level header to be encoded, in the
           case of IP protocols (which are the only kinds handled by libnet's
           checksum implementation).

           This is very obscure, or would be much more clear if it was done in
           two loops.
           */
        std_pblock_t *q = NULL;
        std_pblock_t *p = NULL;
        uint32_t n;

        for (n = l->aligner + l->total_size, p = l->protocol_blocks; p || q; )
        {
            if (q)
            {
                p = p->next;
            }
            if (p)
            {
                n -= p->b_len;
                /* copy over the packet chunk */
                memcpy(*packet + n, p->buf, p->b_len);
            }
#if 0
            printf("-- n %d/%d cksum? %d\n", n, l->aligner + l->total_size,
                    q &&
                    (p == NULL || (p->flags & LIBNET_PBLOCK_DO_CHECKSUM)) &&
                    (q->flags & LIBNET_PBLOCK_DO_CHECKSUM));
            if(q)
            {
                printf(" iph %d/%d offset -%d\n",
                        (l->total_size + l->aligner) - q->ip_offset,
                        l->total_size + l->aligner,
                        q->ip_offset
                      );
            }
            if (p)
            {
                printf("p %p ptag %d b_len %d h_len %d cksum? %d type %s\n",
                        p, p->ptag,
                        p->b_len, p->h_len,
                        p->flags & LIBNET_PBLOCK_DO_CHECKSUM,
                        std_diag_dump_pblock_type(p->type)
                      );
            }
            if (q)
            {
                printf("q %p ptag %d b_len %d h_len %d cksum? %d type %s\n",
                        q, q->ptag,
                        q->b_len, q->h_len,
                        q->flags & LIBNET_PBLOCK_DO_CHECKSUM,
                        std_diag_dump_pblock_type(q->type)
                      );
            }
#endif
            if (q)
            {
                if (p == NULL || (p->flags & LIBNET_PBLOCK_DO_CHECKSUM))
                {
                    if (q->flags & LIBNET_PBLOCK_DO_CHECKSUM)
                    {
                        uint32_t c;
                        uint8_t* end = *packet + l->aligner + l->total_size;
                        uint8_t* beg = *packet + n;
                        int ip_offset = calculate_ip_offset(l, q);
                        uint8_t* iph = end - ip_offset;
#if 0
			printf("p %d/%s q %d/%s offset calculated %d\n",
				p ? p->ptag : -1, p ? std_diag_dump_pblock_type(p->type) : "nil",
				q->ptag, std_diag_dump_pblock_type(q->type),
				ip_offset);
#endif
                        c = std_inet_checksum(l, iph,
                                std_pblock_p2p(q->type), q->h_len,
                                beg, end);
                        if (c == -1)
                        {
                            /* err msg set in std_do_checksum() */
                            goto err;
                        }
                    }
                    q = p;
                }
            }
            else
            {
                q = p;
            }
        }
    }
    *size = l->aligner + l->total_size;

    /*
     *  Set the packet pointer to the true beginning of the packet and set
     *  the size for transmission.
     */
    if ((l->injection_type == LIBNET_LINK ||
        l->injection_type == LIBNET_LINK_ADV) && l->aligner)
    {
        *packet += l->aligner;
        *size -= l->aligner;
    }
    return (1);

err:
    free(*packet);
    *packet = NULL;
    return (-1);
}

int
std_pblock_p2p(uint8_t type)
{
    /* for checksum; return the protocol number given a pblock type*/
    switch (type)
    {
        case LIBNET_PBLOCK_IPV4_H:
            return (IPPROTO_IP);
        case LIBNET_PBLOCK_OSPF_H:
            return (IPPROTO_OSPF);
        case LIBNET_PBLOCK_LS_RTR_H:
            return (IPPROTO_OSPF_LSA);
        case LIBNET_PBLOCK_TCP_H:
            return (IPPROTO_TCP);

        default:
            return (-1);
    }
}

static int pblock_is_ip(std_pblock_t* p)
{
    return p->type == LIBNET_PBLOCK_IPV4_H || p->type == LIBNET_PBLOCK_IPV6_H;
}


/* q is either an ip hdr, or is followed  by an ip hdr. return the offset
 * from end of packet. if there is no offset, we'll return the total size,
 * and things will break later
 */
static int calculate_ip_offset(std_t* l, std_pblock_t* q)
{
    int ip_offset = 0;
    std_pblock_t* p = l->protocol_blocks;
    for(; p && p != q; p = p->next) {
	ip_offset += p->b_len;
    }
    assert(p == q); /* if not true, then q is not a pblock! */

    for(; p; p = p->next) {
	ip_offset += p->b_len;
	if(pblock_is_ip(p))
	    break;
    }

    return ip_offset;
}

#define CHECK_IP_PAYLOAD_SIZE() do { \
    int e=check_ip_payload_size(l,iphdr,ip_hl, h_len, end, __func__);\
    if(e) return e;\
} while(0)

int
std_inet_checksum(std_t *l, uint8_t *iphdr, int protocol, int h_len, const uint8_t *beg, const uint8_t * end)
{
    /* will need to update this for ipv6 at some point */
    struct std_ipv4_hdr *iph_p = (struct std_ipv4_hdr *)iphdr;
    //struct std_ipv6_hdr *ip6h_p = NULL; /* default to not using IPv6 */
    int ip_hl   = 0;
    int sum     = 0;
    int is_ipv6 = 0; /* TODO - remove this, it is redundant with ip6h_p */

    /* Check for memory under/over reads/writes. */
    if(iphdr < beg || (iphdr+sizeof(*iph_p)) > end)
    {
        snprintf(l->err_buf, STD_ERRBUF_SIZE,
            "%s(): ipv4 hdr not inside packet (where %d, size %d)\n", __func__,
	    (int)(iphdr-beg), (int)(end-beg));
        return -1;
    }

    /*
     *  Figure out which IP version we're dealing with.  We'll assume v4
     *  and overlay a header structure to yank out the version.
     */
    if (iph_p->ip_v == 6)
    {
        //ip6h_p = (struct std_ipv6_hdr *)iph_p;
        iph_p = NULL;
        ip_hl   = 40;
        //if((uint8_t*)(ip6h_p+1) > end)
        {
            snprintf(l->err_buf, STD_ERRBUF_SIZE,
                    "%s(): ipv6 hdr not inside packet\n", __func__);
            return -1;
        }
    }
    else
    {
        ip_hl = iph_p->ip_hl << 2;
    }

    if((iphdr+ip_hl) > end)
    {
        snprintf(l->err_buf, STD_ERRBUF_SIZE,
            "%s(): ip hdr len not inside packet\n", __func__);
        return -1;
    }

    /*
     *  Dug Song came up with this very cool checksuming implementation
     *  eliminating the need for explicit psuedoheader use.  Check it out.
     */
    switch (protocol)
    {
        case IPPROTO_OSPF:
        {
            struct std_ospf_hdr *oh_p =
                (struct std_ospf_hdr *)(iphdr + ip_hl);

            CHECK_IP_PAYLOAD_SIZE();

            oh_p->ospf_sum = 0;
            sum += std_in_cksum((uint16_t *)oh_p, h_len);
            oh_p->ospf_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_OSPF_LSA:
        {
            struct std_ospf_hdr *oh_p =
                (struct std_ospf_hdr *)(iphdr + ip_hl);
            struct std_lsa_hdr *lsa_p =
                (struct std_lsa_hdr *)(iphdr + 
                ip_hl + oh_p->ospf_len);

            /* FIXME need additional length check, to account for ospf_len */
            lsa_p->lsa_sum = 0;
            sum += std_in_cksum((uint16_t *)lsa_p, h_len);
            lsa_p->lsa_sum = LIBNET_CKSUM_CARRY(sum);
            break;
#if 0
            /*
             *  Reworked fletcher checksum taken from RFC 1008.
             */
            int c0, c1;
            struct std_lsa_hdr *lsa_p = (struct std_lsa_hdr *)buf;
            uint8_t *p, *p1, *p2, *p3;

            c0 = 0;
            c1 = 0;

            lsa_p->lsa_cksum = 0;

            p = buf;
            p1 = buf;
            p3 = buf + len;             /* beginning and end of buf */

            while (p1 < p3)
            {
                p2 = p1 + LIBNET_MODX;
                if (p2 > p3)
                {
                    p2 = p3;
                }
  
                for (p = p1; p < p2; p++)
                {
                    c0 += (*p);
                    c1 += c0;
                }

                c0 %= 255;
                c1 %= 255;      /* modular 255 */
 
                p1 = p2;
            }

#if AWR_PLEASE_REWORK_THIS
            lsa_p->lsa_cksum[0] = (((len - 17) * c0 - c1) % 255);
            if (lsa_p->lsa_cksum[0] <= 0)
            {
                lsa_p->lsa_cksum[0] += 255;
            }

            lsa_p->lsa_cksum[1] = (510 - c0 - lsa_p->lsa_cksum[0]);
            if (lsa_p->lsa_cksum[1] > 255)
            {
                lsa_p->lsa_cksum[1] -= 255;
            }
#endif
            break;
#endif
        }
        case IPPROTO_IP:
        {
            if(!iph_p) {
                /* IPv6 doesn't have a checksum */
            } else {
                iph_p->ip_sum = 0;
                sum = std_in_cksum((uint16_t *)iph_p, ip_hl);
                iph_p->ip_sum = LIBNET_CKSUM_CARRY(sum);
            }
            break;
        }
        
        default:
        {
            snprintf(l->err_buf, STD_ERRBUF_SIZE,
                "%s(): unsuported protocol %d\n", __func__, protocol);
            return (-1);
        }
    }
    return (1);
}

#undef DEBIAN
/* Note: len is in bytes, not 16-bit words! */
int
std_in_cksum(uint16_t *addr, int len)
{
    int sum;
#ifdef DEBIAN
    uint16_t last_byte;

    sum = 0;
    last_byte = 0;
#else
    union
    {
        uint16_t s;
        uint8_t b[2];
    }pad;

    sum = 0;
#endif

    while (len > 1)
    {
        sum += *addr++;
        len -= 2;
    }
#ifdef DEBIAN
    if (len == 1)
    {
        *(uint8_t *)&last_byte = *(uint8_t *)addr;
        sum += last_byte;
#else
    if (len == 1)
    {
        pad.b[0] = *(uint8_t *)addr;
        pad.b[1] = 0;
        sum += pad.s;
#endif
    }

    return (sum);
}

std_ptag_t
std_build_ospfv2_dbd(uint16_t dgram_len, uint8_t opts, uint8_t type,
uint32_t seqnum, const uint8_t *payload, uint32_t payload_s, std_t *l,
std_ptag_t ptag)
{
    uint32_t n, h;
    std_pblock_t *p;
    struct std_dbd_hdr dbd_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 

    n = STD_OSPF_DBD_H + payload_s;
    h = 0;

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = std_pblock_probe(l, ptag, n, LIBNET_PBLOCK_OSPF_DBD_H);
    if (p == NULL)
    {
        return (-1);
    }
    
    memset(&dbd_hdr, 0, sizeof(dbd_hdr));
    dbd_hdr.dbd_mtu_len	= htons(dgram_len); /* Max length of IP packet IF can use */
    dbd_hdr.dbd_opts    = opts;	            /* OSPF_* options */
    dbd_hdr.dbd_type    = type;	            /* Type of exchange occuring */
    dbd_hdr.dbd_seq     = htonl(seqnum);    /* DBD sequence number */

    n = std_pblock_append(l, p, (uint8_t *)&dbd_hdr, STD_OSPF_DBD_H);
    if (n == -1)
    {
        goto bad;
    }

    /* boilerplate payload sanity check / append macro */
    STD_DO_PAYLOAD(l, p);

    return (ptag ? ptag : std_pblock_update(l, p, h, 
            LIBNET_PBLOCK_OSPF_DBD_H));
bad:
    std_pblock_delete(l, p);
    return (-1);
}


/* FIXME both ptag setting and end setting should be done in pblock new and/or pblock probe. */
std_ptag_t
std_pblock_update(std_t *l, std_pblock_t *p, uint32_t h_len, uint8_t type)
{
    p->type  =  type;
    p->ptag  =  ++(l->ptag_state);
    p->h_len = h_len;
    l->pblock_end = p;              /* point end of pblock list here */

    return (p->ptag);
}

uint32_t
std_name2addr4(std_t *l, char *host_name, uint8_t use_name)
{
    struct in_addr addr;
    struct hostent *host_ent; 
    uint32_t m;
    uint val;
    int i;

    if (use_name == LIBNET_RESOLVE)
    {
		if ((addr.s_addr = inet_addr(host_name)) == -1)
        {
            if (!(host_ent = gethostbyname(host_name)))
            {
                snprintf(l->err_buf, STD_ERRBUF_SIZE,
                        "%s(): %s\n", __func__, hstrerror(h_errno));
                /* XXX - this is actually 255.255.255.255 */
                return (-1);
            }
            memcpy(&addr.s_addr, host_ent->h_addr, host_ent->h_length);
        }
        /* network byte order */
        return (addr.s_addr);
    }
    else
    {
        /*
         *  We only want dots 'n decimals.
         */
        if (!isdigit(host_name[0]))
        {
            if (l)
            {
                snprintf(l->err_buf, STD_ERRBUF_SIZE,
                    "%s(): expecting dots and decimals\n", __func__);
            }
            /* XXX - this is actually 255.255.255.255 */
            return (-1);
        }

        m = 0;
        for (i = 0; i < 4; i++)
        {
            m <<= 8;
            if (*host_name)
            {
                val = 0;
                while (*host_name && *host_name != '.')
                {   
                    val *= 10;
                    val += *host_name - '0';
                    if (val > 255)
                    {
                        if (l)
                        {
                            snprintf(l->err_buf, STD_ERRBUF_SIZE,
                            "%s(): value greater than 255\n", __func__);
                        }
                        /* XXX - this is actually 255.255.255.255 */
                        return (-1);
                    }
                    host_name++;
                }
                m |= val;
                if (*host_name)
                {
                    host_name++;
                }
            }
        }
        /* host byte order */
       return (ntohl(m));
    }
}


std_ptag_t
std_build_ospfv2_lsr(uint32_t type, uint lsid, uint32_t advrtr, 
const uint8_t *payload, uint32_t payload_s, std_t *l, std_ptag_t ptag)
{
    uint32_t n, h;
    std_pblock_t *p;
    struct std_lsr_hdr lsr_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 

    n = STD_OSPF_LSR_H + payload_s;
    h = 0;

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = std_pblock_probe(l, ptag, n, LIBNET_PBLOCK_OSPF_LSR_H);
    if (p == NULL)
    {
        return (-1);
    }

    memset(&lsr_hdr, 0, sizeof(lsr_hdr));
    lsr_hdr.lsr_type         = htonl(type);     /* Type of LS being requested */
    lsr_hdr.lsr_lsid	     = htonl(lsid);     /* Link State ID */
    lsr_hdr.lsr_adrtr.s_addr = htonl(advrtr);   /* Advertising router */

    n = std_pblock_append(l, p, (uint8_t *)&lsr_hdr, STD_OSPF_LSR_H);
    if (n == -1)
    {
        goto bad;
    }

    /* boilerplate payload sanity check / append macro */
    STD_DO_PAYLOAD(l, p);

    return (ptag ? ptag : std_pblock_update(l, p, h, 
            LIBNET_PBLOCK_OSPF_LSR_H));
bad:
    std_pblock_delete(l, p);
    return (-1);
}


char *
std_geterror(std_t *l)
{
    if (l == NULL)
    { 
        return (NULL);
    } 

    return (l->err_buf);
}

std_pblock_t *
std_pblock_new(std_t *l, uint32_t b_len)
{
    std_pblock_t *p = (std_pblock_t *)zmalloc(l, sizeof(std_pblock_t), __func__);
    if(!p)
        return NULL;

    p->buf = (uint8_t *)zmalloc(l, b_len, __func__);

    if(!p->buf)
    {
        free(p);
        return NULL;
    }

    p->b_len = b_len;

    l->total_size += b_len;
    l->n_pblocks++;

    /* make the head node if it doesn't exist */
    if (l->protocol_blocks == NULL)
    {
        l->protocol_blocks = p;
        l->pblock_end = p;
    }
    else
    {
        l->pblock_end->next = p;
        p->prev = l->pblock_end;
        l->pblock_end = p;
    }

    return p;
}

std_pblock_t *
std_pblock_find(std_t *l, std_ptag_t ptag)
{
    std_pblock_t *p;

    for (p = l->protocol_blocks; p; p = p->next)
    {
        if (p->ptag == ptag)
        {
            return (p); 
        }
    }
    snprintf(l->err_buf, STD_ERRBUF_SIZE,
            "%s(): couldn't find protocol block\n", __func__);
    return (NULL);
}

int
std_open_raw4(std_t *l)
{
    int len; /* now supposed to be socklen_t, but maybe old systems used int? */

#if !(__WIN32__)
     int n = 1;
#if (__svr4__)
     void *nptr = &n;
#else
    int *nptr = &n;
#endif  /* __svr4__ */
#else 
	BOOL n;
#endif

    if (l == NULL)
    { 
        return (-1);
    } 

    l->fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (l->fd == -1)
    {
        snprintf(l->err_buf, STD_ERRBUF_SIZE, 
                "%s(): SOCK_RAW allocation failed: %s\n",
		 __func__, strerror(errno));
        goto bad;
    }

#ifdef IP_HDRINCL
/* 
 * man raw
 *
 * The IPv4 layer generates an IP header when sending a packet unless
 * the IP_HDRINCL socket option is enabled on the socket.  When it
 * is enabled, the packet must contain an IP header.  For
 * receiving the IP header is always included in the packet.
 */
#if !(__WIN32__)
    if (setsockopt(l->fd, IPPROTO_IP, IP_HDRINCL, nptr, sizeof(n)) == -1)
#else
    n = TRUE;
    if (setsockopt(l->fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) == -1)
#endif

    {
        snprintf(l->err_buf, STD_ERRBUF_SIZE, 
                "%s(): set IP_HDRINCL failed: %s\n",
                __func__, strerror(errno));
        goto bad;
    }
#endif /*  IP_HDRINCL  */

#ifdef SO_SNDBUF

/*
 * man 7 socket 
 *
 * Sets and  gets  the  maximum  socket  send buffer in bytes. 
 *
 * Taken from libdnet by Dug Song
 */
    len = sizeof(n);
    if (getsockopt(l->fd, SOL_SOCKET, SO_SNDBUF, &n, (socklen_t *)&len) < 0)
    {
        snprintf(l->err_buf, STD_ERRBUF_SIZE, 
		 "%s(): get SO_SNDBUF failed: %s\n",
		 __func__, strerror(errno));
        goto bad;
    }
    
    for (n += 128; n < 1048576; n += 128)
    {
        if (setsockopt(l->fd, SOL_SOCKET, SO_SNDBUF, &n, len) < 0) 
        {
            if (errno == ENOBUFS)
            {
                break;
            }
             snprintf(l->err_buf, STD_ERRBUF_SIZE, 
                     "%s(): set SO_SNDBUF failed: %s\n",
                     __func__, strerror(errno));
             goto bad;
        }
    }
#endif

#ifdef SO_BROADCAST
/*
 * man 7 socket
 *
 * Set or get the broadcast flag. When  enabled,  datagram  sockets
 * receive packets sent to a broadcast address and they are allowed
 * to send packets to a broadcast  address.   This  option  has  no
 * effect on stream-oriented sockets.
 */
    if (setsockopt(l->fd, SOL_SOCKET, SO_BROADCAST, nptr, sizeof(n)) == -1)
    {
        snprintf(l->err_buf, STD_ERRBUF_SIZE,
                "%s(): set SO_BROADCAST failed: %s\n",
                __func__, strerror(errno));
        goto bad;
    }
#endif  /*  SO_BROADCAST  */
    return (l->fd);

bad:
    return (-1);    
}

void
std_pblock_setflags(std_pblock_t *p, uint8_t flags)
{
    p->flags = flags;
}

int
std_pblock_swap(std_t *l, std_ptag_t ptag1, std_ptag_t ptag2)
{
    std_pblock_t *p1, *p2;

    p1 = std_pblock_find(l, ptag1);
    p2 = std_pblock_find(l, ptag2);
    if (p1 == NULL || p2 == NULL)
    {
        /* error set elsewhere */
        return (-1);
    }

    p2->prev = p1->prev;
    p1->next = p2->next;
    p2->next = p1;
    p1->prev = p2;

    if (p1->next)
    {
        p1->next->prev = p1;
    }

    if (p2->prev)
    {
        p2->prev->next = p2;
    }
    else
    {
        /* first node on the list */
        l->protocol_blocks = p2;
    }

    if (l->pblock_end == p2)
    {
        l->pblock_end = p1;
    }
    return (1);
}

int
std_pblock_insert_before(std_t *l, std_ptag_t ptag1,
        std_ptag_t ptag2)
{
    std_pblock_t *p1, *p2;

    p1 = std_pblock_find(l, ptag1);
    p2 = std_pblock_find(l, ptag2);
    if (p1 == NULL || p2 == NULL)
    {
        /* error set elsewhere */
        return (-1);
    }

    /* check for already present before */
    if(p2->next == p1)
        return 1;

    std_pblock_remove_from_list(l, p2);

    /* insert p2 into list */
    p2->prev = p1->prev;
    p2->next = p1;
    p1->prev = p2;

    if (p2->prev)  
    {
        p2->prev->next = p2;
    }
    else
    {
        /* first node on the list */
        l->protocol_blocks = p2;
    }
    
    return (1);
}

int
std_write_raw_ipv4(std_t *l, const uint8_t *packet, uint32_t size)
{
    int c;
    struct sockaddr_in sin;
    struct std_ipv4_hdr *ip_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 

    ip_hdr = (struct std_ipv4_hdr *)packet;

#if (LIBNET_BSD_BYTE_SWAP)
    /*
     *  For link access, we don't need to worry about the inconsistencies of
     *  certain BSD kernels.  However, raw socket nuances abound.  Certain
     *  BSD implmentations require the ip_len and ip_off fields to be in host
     *  byte order.
     */
    ip_hdr->ip_len = FIX(ip_hdr->ip_len);
    ip_hdr->ip_off = FIX(ip_hdr->ip_off);
#endif /* LIBNET_BSD_BYTE_SWAP */

    memset(&sin, 0, sizeof(sin));
    sin.sin_family  = AF_INET;
    sin.sin_addr.s_addr = ip_hdr->ip_dst.s_addr;
#if (__WIN32__)
    /* set port for TCP */
    /*
     *  XXX - should first check to see if there's a pblock for a TCP
     *  header, if not we can use a dummy value for the port.
     */
    if (ip_hdr->ip_p == 6)
    {
        struct std_tcp_hdr *tcph_p =
                (struct std_tcp_hdr *)(packet + (ip_hdr->ip_hl << 2));
        sin.sin_port = tcph_p->th_dport;
    }
    /* set port for UDP */
    /*
     *  XXX - should first check to see if there's a pblock for a UDP
     *  header, if not we can use a dummy value for the port.
     */
    else if (ip_hdr->ip_p == 17)
    {
        struct std_udp_hdr *udph_p =
                (struct std_udp_hdr *)(packet + (ip_hdr->ip_hl << 2));
       sin.sin_port = udph_p->uh_dport;
    }
#endif /* __WIN32__ */

    c = sendto(l->fd, packet, size, 0, (struct sockaddr *)&sin,
            sizeof(struct sockaddr));

#if (LIBNET_BSD_BYTE_SWAP)
    ip_hdr->ip_len = UNFIX(ip_hdr->ip_len);
    ip_hdr->ip_off = UNFIX(ip_hdr->ip_off);
#endif /* LIBNET_BSD_BYTE_SWAP */

    if (c != size)
    {
#if !(__WIN32__)
        snprintf(l->err_buf, STD_ERRBUF_SIZE,
                "%s(): %d bytes written (%s)\n", __func__, c,
                strerror(errno));
#else /* __WIN32__ */
        snprintf(l->err_buf, STD_ERRBUF_SIZE,
                "%s(): %d bytes written (%d)\n", __func__, c,
                WSAGetLastError());
#endif /* !__WIN32__ */
    }
    return (c);
}


static int check_ip_payload_size(std_t*l, const uint8_t *iphdr, int ip_hl, int h_len, const uint8_t * end, const char* func)
{
    if((iphdr+ip_hl+h_len) > end)
    {
        snprintf(l->err_buf, STD_ERRBUF_SIZE,
                "%s(): ip payload not inside packet (pktsz %d, iphsz %d, payloadsz %d)\n", func,
		(int)(end - iphdr), ip_hl, h_len);
        return -1;
    }

    return 0;
}

static void* zmalloc(std_t* l, uint32_t size, const char* func)
{
    void* v = malloc(size);
    if(v)
        memset(v, 0, size);
    else
        snprintf(l->err_buf, STD_ERRBUF_SIZE, "%s(): malloc(): %s\n", func, 
                strerror(errno));
    return v;
}


std_ptag_t
std_build_ospfv2_lsa(uint16_t age, uint8_t opts, uint8_t type, uint lsid,
uint32_t advrtr, uint32_t seqnum, uint16_t sum, uint16_t len,
const uint8_t *payload, uint32_t payload_s, std_t *l, std_ptag_t ptag)
{
    uint32_t n, h;
    std_pblock_t *p;
    struct std_lsa_hdr lsa_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 

    n = STD_OSPF_LSA_H + payload_s;
    h = len + payload_s;

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = std_pblock_probe(l, ptag, n, LIBNET_PBLOCK_OSPF_LSA_H);
    if (p == NULL)
    {
        return (-1);
    }

    memset(&lsa_hdr, 0, sizeof(lsa_hdr));
    lsa_hdr.lsa_age         = htons(age);
    lsa_hdr.lsa_opts        = opts;
    lsa_hdr.lsa_type        = type;
    lsa_hdr.lsa_id          = htonl(lsid);
    lsa_hdr.lsa_adv.s_addr  = htonl(advrtr);
    lsa_hdr.lsa_seq         = htonl(seqnum);
    lsa_hdr.lsa_sum         = sum;
    lsa_hdr.lsa_len         = htons(h);

    n = std_pblock_append(l, p, (uint8_t *)&lsa_hdr, STD_OSPF_LSA_H);
    if (n == -1)
    {
        goto bad;
    }

    /* boilerplate payload sanity check / append macro */
    STD_DO_PAYLOAD(l, p);

    if (sum == 0)
    {
        /*
         *  If checksum is zero, by default libnet will compute a checksum
         *  for the user.  The programmer can override this by calling
         *  std_toggle_checksum(l, ptag, 1);
         */
        std_pblock_setflags(p, LIBNET_PBLOCK_DO_CHECKSUM);
    }
    return (ptag ? ptag : std_pblock_update(l, p, h, 
            LIBNET_PBLOCK_OSPF_LSA_H));
bad:
    std_pblock_delete(l, p);
    return (-1);
}
