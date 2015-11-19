#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "nc_nvr_sdk.h"

#include "st_arp.h"

#define NC_DEBUG 1

#ifndef st_dbg
#if NC_DEBUG == 1
#define st_dbg(format, ...) \
            printf("[%05d:%s]"format"\n", \
            __LINE__, \
            __FUNCTION__, \
            ## __VA_ARGS__)
#else
#define st_dbg(format, ...)
#endif
#endif

#define st_err(format, args...) \
            fprintf(stderr, "[%05d:%s]"format"\n", \
            __LINE__, \
            __FUNCTION__, \
            ##args)

static inline void st_fds_set(fd_set * fds, int fd, int *maxfd)
{
    FD_SET(fd, fds);
    if (*maxfd < fd)
    {
        *maxfd = fd;
    }
}


#define TEST   1

#define NC_WIRE_VID_START   3200
#define NC_WIRELESS_VID     3249
#define NC_WIRELESS_SZ      13
#define NC_ARP_TIMEOUT_INTERVAL 2
#define NC_ARP_TIMEOUT_MAX      5

const static uint8_t bcast_hwaddr[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

struct arp_pkt
{
    /* Ethernet header */
    uint8_t  h_dest[ETH_ALEN];     /* 00 destination ether addr */
    uint8_t  h_source[ETH_ALEN];   /* 06 source ether addr */
    uint16_t h_proto;       /* 0c packet type ID field */

    /* ARP packet */
    uint16_t htype;         /* 0e hardware type (must be ARPHRD_ETHER) */
    uint16_t ptype;         /* 10 protocol type (must be ETH_P_IP) */
    uint8_t  hlen;          /* 12 hardware address length (must be 6) */
    uint8_t  plen;          /* 13 protocol address length (must be 4) */
    uint16_t operation;     /* 14 ARP opcode */
    uint8_t  src_hwaddr[ETH_ALEN];     /* 16 sender's hardware address */
    uint8_t  src_inaddr[4];    /* 1c sender's IP address */
    uint8_t  tgt_hwaddr[ETH_ALEN];     /* 20 target's hardware address */
    uint8_t  tgt_inaddr[4];    /* 26 target's IP address */
    uint8_t  pad[18];       /* 2a pad for min. ethernet payload (60 bytes) */
};

struct nc_ipcs_table_item
{
    int port;
    uint32_t ip;
    uint8_t mac[8];
    int alive_sec;
};

struct nc_ipcs_table
{
    char iface_name[32];

    int init_fds[2];
    int init_ok;

    int dhcp_fd;
    int get_fd;

    pthread_mutex_t tbl_lock;

    int wire_cnt;
    struct nc_ipcs_table_item *wire_ipcs;

    int wireless_enable;
    struct nc_ipcs_table_item *wireless_ipcs;
};

static struct nc_ipcs_table ipcs_tbl;

static void *ipcs_table_updating(void *data);

static inline int get_iface_addr(
    const char *iface_name,
    uint8_t *hwaddr,
    int hwaddr_len,
    uint32_t *ip
)
{
    int fd = -1;
    struct ifreq mreq;
    int ret = -1;

    if (hwaddr_len < ETH_ALEN)
    {
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        st_err("socket error:%d!\n", errno);
        perror("socket");
        return -1;
    }

    memset(&mreq, 0, sizeof(mreq));
    strcpy(mreq.ifr_name, iface_name);

    ret = ioctl(fd, SIOCGIFHWADDR, &mreq);
    if (ret < 0)
    {
        st_err("ioctl error:%d!\n", errno);
        perror("ioctl");
        goto out;
    }
    memcpy(hwaddr, mreq.ifr_hwaddr.sa_data, ETH_ALEN);


    memset(&mreq, 0, sizeof(mreq));
    strcpy(mreq.ifr_name, iface_name);

    ret = ioctl(fd, SIOCGIFADDR, &mreq);
    if (ret < 0)
    {
        st_err("ioctl error:%d!\n", errno);
        perror("ioctl");
        goto out;
    }
    memcpy(ip, &((struct sockaddr_in *)(&mreq.ifr_addr))->sin_addr, sizeof(*ip));

    ret = 0;
out:
    close(fd);
    return ret;
}


static int __nc_ipcs_table_init(
    struct nc_ipcs_table *tbl,
    const char *iface_name,
    int dhcp_fd,
    int get_fd,
    int wire_cnt,
    int wireless_enable
)
{
    int i;
    int ret = -1;

    memset(tbl, 0, sizeof(*tbl));
    strcpy(tbl->iface_name, iface_name);

    tbl->init_fds[0] = -1;
    tbl->init_fds[1] = -1;

    ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, tbl->init_fds);
    if (ret < 0)
    {
        st_err("socketpair failed:%d!\n", errno);
        perror("socketpair");
        return -1;
    }

    tbl->dhcp_fd = dhcp_fd;
    tbl->get_fd = get_fd;
    pthread_mutex_init(&tbl->tbl_lock, NULL);
    tbl->wire_cnt = wire_cnt;
    tbl->wire_ipcs = (struct nc_ipcs_table_item *)calloc(
                         tbl->wire_cnt,
                         sizeof(*tbl->wire_ipcs)
                     );
    if (!tbl->wire_ipcs)
    {
        goto error;
    }

    for (i = 0; i < tbl->wire_cnt; ++i)
    {
        tbl->wire_ipcs[i].port = i;
        tbl->wire_ipcs[i].alive_sec = -1;
    }

    tbl->wireless_enable = wireless_enable;
    if (tbl->wireless_enable)
    {
        tbl->wireless_ipcs = (struct nc_ipcs_table_item *)calloc(
                                 NC_WIRELESS_SZ,
                                 sizeof(*tbl->wireless_ipcs)
                             );
        if (!tbl->wireless_ipcs)
        {
            goto error;
        }
    }
    if (tbl->wireless_enable)
    {
        for (i = 0; i < NC_WIRELESS_SZ; ++i)
        {
            tbl->wireless_ipcs[i].port = -1;
            tbl->wireless_ipcs[i].alive_sec = -1;
        }
    }
    return 0;
error:
    if (tbl->wireless_ipcs)
    {
        free(tbl->wireless_ipcs);
        tbl->wireless_ipcs = NULL;
    }

    if (tbl->wire_ipcs)
    {
        free(tbl->wire_ipcs);
        tbl->wire_ipcs = NULL;
    }

    pthread_mutex_destroy(&tbl->tbl_lock);

    close(tbl->init_fds[0]);
    tbl->init_fds[0] = -1;
    close(tbl->init_fds[1]);
    tbl->init_fds[1] = -1;

    return -1;
}

int nc_ipcs_table_init(
    int dhcp_fd,
    int get_fd,
    int wire_cnt,
    int wireless_enable
)
{
    pthread_t thd;
    int ret = 0;

    ret = __nc_ipcs_table_init(
              &ipcs_tbl,
              "eth0",
              dhcp_fd,
              get_fd,
              wire_cnt,
              wireless_enable
          );
    if (ret < 0)
    {
        return -1;
    }

    ret = pthread_create(&thd, NULL, ipcs_table_updating, (void *)&ipcs_tbl);
    if (ret != 0)
    {
        st_err("pthread_create failed:%d!\n", ret);
        perror("pthread_err");
        goto error;
    }

    while (!ipcs_tbl.init_ok)
    {
        int cmd = 0;
        ret = recv(ipcs_tbl.init_fds[0], &cmd, sizeof(cmd), 0);
        if (ret == sizeof(cmd))
        {
            ipcs_tbl.init_ok = 1;
            break;
        }
    }

    return 0;
error:
    nc_ipcs_table_uninit();
    return -1;
}

int nc_ipcs_table_uninit( void )
{
    struct nc_ipcs_table *tbl = &ipcs_tbl;

    pthread_mutex_destroy(&tbl->tbl_lock);

    if (tbl->wireless_ipcs)
    {
        free(tbl->wireless_ipcs);
        tbl->wireless_ipcs = NULL;

    }

    if (tbl->wire_ipcs)
    {
        free(tbl->wire_ipcs);
        tbl->wire_ipcs = NULL;
    }

    if (tbl->init_fds[0] != -1)
    {
        close(tbl->init_fds[0]);
        tbl->init_fds[0] = -1;
        close(tbl->init_fds[1]);
        tbl->init_fds[1] = -1;
    }

    return 0;
}

static int arp_socket_create(char *iface_name)
{
    int fd = -1;
    struct sockaddr_ll addr;
    int ret = -1;

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0)
    {
        st_err("socket error:%d!\n", errno);
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = if_nametoindex(iface_name);
    //addr.sll_hatype = ARPHRD_ETHER;
    //addr.sll_pkttype = PACKET_BROADCAST | PACKET_HOST;

    ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0)
    {
        st_err("bind error:%d!\n", errno);
        perror("bind");
        goto err;
    }

    return fd;
err:
    close(fd);
    return -1;
}

static inline int send_ipc_info(
    struct nc_ipcs_table *tbl,
    int port_idx,
    char *mac,
    uint32_t ip,
    int is_lost
)
{
    struct nc_new_info info = {0};
    info.port_id = port_idx;
    memcpy(info.hwaddr, mac, ETH_ALEN);
    info.client_ip = ip;
    info.is_lost = is_lost;
    return send(tbl->get_fd, &info, sizeof(info), MSG_DONTWAIT);
}

static inline int send_arp_req(
    int fd,
    uint8_t *src_hwaddr,
    uint32_t src_ip,
    uint32_t req_ip,
    struct sockaddr_ll *saddr,
    socklen_t saddr_len
)
{
    struct arp_pkt arp;
    int ret = -1;

    memset(&arp, 0, sizeof(arp));

    memcpy(arp.h_dest, bcast_hwaddr, ETH_ALEN);
    memcpy(arp.h_source, src_hwaddr, ETH_ALEN);
    arp.h_proto = htons(ETH_P_ARP);

    arp.htype = htons(ARPHRD_ETHER);
    arp.ptype = htons(ETH_P_IP);
    arp.hlen = ETH_ALEN;
    arp.plen = sizeof(uint32_t);
    arp.operation = htons(ARPOP_REQUEST);
    memcpy(arp.src_hwaddr, src_hwaddr, ETH_ALEN);
    memcpy(&arp.src_inaddr, (uint8_t *)&src_ip, 4);
    //memset(arp.tgt_hwaddr, 0, ETH_ALEN);
    memcpy(&arp.tgt_inaddr, (uint8_t *)&req_ip, 4);

    return sendto(
               fd,
               &arp,
               sizeof(arp),
               MSG_DONTWAIT,
               (struct sockaddr *)saddr,
               saddr_len
           );
}

static int ipcs_table_updating_by_time(struct nc_ipcs_table *tbl)
{
    int i;

    pthread_mutex_lock(&tbl->tbl_lock);
    for (i = 0; i < tbl->wire_cnt; ++i)
    {
        tbl->wire_ipcs[i].alive_sec--;
    }

    if (tbl->wireless_enable)
    {
        for (i = 0; i < NC_WIRELESS_SZ; ++i)
        {
            tbl->wireless_ipcs[i].alive_sec--;
        }
    }
    pthread_mutex_unlock(&tbl->tbl_lock);
}

static inline
void ipcs_table_refresh_wire(struct nc_ipcs_table *tbl, int *fds)
{
    struct nc_ipcs_table_item *ipc = NULL;
    int i;

    for (i = 0; i < tbl->wire_cnt; ++i)
    {
        ipc = &tbl->wire_ipcs[i];

        if (ipc->alive_sec < 0)
        {
            continue;
        }

        if (ipc->alive_sec == 0)
        {
            send_ipc_info(tbl, i, ipc->mac, ipc->ip, 1);
        }
        else
        {
            char iface_name[32];
            uint8_t hwaddr[ETH_ALEN] = {0};
            uint32_t src_ip = 0;
            int ret = -1;

            sprintf(iface_name, "%s.%d", tbl->iface_name, NC_WIRE_VID_START + i);
            ret = get_iface_addr(iface_name, hwaddr, ETH_ALEN, &src_ip);
            if (ret < 0)
            {
                continue;
            }

            send_arp_req(fds[i], hwaddr, src_ip, ipc->ip, NULL, 0);
        }
    }
}

static inline
void ipcs_table_refresh_wireless(struct nc_ipcs_table *tbl, int fd)
{
    struct nc_ipcs_table_item *ipc = NULL;
    char iface_name[32];
    uint8_t hwaddr[ETH_ALEN] = {0};
    uint32_t src_ip = 0;
    int ret = -1;
    int i;

    if (tbl->wireless_enable == 0)
    {
        return ;
    }

    sprintf(iface_name, "%s.%d", tbl->iface_name, NC_WIRELESS_VID);

    ret = get_iface_addr(iface_name, hwaddr, ETH_ALEN, &src_ip);
    if (ret < 0)
    {
        return ;
    }

    if (tbl->wireless_enable)
    {
        for (i = 0; i < NC_WIRELESS_SZ; ++i)
        {
            ipc = &tbl->wireless_ipcs[i];

            if (ipc->alive_sec < 0)
            {
                continue;
            }

            if (ipc->alive_sec == 0)
            {
                send_ipc_info(tbl, -1, ipc->mac, ipc->ip, 1);
            }
            else
            {
                if ((ipc->alive_sec & 0x1) == 0x1)
                {
                    st_dbg("send to \n");
                    send_arp_req(fd, hwaddr, src_ip, ipc->ip, NULL, 0);
                }
            }
        }
    }
}

static int ipcs_table_updating_wire(
    struct nc_ipcs_table *tbl,
    int port_idx,
    uint32_t ip,
    uint8_t *mac
)
{
    struct nc_ipcs_table_item *ipc = &tbl->wire_ipcs[port_idx];
    int get_new = 0;
    int lost_port = -1;
    int i;

    if (ipc->alive_sec <= 0)
    {
        get_new = 1;
    }
    else if (memcmp(ipc->mac, mac, ETH_ALEN))
    {
        get_new = 1;
    }
    else if (ipc->ip != ip)
    {
        get_new = 1;
    }
    else
    {
        get_new = 0;
    }

    if (get_new)
    {
        /*通知get_ipc, port_idx位置的原ipc已经丢失*/
        if (ipc->alive_sec > 0)
        {
            send_ipc_info(tbl, port_idx, ipc->mac, ipc->ip, 1);
        }

        for (i = 0; i < tbl->wire_cnt; ++i)
        {
            struct nc_ipcs_table_item *itm = &tbl->wire_ipcs[i];
            if (itm->alive_sec <= 0)
            {
                continue;
            }

            if (i == port_idx)
            {
                continue;
            }

            if (memcmp(tbl->wire_ipcs[i].mac, mac, ETH_ALEN))
            {
                continue;
            }

            lost_port = i;
            break;
        }

        if (lost_port != -1)
        {
            /*通知get_ipc, lost_port位置的原ipc已经丢失*/
            struct nc_ipcs_table_item * p = &tbl->wire_ipcs[lost_port];
            pthread_mutex_lock(&tbl->tbl_lock);
            p->alive_sec = -1;
            pthread_mutex_unlock(&tbl->tbl_lock);
            send_ipc_info(tbl, lost_port, p->mac, p->ip, 1);
        }

        /*更新为新的ipc信息*/
        pthread_mutex_lock(&tbl->tbl_lock);
        ipc->port = port_idx;
        ipc->ip = ip;
        memcpy(ipc->mac, mac, ETH_ALEN);
        ipc->alive_sec = NC_ARP_TIMEOUT_MAX;
        pthread_mutex_unlock(&tbl->tbl_lock);

        /*通知get_ipc, port_idx位置探测到新的ipc*/
        send_ipc_info(tbl, port_idx, ipc->mac, ipc->ip, 0);
    }
    else
    {
        pthread_mutex_lock(&tbl->tbl_lock);
        ipc->alive_sec = NC_ARP_TIMEOUT_MAX;
        pthread_mutex_unlock(&tbl->tbl_lock);
    }

    return 0;
}

static int ipcs_table_updating_wire_by_arp(
    struct nc_ipcs_table *tbl,
    int port_idx,
    char *pkt_buf,
    int pkt_len,
    struct sockaddr_ll *saddr
)
{
    struct arp_pkt *arp = (struct arp_pkt *)pkt_buf;
    uint32_t ip;

    if (pkt_len < (sizeof(struct arp_pkt)-18))
    {
        return -1;
    }
    if ((saddr->sll_pkttype != PACKET_HOST) && (saddr->sll_pkttype != PACKET_BROADCAST))
    {
        return -1;
    }

    /*我们只关心sender's address*/
    ip = *(uint32_t *)arp->src_inaddr;
    return ipcs_table_updating_wire(tbl, port_idx, ip, arp->src_hwaddr);
}

static int ipcs_table_updating_wireless(
    struct nc_ipcs_table *tbl,
    uint32_t ip,
    uint8_t *mac
)
{
    struct nc_ipcs_table_item *ipc = NULL;
    int i;
    int idle_idx = -1;
    int get_new = 1;

    for (i = 0; i < NC_WIRELESS_SZ; ++i)
    {
        ipc = &tbl->wireless_ipcs[i];

        if (ipc->alive_sec <= 0)
        {
            idle_idx = i;
            continue;
        }

        if (memcmp(ipc->mac, mac, ETH_ALEN))
        {
            continue;
        }

        get_new = 0;
        pthread_mutex_lock(&tbl->tbl_lock);
        ipc->alive_sec = NC_ARP_TIMEOUT_MAX;
        ipc->alive_sec <<= 1;
        pthread_mutex_unlock(&tbl->tbl_lock);
        break;
    }

    if (get_new)
    {
        if (idle_idx == -1)
        {
            /*没有空闲的位置了*/
            st_dbg("no more ....\n");
            return 0;
        }
        ipc = &tbl->wireless_ipcs[idle_idx];

        /*更新为新的ipc信息*/
        pthread_mutex_lock(&tbl->tbl_lock);
        ipc->port = -1;
        ipc->ip = ip;
        memcpy(ipc->mac, mac, ETH_ALEN);
        ipc->alive_sec = NC_ARP_TIMEOUT_MAX;
        ipc->alive_sec <<= 1;
        pthread_mutex_unlock(&tbl->tbl_lock);

        /*通知get_ipc, port_idx位置探测到新的ipc*/
        send_ipc_info(tbl, -1, ipc->mac, ipc->ip, 0);
    }

    return 0;
}

static int ipcs_table_updating_wireless_by_arp(
    struct nc_ipcs_table *tbl,
    char *pkt_buf,
    int pkt_len,
    struct sockaddr_ll *saddr
)
{
    struct arp_pkt *arp = (struct arp_pkt *)pkt_buf;
    uint32_t ip;

    if (pkt_len < (sizeof(struct arp_pkt)-18))//去掉18个填充位
    {
        st_dbg("pkt_len = %d\n",pkt_len);
        return -1;
    }

    if ((saddr->sll_pkttype != PACKET_HOST) && (saddr->sll_pkttype != PACKET_BROADCAST))
    {
        st_dbg("saddr->sll_pkttype = %d\n",saddr->sll_pkttype);
        return -1;
    }

    /*我们只关心sender's address*/

    ip = *(uint32_t *)arp->src_inaddr;
    st_dbg("ip = %d,mac = %02x:%02x\n",ip,(arp->src_hwaddr)[4],(arp->src_hwaddr)[5]);

    return ipcs_table_updating_wireless(tbl, ip, arp->src_hwaddr);
}

static void __ipcs_table_updating(
    struct nc_ipcs_table *tbl,
    int *arp_fds,
    int arp_wireless_fd
)
{
    fd_set readfds;
    int maxfd = -1;
    struct timeval timeo;
#define RCV_BUF_SIZE    1400
    char buf[RCV_BUF_SIZE];
    struct sockaddr_ll saddr;
    socklen_t saddr_len;
    int i;
    int ret = -1;

    timeo.tv_sec = NC_ARP_TIMEOUT_INTERVAL;
    timeo.tv_usec = 0;

    while (1)
    {
        FD_ZERO(&readfds);
        maxfd = 0;

        for (i = 0; i < tbl->wire_cnt; ++i)
        {
            st_fds_set(&readfds, arp_fds[i], &maxfd);
        }

        if (tbl->wireless_enable)
        {
            st_fds_set(&readfds, arp_wireless_fd, &maxfd);
        }

        st_fds_set(&readfds, tbl->dhcp_fd, &maxfd);

        ret = select(maxfd + 1, &readfds, NULL, NULL, &timeo);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            st_err("select error:%d\n", errno);
            perror("select ");
            break;
        }

        if (ret == 0)
        {
            timeo.tv_sec = NC_ARP_TIMEOUT_INTERVAL;
            timeo.tv_usec = 0;
            ipcs_table_updating_by_time(tbl);
            ipcs_table_refresh_wire(tbl, arp_fds);
            ipcs_table_refresh_wireless(tbl, arp_wireless_fd);
            continue;
        }

        /*for wire*/
        for (i = 0; i < tbl->wire_cnt; ++i)
        {
            if (FD_ISSET(arp_fds[i], &readfds))
            {
                st_dbg("\n");
                saddr_len = sizeof(saddr);
                memset(&saddr, 0, sizeof(saddr));
                ret = recvfrom(
                          arp_fds[i],
                          buf,
                          RCV_BUF_SIZE,
                          0,
                          (struct sockaddr *)&saddr,
                          &saddr_len
                      );
                if (ret < 0)
                {
                    st_err("recvfrom error:%d!\n", errno);
                    perror("recvfrom");
                    continue;
                }

                ipcs_table_updating_wire_by_arp(tbl, i, buf, ret, &saddr);
            }
        }

        /*for wireless*/
        if (tbl->wireless_enable)
        {
            if (FD_ISSET(arp_wireless_fd, &readfds))
            {
                st_dbg("\n");
                while (1)
                {
                    saddr_len = sizeof(saddr);
                    memset(&saddr, 0, sizeof(saddr));
                    ret = recvfrom(
                              arp_wireless_fd,
                              buf,
                              RCV_BUF_SIZE,
                              MSG_DONTWAIT,
                              (struct sockaddr *)&saddr,
                              &saddr_len
                          );
                    if (ret < 0)
                    {
                        st_dbg("errno = %d\n",errno);
                        if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
                        {
                            st_err("recvfrom error:%d!\n", errno);
                            perror("recvfrom");
                        }
                        break;
                    }

                    ipcs_table_updating_wireless_by_arp(tbl, buf, ret, &saddr);
                }
            }
        }

        if (FD_ISSET(tbl->dhcp_fd, &readfds))
        {
            struct nc_new_info *ipc = NULL;

            while (1)
            {
                ret = recv(tbl->dhcp_fd, buf, RCV_BUF_SIZE, MSG_DONTWAIT);
                if (ret < 0)
                {
                    if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
                    {
                        st_err("recv error:%d!\n", errno);
                        perror("recv");
                    }
                    break;
                }

                if (ret == 0)
                {
                    st_err("fd error, something wrong ...!\n");
                    break;
                }

                ipc = (struct nc_new_info*)buf;
                if (ipc->port_id == (unsigned short)-1)
                {
                    st_dbg("dhcp update:%d,%02x:%02x:%02x:%02x:%02x:%02x\n",
                           ipc->client_ip,(ipc->hwaddr)[0],(ipc->hwaddr)[1],
                           (ipc->hwaddr)[2],(ipc->hwaddr)[3],(ipc->hwaddr)[4],
                           (ipc->hwaddr)[5]);
                    ipcs_table_updating_wireless(tbl, ipc->client_ip, ipc->hwaddr);
                }
                else
                {
                    if ((((short)ipc->port_id) < 0) || (ipc->port_id >= tbl->wire_cnt))
                    {
                        st_err("port_id:%d from dhcp is wrong! range:[0-%d)\n", ipc->port_id, tbl->wire_cnt);
                        abort();
                    }
                    ipcs_table_updating_wire(tbl, ipc->port_id, ipc->client_ip, ipc->hwaddr);
                }
            }
        }
    }
}

static void *ipcs_table_updating(void *data)
{
    struct nc_ipcs_table *tbl = (struct nc_ipcs_table *)data;
    int *arp_fds = NULL;
    int arp_wireless_fd = -1;
    char iface_name[32];
    int cmd = 0;
    int i;

    pthread_detach(pthread_self());

    arp_fds = (int *)calloc(tbl->wire_cnt, sizeof(int));
    if (!arp_fds)
    {
        goto out;
    }

    for (i = 0; i < tbl->wire_cnt; ++i)
    {
        sprintf(iface_name, "%s.%d", tbl->iface_name, NC_WIRE_VID_START + i);
        arp_fds[i] = arp_socket_create(iface_name);
        if (arp_fds[i] < 0)
        {
            goto out;
        }
    }

    if (tbl->wireless_enable)
    {
        sprintf(iface_name, "%s.%d", tbl->iface_name, NC_WIRELESS_VID);
        arp_wireless_fd = arp_socket_create(iface_name);
        if (arp_wireless_fd < 0)
        {
            goto out;
        }
    }

    send(tbl->init_fds[1], &cmd, sizeof(cmd), 0);

    __ipcs_table_updating(tbl, arp_fds, arp_wireless_fd);

out:

    if (arp_wireless_fd >= 0)
    {
        close(arp_wireless_fd);
        arp_wireless_fd = -1;
    }

    if (arp_fds)
    {
        for (i = 0; i < tbl->wire_cnt; ++i)
        {
            if (arp_fds[i] < 0)
            {
                break;
            }
            close(arp_fds[i]);
            arp_fds[i] = -1;
        }
        free(arp_fds);
        arp_fds = NULL;
    }

    pthread_exit((void *)0);
}

int __nc_nvr_get_ipc(int fd, struct nc_new_info *ipc)
{
    int ret = -1;

    while (1)
    {
        ret = recv(fd, ipc, sizeof(*ipc), 0);
        if (ret < 0)
        {
            if (errno == EAGAIN)
            {
                continue;
            }
            return -1;
        }
        break;
    }

    return 0;
}

static int __ipcs_table_list_ipcs(
    struct nc_ipcs_table *tbl,
    struct nc_info *infos,
    int info_size
)
{
    int cnt = 0;
    int i;

    for (i = 0; i < tbl->wire_cnt; ++i)
    {
        if (tbl->wire_ipcs[i].alive_sec <= 0)
        {
            continue;
        }

        memcpy(infos[cnt].hwaddr, tbl->wire_ipcs[i].mac, ETH_ALEN);
        infos[cnt].port_id = i;
        infos[cnt].client_ip = tbl->wire_ipcs[i].ip;
        infos[cnt].is_lost = 0;

        cnt++;
        if (cnt == info_size)
        {
            return cnt;
        }
    }

    if (tbl->wireless_enable == 0)
    {
        return cnt;
    }

    for (i = 0; i < NC_WIRELESS_SZ; i++)
    {
        if( tbl->wireless_ipcs[i].alive_sec <= 0 )
        {
            continue;
        }

        memcpy(infos[cnt].hwaddr, tbl->wireless_ipcs[i].mac, ETH_ALEN);
        infos[cnt].port_id = -1;
        infos[cnt].client_ip = tbl->wireless_ipcs[i].ip;
        infos[cnt].is_lost = 0;

        cnt++;
        if (cnt == info_size)
        {
            return cnt;
        }
    }

    return cnt;
}


int ipcs_table_list_ipcs(struct nc_info *infos, int info_size)
{
    int ret = -1;

    if (info_size <= 0)
    {
        return -1;
    }

    pthread_mutex_lock( &ipcs_tbl.tbl_lock );
    ret = __ipcs_table_list_ipcs(&ipcs_tbl, infos, info_size);
    pthread_mutex_unlock( &ipcs_tbl.tbl_lock );

    int i = 0;
    struct in_addr addr;


    for(i = 0; i < ret; i++)
    {
        st_dbg("-------------------------------\n");
        st_dbg("%02x:%02x:%02x:%02x:%02x:%02x\n",
               infos[i].hwaddr[0],infos[i].hwaddr[1],
               infos[i].hwaddr[2],infos[i].hwaddr[3],
               infos[i].hwaddr[4],infos[i].hwaddr[5]);
        memset(&addr,0,sizeof(addr));
        addr.s_addr = infos[i].client_ip;
        st_dbg("%s\n",inet_ntoa(addr));
        st_dbg("%d\n",infos[i].is_lost);
        st_dbg("-------------------------------\n");
    }
    return ret;
}

static int onvif_socket_create(const char *iface_name)
{
    int fd = -1, n = 0;
    uint8_t hwaddr[ETH_ALEN] = {0};
    struct in_addr sin_addr = {0};
    struct ifreq ifr;
    char sip[INET_ADDRSTRLEN] = {0};
    const char *sip_str = NULL;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ressave = NULL;
    int val = 0;
    int ret = -1;

    ret = get_iface_addr(iface_name, hwaddr, ETH_ALEN, &sin_addr.s_addr);
    if (ret < 0)
    {
        st_err("get_iface_addr failed!\n");
        return -1;
    }

    sip_str = inet_ntop(AF_INET, &sin_addr, sip, INET_ADDRSTRLEN);
    if (!sip_str)
    {
        st_err("inet_ntop error:%d!\n", errno);
        perror("inet_ntop");
        return -1;
    }

    bzero(&hints, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    n = getaddrinfo(sip, NULL, &hints, &res);
    if (n != 0)
    {
        st_err("error for %s - %s: %s\n",
               iface_name,
               sip,
               gai_strerror(n));
        return -1;
    }
    ressave = res;

    do
    {
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0)
        {
            continue;
        }

        val = 1;
        ret = setsockopt(
                  fd,
                  SOL_SOCKET,
                  SO_REUSEADDR,
                  &val,
                  sizeof(val)
              );
        if( ret < 0 )
        {
            st_err("ioctl error:%d!\n", errno);
            perror("ioctl");
            goto sock_err;
        }

        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, iface_name);
        ret = setsockopt(
                  fd,
                  SOL_SOCKET,
                  SO_BINDTODEVICE,
                  (char *)&ifr,
                  sizeof(ifr)
              );
        if( ret < 0 )
        {
            st_err("ioctl error:%d!\n", errno);
            perror("ioctl");
            goto sock_err;
        }

        ret = bind(fd, res->ai_addr, res->ai_addrlen);
        if (ret == 0)
        {
            break;
        }

sock_err:
        close(fd);
    }
    while ((res = res->ai_next) != NULL);

    if (res == NULL)
    {
        st_err("error for %s - %s\n", iface_name, sip);
        perror("\n");
        goto error;
    }

    freeaddrinfo(ressave);

    return fd;

error:
    if (ressave)
    {
        freeaddrinfo(ressave);
    }
    return -1;
}

static char onvif_probe_content[] =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
    "<Envelope xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\" xmlns=\"http://www.w3.org/2003/05/soap-envelope\">"
    "<Header>"
    "<wsa:MessageID xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">uuid:4bae0473-5b94-4fa9-95ba-d683a96a12f1</wsa:MessageID>"
    "<wsa:To xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
    "<wsa:Action xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
    "</Header>"
    "<Body>"
    "<Probe xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">"
    "<Types>dn:NetworkVideoTransmitter</Types>"
    "<Scopes />"
    "</Probe>"
    "</Body>"
    "</Envelope>";

static inline int send_onvif_probe(int fd)
{
    struct sockaddr_in daddr;
    int ret = -1;

    memset( &daddr, 0, sizeof(daddr) );
    daddr.sin_family = AF_INET;
    daddr.sin_port = htons(3702);
    daddr.sin_addr.s_addr = inet_addr("239.255.255.250");

    return sendto(
               fd,
               onvif_probe_content,
               sizeof(onvif_probe_content) - 1,
               MSG_DONTWAIT,
               (struct sockaddr*)&daddr,
               sizeof(struct sockaddr_in)
           );
}

static int recv_onvif_probematch(
    struct nc_ipcs_table *tbl,
    int arp_fd,
    int port_idx,
    char *probematch,
    int pm_len,
    struct sockaddr_in *addr
)
{
    char iface_name[32];
    uint8_t hwaddr[ETH_ALEN] = {0};
    uint32_t src_ip = 0;
    uint32_t tgt_ip = addr->sin_addr.s_addr;
    struct sockaddr_ll hw_sa;
    int ret = -1;

    if (port_idx < 0)
    {
        sprintf(iface_name, "%s.%d", tbl->iface_name, NC_WIRELESS_VID);
    }
    else
    {
        sprintf(iface_name, "%s.%d", tbl->iface_name, NC_WIRE_VID_START + port_idx);
    }

    ret = get_iface_addr(iface_name, hwaddr, ETH_ALEN, &src_ip);
    if (ret < 0)
    {
        return -1;
    }

    memset(&hw_sa, 0, sizeof(hw_sa));

    hw_sa.sll_family = AF_PACKET;
    hw_sa.sll_protocol = htons(ETH_P_ARP);
    hw_sa.sll_ifindex = if_nametoindex(iface_name);
    hw_sa.sll_halen = ETH_ALEN;
    memcpy(hw_sa.sll_addr, hwaddr, ETH_ALEN);

    return send_arp_req(arp_fd, hwaddr, src_ip, tgt_ip, &hw_sa, sizeof(hw_sa));
}

static void __ipcs_table_manual_refresh(
    struct nc_ipcs_table *tbl,
    int *onvif_fds,
    int onvif_wireless_fd,
    int arp_fd,
    int wait_ms
)
{
    fd_set readfds;
    int maxfd = -1;
    struct timeval timeo;
#define ONVIF_RCV_BUF_SZ    0x10000
    char buf[ONVIF_RCV_BUF_SZ];
    struct sockaddr_in saddr;
    socklen_t saddr_len;
    int i;
    int ret = -1;

    for (i = 0; i < tbl->wire_cnt; ++i)
    {
        send_onvif_probe(onvif_fds[i]);
    }

    if (tbl->wireless_enable)
    {
        send_onvif_probe(onvif_wireless_fd);
    }

    timeo.tv_sec = 0;
    if (wait_ms > 999)
    {
        timeo.tv_sec = wait_ms / 1000;
        wait_ms -= timeo.tv_sec * 1000;
    }
    timeo.tv_usec = wait_ms * 1000;

    while (1)
    {
        FD_ZERO(&readfds);
        maxfd = 0;

        for (i = 0; i < tbl->wire_cnt; ++i)
        {
            st_fds_set(&readfds, onvif_fds[i], &maxfd);
        }

        if (tbl->wireless_enable)
        {
            st_fds_set(&readfds, onvif_wireless_fd, &maxfd);
        }

        ret = select(maxfd + 1, &readfds, NULL, NULL, &timeo);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            st_err("select error:%d\n", errno);
            perror("select ");
            break;
        }

        if (ret == 0)
        {
            break;
        }

        /*for wire*/
        for (i = 0; i < tbl->wire_cnt; ++i)
        {
            if (FD_ISSET(onvif_fds[i], &readfds))
            {
                saddr_len = sizeof(saddr);
                memset(&saddr, 0, sizeof(saddr));
                ret = recvfrom(
                          onvif_fds[i],
                          buf,
                          ONVIF_RCV_BUF_SZ,
                          0,
                          (struct sockaddr *)&saddr,
                          &saddr_len
                      );
                if (ret < 0)
                {
                    st_err("recvfrom error:%d!\n", errno);
                    perror("recvfrom");
                    continue;
                }

                recv_onvif_probematch(tbl, arp_fd, i, buf, ret, &saddr);
            }
        }

        /*for wireless*/
        if (tbl->wireless_enable)
        {
            if (FD_ISSET(onvif_wireless_fd, &readfds))
            {
                st_dbg("recv wireless:%d\n");
                while (1)
                {
                    saddr_len = sizeof(saddr);
                    memset(&saddr, 0, sizeof(saddr));
                    ret = recvfrom(
                              onvif_wireless_fd,
                              buf,
                              ONVIF_RCV_BUF_SZ,
                              MSG_DONTWAIT,
                              (struct sockaddr *)&saddr,
                              &saddr_len
                          );
                    if (ret < 0)
                    {
                        if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
                        {
                            st_err("recvfrom error:%d!\n", errno);
                            perror("recvfrom");
                        }
                        break;
                    }

                    recv_onvif_probematch(tbl, arp_fd, -1, buf, ret, &saddr);
                }
            }
        }

    }
}

int ipcs_table_manual_refresh(int wait_ms)
{
    struct nc_ipcs_table *tbl = &ipcs_tbl;
    int *onvif_fds = NULL;
    int onvif_wireless_fd = -1;
    int arp_fd = -1;
    char iface_name[32];
    int i;
    int ret = -1;

    if (tbl->init_ok == 0)
    {
        st_err("please waiting for initialize ok!\n");
        return 0;
    }

    onvif_fds = (int *)calloc(tbl->wire_cnt, sizeof(int));
    if (!onvif_fds)
    {
        goto out;
    }

    for (i = 0; i < tbl->wire_cnt; ++i)
    {
        sprintf(iface_name, "%s.%d", tbl->iface_name, NC_WIRE_VID_START + i);
        onvif_fds[i] = onvif_socket_create(iface_name);
        if (onvif_fds[i] < 0)
        {
            goto out;
        }
    }

    if (tbl->wireless_enable)
    {
        sprintf(iface_name, "%s.%d", tbl->iface_name, NC_WIRELESS_VID);
        onvif_wireless_fd = onvif_socket_create(iface_name);
        if (onvif_wireless_fd < 0)
        {
            goto out;
        }
    }

    arp_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (arp_fd < 0)
    {
        st_err("socket error:%d!\n", errno);
        perror("socket");
        goto out;
    }

    __ipcs_table_manual_refresh(tbl, onvif_fds, onvif_wireless_fd, arp_fd, wait_ms);

    ret = 0;
out:
    if (arp_fd >= 0)
    {
        close(arp_fd);
        arp_fd = -1;
    }

    if (onvif_wireless_fd >= 0)
    {
        close(onvif_wireless_fd);
        onvif_wireless_fd = -1;
    }

    if (onvif_fds)
    {
        for (i = 0; i < tbl->wire_cnt; ++i)
        {
            if (onvif_fds[i] < 0)
            {
                break;
            }
            close(onvif_fds[i]);
            onvif_fds[i] = -1;
        }
        free(onvif_fds);
        onvif_fds = NULL;
    }

    return ret;
}

