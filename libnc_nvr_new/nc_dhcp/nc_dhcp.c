#include "nc_dhcp.h"
#include "nc_common.h"
#include "nc_options.h"
//#include "nc_list.h"
#include "nc_libbb.h"

//#define NC_NET_TOOL             "/tmp/busybox"
#define NC_NET_INTERFACE        "eth0"
#define NC_NET_FIXED_INTERFACE  "2015"
#define NC_NET_FIXED_IP         "172.20.13.253"
#define NC_NET_FIXED_NETMASK    "255.255.255.0"
#define NC_NET_FIXED_IP_CMD     NC_NET_FIXED_IP" netmask "NC_NET_FIXED_NETMASK

#define NC_NET_VID_HDR          "32"
#define NC_VLAN_RJ45_MAX        49

struct nc_net_vlan
{
    char vid[16];
    char address[16];
    char netmask[16];
};

enum
{
    NC_VLAN_IDX_START = 0,
    NC_VLAN_IDX_WIRELESS = NC_VLAN_IDX_START,
    NC_VLAN_IDX_RJ45_START,
    NC_VLAN_IDX_RJ45_MAX = NC_VLAN_IDX_RJ45_START + NC_VLAN_RJ45_MAX,
    NC_VLAN_IDX_MAX = NC_VLAN_IDX_RJ45_MAX,
};

/*vlan0~vlan48共49个vlan对应7*7屏幕49个固定屏幕端口*/
/*vlan49对应无线接入，共13个无线IPC*/
static struct nc_net_vlan nc_vlans[] =
{
    {NC_NET_VID_HDR"49", "172.25.123.1",   "255.255.255.240"},

    {NC_NET_VID_HDR"00", "172.25.123.17",  "255.255.255.252"},
    {NC_NET_VID_HDR"01", "172.25.123.21",  "255.255.255.252"},
    {NC_NET_VID_HDR"02", "172.25.123.25",  "255.255.255.252"},
    {NC_NET_VID_HDR"03", "172.25.123.29",  "255.255.255.252"},
    {NC_NET_VID_HDR"04", "172.25.123.33",  "255.255.255.252"},

    {NC_NET_VID_HDR"05", "172.25.123.37",  "255.255.255.252"},
    {NC_NET_VID_HDR"06", "172.25.123.41",  "255.255.255.252"},
    {NC_NET_VID_HDR"07", "172.25.123.45",  "255.255.255.252"},
    {NC_NET_VID_HDR"08", "172.25.123.49",  "255.255.255.252"},
    {NC_NET_VID_HDR"09", "172.25.123.53",  "255.255.255.252"},

    {NC_NET_VID_HDR"10", "172.25.123.57",  "255.255.255.252"},
    {NC_NET_VID_HDR"11", "172.25.123.61",  "255.255.255.252"},
    {NC_NET_VID_HDR"12", "172.25.123.65",  "255.255.255.252"},
    {NC_NET_VID_HDR"13", "172.25.123.69",  "255.255.255.252"},
    {NC_NET_VID_HDR"14", "172.25.123.73",  "255.255.255.252"},

    {NC_NET_VID_HDR"15", "172.25.123.77",  "255.255.255.252"},
    {NC_NET_VID_HDR"16", "172.25.123.81",  "255.255.255.252"},
    {NC_NET_VID_HDR"17", "172.25.123.85",  "255.255.255.252"},
    {NC_NET_VID_HDR"18", "172.25.123.89",  "255.255.255.252"},
    {NC_NET_VID_HDR"19", "172.25.123.93",  "255.255.255.252"},

    {NC_NET_VID_HDR"20", "172.25.123.97",  "255.255.255.252"},
    {NC_NET_VID_HDR"21", "172.25.123.101",  "255.255.255.252"},
    {NC_NET_VID_HDR"22", "172.25.123.105",  "255.255.255.252"},
    {NC_NET_VID_HDR"23", "172.25.123.109",  "255.255.255.252"},
    {NC_NET_VID_HDR"24", "172.25.123.113",  "255.255.255.252"},

    {NC_NET_VID_HDR"25", "172.25.123.117",  "255.255.255.252"},
    {NC_NET_VID_HDR"26", "172.25.123.121",  "255.255.255.252"},
    {NC_NET_VID_HDR"27", "172.25.123.125",  "255.255.255.252"},
    {NC_NET_VID_HDR"28", "172.25.123.129",  "255.255.255.252"},
    {NC_NET_VID_HDR"29", "172.25.123.133",  "255.255.255.252"},

    {NC_NET_VID_HDR"30", "172.25.123.137",  "255.255.255.252"},
    {NC_NET_VID_HDR"31", "172.25.123.141",  "255.255.255.252"},
    {NC_NET_VID_HDR"32", "172.25.123.145",  "255.255.255.252"},
    {NC_NET_VID_HDR"33", "172.25.123.149",  "255.255.255.252"},
    {NC_NET_VID_HDR"34", "172.25.123.153",  "255.255.255.252"},

    {NC_NET_VID_HDR"35", "172.25.123.157",  "255.255.255.252"},
    {NC_NET_VID_HDR"36", "172.25.123.161",  "255.255.255.252"},
    {NC_NET_VID_HDR"37", "172.25.123.165",  "255.255.255.252"},
    {NC_NET_VID_HDR"38", "172.25.123.169",  "255.255.255.252"},
    {NC_NET_VID_HDR"39", "172.25.123.173",  "255.255.255.252"},

    {NC_NET_VID_HDR"40", "172.25.123.177",  "255.255.255.252"},
    {NC_NET_VID_HDR"41", "172.25.123.181",  "255.255.255.252"},
    {NC_NET_VID_HDR"42", "172.25.123.185",  "255.255.255.252"},
    {NC_NET_VID_HDR"43", "172.25.123.189",  "255.255.255.252"},
    {NC_NET_VID_HDR"44", "172.25.123.193",  "255.255.255.252"},

    {NC_NET_VID_HDR"45", "172.25.123.197",  "255.255.255.252"},
    {NC_NET_VID_HDR"46", "172.25.123.201",  "255.255.255.252"},
    {NC_NET_VID_HDR"47", "172.25.123.205",  "255.255.255.252"},
    {NC_NET_VID_HDR"48", "172.25.123.209",  "255.255.255.252"},
};

#define NC_VLAN_CNT (sizeof(nc_vlans) / sizeof(nc_vlans[0]))

static __u32 nc_vlan_wireless_start_ip = 0;
static __u32 nc_vlan_wireless_end_ip = 0;

static int nc_vlan_cnt = 0;

static int nc_bwireless = 0; //是否启动无线

static int NC_NET_MAX_LAN_NIP = 0;

static const __u8 MAC_BCAST_ADDR[6] =
{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

// dhcp 是否可用标记
enum nc_net_devif_rx_flag_e
{
    NC_NET_DEVIF_RX_FLAG_START = NC_VLAN_CNT,
    NC_NET_DEVIF_RX_FLAG_EXIT = NC_NET_DEVIF_RX_FLAG_START,
    NC_NET_DEVIF_RX_FLAG_MAX,
};
static unsigned long nc_dhcpd_rx_flags[NC_NET_DEVIF_RX_FLAG_MAX] = {0,};

// 监听端口数据结构
struct nc_recv_st
{
    pthread_t tid;
    int fd;
    int vlan_idx;
};
static struct nc_recv_st *recv_st = 0;

static struct __nc_info *static_nips = 0;
static pthread_rwlock_t rwlock_for_static_nips;

static struct nc_dhcp_st *nc_dhcp_eth0_45 = 0;

static struct nc_dhcp_st *nc_dhcp_eth0 = 0;

//discover_one_ipc g_fun_discover = 0;

int g_fd = 0;

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

int setsockopt_reuseaddr(int fd)
{
    const int ion = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &ion, sizeof(ion));
}

int setsockopt_broadcast(int fd)
{
    const int ion = 1;
    return setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &ion, sizeof(ion));
}

int setsockopt_bindtodevice(int fd, const char* inf, int isize)
{
    return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, inf, isize);
}

#define __NC_NET____APP_START_________________________________________

static int do_user_app(const char* cmd)
{
    st_dbg("%s",cmd);
    return system(cmd)	;
}

static inline void __nc_net_app_cleanup(void)
{
    int i;
    int ibIndex = 0;

    if (nc_bwireless)
        ibIndex = NC_VLAN_IDX_WIRELESS;
    else
        ibIndex = NC_VLAN_IDX_RJ45_START;

    for (i = ibIndex; i < nc_vlan_cnt; ++i)
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd) - 1, "vconfig rem "NC_NET_INTERFACE".%s", nc_vlans[i].vid);
        do_user_app(cmd);
    }
}

static int __nc_net_app_apply(void)
{
    int ret = -1;
    int i;
    int ibIndex = 0;

    if (!(nc_dhcp_eth0->flags & IFF_UP))
    {
        ret = do_user_app("ifconfig "NC_NET_INTERFACE" up");
        if (ret != 0)
        {
            st_dbg("\n");
            goto out;
        }
    }

    ret = do_user_app("ifconfig "NC_NET_INTERFACE":"NC_NET_FIXED_INTERFACE" "NC_NET_FIXED_IP_CMD);
    if (ret != 0)
    {
        st_dbg("\n");
        goto out;
    }

    if (nc_bwireless)
        ibIndex = NC_VLAN_IDX_WIRELESS;
    else
        ibIndex = NC_VLAN_IDX_RJ45_START;

    for (i = ibIndex; i < nc_vlan_cnt; ++i)
    {
        char cmd[512];
        // 检查vlan 是否已经创建好
        snprintf(cmd, sizeof(cmd) - 1, "ifconfig "NC_NET_INTERFACE".%s", nc_vlans[i].vid);
        ret = do_user_app(cmd);
        if (ret == 0)
        {
            continue;
        }

        snprintf(cmd, sizeof(cmd) - 1, "vconfig add "NC_NET_INTERFACE" %s", nc_vlans[i].vid);
        ret = do_user_app(cmd);
        if (ret != 0)
        {
            st_dbg("\n");
            goto out;
        }

        snprintf(cmd, sizeof(cmd) - 1, "vconfig set_flag "NC_NET_INTERFACE".%s 1 1", nc_vlans[i].vid);
        ret = do_user_app(cmd);
        if (ret != 0)
        {
            st_dbg("\n");
            goto out;
        }
        nc_dhcp_eth0_45[i].mtu = nc_dhcp_eth0->mtu - 0x4;
        snprintf(cmd
                 , sizeof(cmd) - 1
                 , "ifconfig "
                 NC_NET_INTERFACE".%s %s netmask %s mtu %d up"
                 , nc_vlans[i].vid
                 , nc_vlans[i].address
                 , nc_vlans[i].netmask
                 , nc_dhcp_eth0_45[i].mtu/*vlan tag*/
                );
        ret = do_user_app(cmd);
        if (ret != 0)
        {
            st_dbg("\n");
            goto out;
        }
    }

    ret = 0;
out:
    st_dbg("\n");
    return ret;
}

#define __NC_NET____APP_END___________________________________________

#define __NC_NET____START____STATIC_LEASES_________________________________________START

#if 1
static inline struct __nc_info *__find_static_nip_by_mac(__u8 *mac)
{
    int i;

    for (i = 0; i < NC_NET_MAX_STATIC_NIP; ++i)
    {
        struct __nc_info *info = &static_nips[i];
        if (!memcmp(info->hwaddr, mac, 6))
        {
            return info;
        }
    }

    return NULL;
}

static inline struct __nc_info *__find_static_nip_by_ip(__u32 ip)
{
    int i;

    for (i = 0; i < NC_NET_MAX_STATIC_NIP; ++i)
    {
        struct __nc_info *info = &static_nips[i];
        if (info->client_ip == ip)
        {
            return info;
        }
    }

    return NULL;
}

static inline int is_reserved_nip(__u32 ip)
{
    int ret = 0;

    pthread_rwlock_rdlock(&rwlock_for_static_nips);
    if (__find_static_nip_by_ip(ip))
    {
        ret = 1;
    }
    pthread_rwlock_unlock(&rwlock_for_static_nips);

    return ret;
}

static int __add_static_nip(struct __nc_info *info)
{
    struct __nc_info *p = NULL;
    __u8 tmp_mac[6] = {0};

    p = __find_static_nip_by_ip(info->client_ip);
    if (p)
    {
        if (!memcmp(info->hwaddr, p->hwaddr, ETH_ALEN))
        {
            return 0;
        }
        else
        {
            /*ip conflict*/
            return -1;
        }
    }

    p = __find_static_nip_by_mac(info->hwaddr);
    if (p)
    {
        /*mac exist!*/
        return -1;
    }

    p = __find_static_nip_by_mac(tmp_mac);
    if (!p)
    {
        st_dbg("add->%02X:%02X:%02X:%02X:%02X:%02X failed:full!!\n",
               info->hwaddr[0],
               info->hwaddr[1],
               info->hwaddr[2],
               info->hwaddr[3],
               info->hwaddr[4],
               info->hwaddr[5]
              );
        return -1;
    }

    st_dbg("add->%02X:%02X:%02X:%02X:%02X:%02X\n",
           info->hwaddr[0],
           info->hwaddr[1],
           info->hwaddr[2],
           info->hwaddr[3],
           info->hwaddr[4],
           info->hwaddr[5]
          );
    memcpy(p, info, sizeof(*p));

    return 0;
}

static inline int add_static_nip(struct __nc_info *info)
{
    int ret = -1;

    pthread_rwlock_wrlock(&rwlock_for_static_nips);
    ret = __add_static_nip(info);
    pthread_rwlock_unlock(&rwlock_for_static_nips);

    return ret;
}

static int __mod_static_nip(struct __nc_info *info)
{
    struct __nc_info *p = NULL;

    p = __find_static_nip_by_ip(info->client_ip);
    if (p)
    {
        if (!memcmp(info->hwaddr, p->hwaddr, ETH_ALEN))
        {
            return 0;
        }
        else
        {
            /*ip conflict*/
            return -1;
        }
    }

    p = __find_static_nip_by_mac(info->hwaddr);
    if (!p)
    {
        /*mac isn't exist!*/
        return -1;
    }

#if NC_DEBUG == 1
    {
        __u8 *ip = (__u8 *)&p->client_ip;
        st_dbg("mod %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u to\n",
               info->hwaddr[0],
               info->hwaddr[1],
               info->hwaddr[2],
               info->hwaddr[3],
               info->hwaddr[4],
               info->hwaddr[5],
               ip[0],
               ip[1],
               ip[2],
               ip[3]
              );
    }
#endif

    memcpy(p, info, sizeof(*p));

#if NC_DEBUG == 1
    {
        __u8 *ip = (__u8 *)&info->client_ip;
        st_dbg("%u.%u.%u.%u\n",
               ip[0],
               ip[1],
               ip[2],
               ip[3]
              );
    }
#endif

    return 0;
}

static inline int mod_static_nip(struct __nc_info *info)
{
    int ret = -1;

    pthread_rwlock_wrlock(&rwlock_for_static_nips);
    ret = __mod_static_nip(info);
    pthread_rwlock_unlock(&rwlock_for_static_nips);

    return ret;
}

static int __del_static_nip(struct __nc_info *info)
{
    struct __nc_info *p = NULL;

    p = __find_static_nip_by_mac(info->hwaddr);
    if (!p)
    {
        /*mac isn't exist!*/
        return -1;
    }

#if NC_DEBUG == 1
    {
        __u8 *ip = (__u8 *)&p->client_ip;
        st_dbg("clr %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u\n",
               info->hwaddr[0],
               info->hwaddr[1],
               info->hwaddr[2],
               info->hwaddr[3],
               info->hwaddr[4],
               info->hwaddr[5],
               ip[0],
               ip[1],
               ip[2],
               ip[3]
              );
    }
#endif

    memset(p, 0, sizeof(*p));

    return 0;
}

static inline int del_static_nip(struct __nc_info *info)
{
    int ret = -1;

    pthread_rwlock_wrlock(&rwlock_for_static_nips);
    ret = __del_static_nip(info);
    pthread_rwlock_unlock(&rwlock_for_static_nips);

    return ret;
}

static inline int clr_static_nip()
{
    pthread_rwlock_wrlock(&rwlock_for_static_nips);
    memset((char*)static_nips,0,sizeof(struct __nc_info)*NC_NET_MAX_STATIC_NIP);
    pthread_rwlock_unlock(&rwlock_for_static_nips);
    return 0;
}

#endif



#define __NC_NET____END____STATIC_LEASES_________________________________________END


#define __NC_NET____START____LEASE_________________________________________START

static struct dyn_lease *g_leases = NULL;

/* Find the oldest expired lease, NULL if there are no expired leases */
static struct dyn_lease *nc_dhcpd_oldest_expired_lease(void)
{
    struct dyn_lease *oldest_lease = NULL;
    leasetime_t oldest_time = time(NULL);
    unsigned i;

    /* Unexpired leases have g_leases[i].expires >= current time
     * and therefore can't ever match */
    for (i = 0; i < MAX_LEASE; i++)
    {
        if (g_leases[i].expires < oldest_time)
        {
            oldest_time = g_leases[i].expires;
            oldest_lease = &g_leases[i];
        }
    }

    return oldest_lease;
}

/* Clear every lease out that chaddr OR yiaddr matches and is nonzero */
static void nc_dhcpd_clear_lease(const __u8 *chaddr, __u32 yiaddr)
{
    unsigned i, j;

    for (j = 0; j < 16 && !chaddr[j]; j++)
    {
        continue;
    }

    for (i = 0; i < MAX_LEASE; i++)
    {
        if ((j != 16 && memcmp(g_leases[i].lease_mac, chaddr, 6) == 0)
                || (yiaddr && g_leases[i].lease_nip == yiaddr)
           )
        {
            memset(&g_leases[i], 0, sizeof(g_leases[i]));
        }
    }
}

/* Add a lease into the table, clearing out any old ones */
static struct dyn_lease* nc_dhcpd_add_lease(
    const __u8 *chaddr, __u32 yiaddr,
    leasetime_t leasetime,
    const char *hostname, int hostname_len)
{
    struct dyn_lease *oldest;

    /* clean out any old ones */
    nc_dhcpd_clear_lease(chaddr, yiaddr);

    oldest = nc_dhcpd_oldest_expired_lease();

    if (oldest)
    {
        oldest->hostname[0] = '\0';
        if (hostname)
        {
            char *p;
            if (hostname_len > sizeof(oldest->hostname))
                hostname_len = sizeof(oldest->hostname);
            p = strncpy(oldest->hostname, hostname, hostname_len);
            /* sanitization (s/non-ASCII/^/g) */
            while (*p)
            {
                if (*p < ' ' || *p > 126)
                    *p = '^';
                p++;
            }
        }
        memcpy(oldest->lease_mac, chaddr, 6);
        oldest->lease_nip = yiaddr;
        oldest->expires = time(NULL) + leasetime;
    }

    return oldest;
}


/* Find the first lease that matches MAC, NULL if no match */
struct dyn_lease* find_lease_by_mac(const __u8 *mac)
{
    unsigned i;

    for (i = 0; i < MAX_LEASE; i++)
    {
        if (memcmp(g_leases[i].lease_mac, mac, 6) == 0)
        {
            return &g_leases[i];
        }
    }

    return NULL;
}


/* Find the first lease that matches IP, NULL is no match */
static struct dyn_lease* nc_dhcpd_find_lease_by_nip(__u32 nip)
{
    unsigned i;

    for (i = 0; i < MAX_LEASE; i++)
    {
        if (g_leases[i].lease_nip == nip)
        {
            return &g_leases[i];
        }
    }

    return NULL;
}

static int is_nip_reserved(__u32 ip)
{
    int ret = 0;

    if (nc_dhcpd_find_lease_by_nip(ip))
    {
        ret = 1;
    }

    return ret;
}


/* True if a lease has expired */
static int nc_dhcpd_is_expired_lease(struct dyn_lease *lease)
{
    return (lease->expires < (leasetime_t) (time(NULL)));
}

/* Returns 1 if no reply received */
int nc_net_arpping(__u32 test_nip,
                   const __u8 *safe_mac,
                   __u32 from_ip,
                   __u8 *from_mac,
                   const char *interface)
{
    int timeout_ms;
    struct pollfd pfd[1];
#define s (pfd[0].fd)           /* socket */
    int rv = 1;             /* "no reply received" yet */
    struct sockaddr addr;   /* for interface name */
    struct arpMsg arp;

    s = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP));
    if (s == -1)
    {
        st_dbg("nc_net_arpping create socket error");
        return -1;
    }

    if (setsockopt_broadcast(s) == -1)
    {
        st_dbg("can't enable bcast on raw socket");
        goto ret;
    }

    /* send arp request */
    memset(&arp, 0, sizeof(arp));
    memset(arp.h_dest, 0xff, 6);                    /* MAC DA */
    memcpy(arp.h_source, from_mac, 6);              /* MAC SA */
    arp.h_proto = htons(ETH_P_ARP);                 /* protocol type (Ethernet) */
    arp.htype = htons(ARPHRD_ETHER);                /* hardware type */
    arp.ptype = htons(ETH_P_IP);                    /* protocol type (ARP message) */
    arp.hlen = 6;                                   /* hardware address length */
    arp.plen = 4;                                   /* protocol address length */
    arp.operation = htons(ARPOP_REQUEST);           /* ARP op code */
    memcpy(arp.sHaddr, from_mac, 6);                /* source hardware address */
    memcpy(arp.sInaddr, &from_ip, sizeof(from_ip)); /* source IP address */
    /* tHaddr is zero-filled */                     /* target hardware address */
    memcpy(arp.tInaddr, &test_nip, sizeof(test_nip));/* target IP address */

    memset(&addr, 0, sizeof(addr));
    safe_strncpy(addr.sa_data, interface, sizeof(addr.sa_data));
    if (sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr)) < 0)
    {
        // TODO: error message? caller didn't expect us to fail,
        // just returning 1 "no reply received" misleads it.
        goto ret;
    }

    /* wait for arp reply, and check it */
    timeout_ms = 2000;
    do
    {
        int r;
        unsigned prevTime = monotonic_ms();

        pfd[0].events = POLLIN;
        r = safe_poll(pfd, 1, timeout_ms);
        if (r < 0)
            break;
        if (r)
        {
            r = safe_read(s, &arp, sizeof(arp));
            if (r < 0)
                break;

            //log3("sHaddr %02x:%02x:%02x:%02x:%02x:%02x",
            //	arp.sHaddr[0], arp.sHaddr[1], arp.sHaddr[2],
            //	arp.sHaddr[3], arp.sHaddr[4], arp.sHaddr[5]);

            if ((r >= ARP_MSG_SIZE)
                    && (arp.operation == htons(ARPOP_REPLY))
                    /* don't check it: Linux doesn't return proper tHaddr (fixed in 2.6.24?) */
                    /* && memcmp(arp.tHaddr, from_mac, 6) == 0 */
                    && (*((__u32 *)arp.sInaddr) == test_nip)
               )
            {
                /* if ARP source MAC matches safe_mac
                 * (which is client's MAC), then it's not a conflict
                 * (client simply already has this IP and replies to ARPs!)
                 */
                if (!safe_mac || memcmp(safe_mac, arp.sHaddr, 6) != 0)
                    rv = 0;
                //else log2("sHaddr == safe_mac");
                break;
            }
        }
        timeout_ms -= (unsigned)monotonic_ms() - prevTime;
    }
    while (timeout_ms > 0);

ret:
    close(s);
    st_dbg("%srp reply received for this address", rv ? "No a" : "A");
    return rv;
}


/* Check if the IP is taken; if it is, add it to the lease table */
static int nobody_responds_to_arp(
    int vlan_idx,
    __u32 nip,
    const __u8 *safe_mac
)
{
    /* 16 zero bytes */
    static const __u8 blank_chaddr[16] = { 0 };
    /* = { 0 } helps gcc to put it in rodata, not bss */
    char if_name[IFNAMSIZ] = {0};
    int r;

    snprintf(if_name, IFNAMSIZ - 1, NC_NET_INTERFACE".%s", nc_vlans[vlan_idx].vid);

    r = nc_net_arpping(
            nip,
            safe_mac,
            inet_addr(nc_vlans[vlan_idx].address),
            nc_dhcp_eth0_45[vlan_idx].mac,
            if_name
        );
    if (r)
        return r;

    st_dbg("%08X belongs to someone, reserving it for %u seconds",
           nip, (unsigned)CONFLICT_TIME);
    nc_dhcpd_add_lease(blank_chaddr, nip, CONFLICT_TIME, NULL, 0);
    return 0;
}


/* Find a new usable (we think) address */
static __u32 nc_dhcpd_find_free_or_expired_nip(
    int vlan_idx,
    const __u8 *safe_mac,
    __u32 start_ip,
    __u32 end_ip
)
{
    __u32 addr;
    struct dyn_lease *oldest_lease = NULL;

    addr = start_ip; /* addr is in host order here */
    for (; addr <= end_ip; addr++)
    {
        __u32 nip;
        struct dyn_lease *lease;

        /* ie, 172.25.132.2 */
        if ((addr & 0xff) == 0)
            continue;
        /* ie, 172.25.132.14 */
        if ((addr & 0xff) == 0xff)
            continue;
        nip = htonl(addr);

        if (is_reserved_nip(nip))
        {
            continue;
        }

        lease = nc_dhcpd_find_lease_by_nip(nip);

        if (!lease)
        {
            if (nobody_responds_to_arp(vlan_idx, nip, safe_mac))
            {
                return nip;
            }
        }
        else
        {
            if (!oldest_lease || lease->expires < oldest_lease->expires)
            {
                oldest_lease = lease;
            }
        }

    }

    if (oldest_lease && nc_dhcpd_is_expired_lease(oldest_lease)
            && nobody_responds_to_arp(vlan_idx, oldest_lease->lease_nip, safe_mac)
       )
    {
        return oldest_lease->lease_nip;
    }

    return 0;
}

static __u32 nc_dhcpd_select_lease_time(struct dhcp_packet *packet)
{
    __u32 lease_time_sec = MAX_LEASE_TIME;
    __u8 *lease_time_opt = get_option(packet, DHCP_LEASE_TIME);
    if (lease_time_opt)
    {
        move_from_unaligned32(lease_time_sec, lease_time_opt);
        lease_time_sec = ntohl(lease_time_sec);
        if (lease_time_sec > MAX_LEASE_TIME)
            lease_time_sec = MAX_LEASE_TIME;
        if (lease_time_sec < MIN_LEASE_TIME)
            lease_time_sec = MIN_LEASE_TIME;
    }
    return lease_time_sec;
}

static inline
void nc_dhcpd_add_subnet(
    struct dhcp_packet *packet,
    const char *netmask
)
{
    __u32 subnet = inet_addr(netmask);
    __u8 netmask_data[16] = {0};

    /*add options*/
    /* option bytes: [code][len][data1][data2]..[dataLEN] */

    /*netmask*/
    netmask_data[OPT_CODE] = DHCP_SUBNET;
    netmask_data[OPT_LEN] = sizeof(subnet);
    memcpy(&netmask_data[OPT_DATA], &subnet, sizeof(subnet));

    add_option_string(packet->options, netmask_data);
}

static inline
void nc_dhcpd_add_gateway(
    struct dhcp_packet *packet,
    const char *gateway
)
{
    __u32 gw = inet_addr(gateway);
    __u8 gw_data[16] = {0};

    /*add options*/
    /* option bytes: [code][len][data1][data2]..[dataLEN] */

    /*gateway*/
    gw_data[OPT_CODE] = DHCP_ROUTER;
    gw_data[OPT_LEN] = sizeof(gw);
    memcpy(&gw_data[OPT_DATA], &gw, sizeof(gw));

    add_option_string(packet->options, gw_data);
}


#define __NC_NET____END____LEASE_________________________________________END



#define __NC_NET____START____Packet_________________________________________START

void udhcp_init_header(struct dhcp_packet *packet, char type)
{
    memset(packet, 0, sizeof(struct dhcp_packet));
    packet->op = BOOTREQUEST; /* if client to a server */
    switch (type)
    {
    case DHCPOFFER:
    case DHCPACK:
    case DHCPNAK:
        packet->op = BOOTREPLY; /* if server to client */
    }
    packet->htype = ETH_10MB;
    packet->hlen = ETH_10MB_LEN;
    packet->cookie = htonl(DHCP_MAGIC);
    packet->options[0] = DHCP_END;
    add_simple_option(packet->options, DHCP_MESSAGE_TYPE, type);
}


#if defined CONFIG_UDHCP_DEBUG && CONFIG_UDHCP_DEBUG >= 2
void udhcp_dump_packet(struct dhcp_packet *packet)
{
    char buf[sizeof(packet->chaddr)*2 + 1];

    if (dhcp_verbose < 2)
        return;

    *bin2hex(buf, (void *) packet->chaddr, sizeof(packet->chaddr)) = '\0';

}
#endif


/* Read a packet from socket fd, return -1 on read error, -2 on packet error */
int udhcp_recv_kernel_packet(struct dhcp_packet *packet, int fd)
{
    int bytes;
    unsigned char *vendor;

    memset(packet, 0, sizeof(*packet));
    bytes = safe_read(fd, packet, sizeof(*packet));
    if (bytes < 0)
    {
        st_dbg("Packet read error, ignoring");
        return bytes; /* returns -1 */
    }

    if (packet->cookie != htonl(DHCP_MAGIC))
    {
        st_dbg("Packet with bad magic, ignoring");
        return -2;
    }

    st_dbg("Received a packet");
    //udhcp_dump_packet(packet);

    if (packet->op == BOOTREQUEST)
    {
        vendor = get_option(packet, DHCP_VENDOR);
        if (vendor)
        {

            if (vendor[OPT_LEN - 2] == (uint8_t)(sizeof("MSFT 98")-1)
                    && memcmp(vendor, "MSFT 98", sizeof("MSFT 98")-1) == 0
               )
            {
                st_dbg("Broken client (%s), forcing broadcast replies", "MSFT 98");
                packet->flags |= htons(BROADCAST_FLAG);
            }

        }
    }

    return bytes;
}

static void nc_dhcpd_init_packet(int vlan_idx,
                                 struct dhcp_packet *packet,
                                 struct dhcp_packet *oldpacket,
                                 char type)
{
    __u32 server_nip = inet_addr(nc_vlans[vlan_idx].address);
    udhcp_init_header(packet, type);
    packet->xid = oldpacket->xid;
    memcpy(packet->chaddr, oldpacket->chaddr, sizeof(oldpacket->chaddr));
    packet->flags = oldpacket->flags;
    packet->gateway_nip = oldpacket->gateway_nip;
    packet->ciaddr = oldpacket->ciaddr;
    add_simple_option(
        packet->options,
        DHCP_SERVER_ID,
        server_nip
    );
}

/* Let the kernel do all the work for packet generation */
static int nc_dhcpd_send_kernel_packet(
    struct dhcp_packet *dhcp_pkt,
    __u32 source_ip,
    int source_port,
    __u32 dest_ip,
    int dest_port
)
{
    struct sockaddr_in client;
    int fd;
    int ret = -1;

    enum
    {
        DHCP_SIZE = sizeof(struct dhcp_packet) - CONFIG_UDHCPC_SLACK_FOR_BUGGY_SERVERS,
    };

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
    {
        st_dbg("sock_create_kern err:%d, 0x%08X\n", fd, fd);
        return -1;
    }

    setsockopt_reuseaddr(fd);

    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    client.sin_port = htons(source_port);
    client.sin_addr.s_addr = source_ip;

    ret = bind(fd, (struct sockaddr *)&client, sizeof(client));
    if (ret < 0)
    {
        st_dbg("kernel_bind err:%d, 0x%08X\n", ret, ret);
        goto out;
    }

    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    client.sin_port = htons(dest_port);
    client.sin_addr.s_addr = dest_ip;
    ret = connect(fd, (struct sockaddr *)&client, sizeof(client));
    if (ret < 0)
    {
        st_dbg("kernel_connect err:%d, 0x%08X\n", ret, ret);
        goto out;
    }

    /* Currently we send full-sized DHCP packets (see above) */
    //udhcp_dump_packet(dhcp_pkt);
    ret = safe_write(fd, dhcp_pkt, DHCP_SIZE);

out:
    close(fd);
    if (ret < 0)
    {
        st_dbg("error!");
    }
    return ret;
}


/* send a packet to gateway_nip using the kernel ip stack */
static int nc_dhcpd_send_pkt_to_replay(
    int vlan_idx,
    struct dhcp_packet *dhcp_pkt
)
{
    __u32 server_nip = inet_addr(nc_vlans[vlan_idx].address);
    st_dbg("Forwarding packet to relay");

    return nc_dhcpd_send_kernel_packet(dhcp_pkt,
                                       server_nip, SERVER_PORT,
                                       dhcp_pkt->gateway_nip, SERVER_PORT);
}

__u16 udhcp_checksum(void *addr, int count)
{
    /* Compute Internet Checksum for "count" bytes
     * beginning at location "addr".
     */
    __u32 sum = 0;
    __u16 *source = (__u16 *) addr;

    while (count > 1)
    {
        /*  This is the inner loop */
        sum += *source++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if (count > 0)
    {
        /* Make sure that the left-over byte is added correctly both
         * with little and big endian hosts */
        __u16 tmp = 0;
        *(__u8*)&tmp = *(uint8_t*)source;
        sum += tmp;
    }
    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}


/* Construct a ip/udp header for a packet, send packet */
static int nc_dhcpd_send_raw_packet(
    struct dhcp_packet *dhcp_pkt,
    __u32 source_ip,
    int source_port,
    __u32 dest_ip,
    int dest_port,
    const __u8 *dest_arp,
    const char *vid,
    int ifindex
)
{
    struct sockaddr_ll dest;
    struct ip_udp_dhcp_packet packet;
    int fd;
    int result = -1;

    enum
    {
        IP_UPD_DHCP_SIZE = sizeof(struct ip_udp_dhcp_packet) - CONFIG_UDHCPC_SLACK_FOR_BUGGY_SERVERS,
        UPD_DHCP_SIZE    = IP_UPD_DHCP_SIZE - offsetof(struct ip_udp_dhcp_packet, udp),
    };

    fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (fd < 0)
    {
        goto ret_msg;
    }

    memset(&dest, 0, sizeof(dest));
    memset(&packet, 0, sizeof(packet));
    packet.data = *dhcp_pkt; /* struct copy */

    dest.sll_family = AF_PACKET;
    dest.sll_protocol = htons(ETH_P_IP);
    dest.sll_ifindex = ifindex;
    dest.sll_halen = 6;
    memcpy(dest.sll_addr, dest_arp, 6);
    if (bind(fd, (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {

        goto ret_close;
    }

    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.saddr = source_ip;
    packet.ip.daddr = dest_ip;
    packet.udp.source = htons(source_port);
    packet.udp.dest = htons(dest_port);
    /* size, excluding IP header: */
    packet.udp.len = htons(UPD_DHCP_SIZE);
    /* for UDP checksumming, ip.len is set to UDP packet len */
    packet.ip.tot_len = packet.udp.len;
    packet.udp.check = udhcp_checksum(&packet, IP_UPD_DHCP_SIZE);
    /* but for sending, it is set to IP packet len */
    packet.ip.tot_len = htons(IP_UPD_DHCP_SIZE);
    packet.ip.ihl = sizeof(packet.ip) >> 2;
    packet.ip.version = IPVERSION;
    packet.ip.ttl = IPDEFTTL;
    packet.ip.check = udhcp_checksum(&packet.ip, sizeof(packet.ip));

    /* Currently we send full-sized DHCP packets (zero padded).
     * If you need to change this: last byte of the packet is
     * packet.data.options[end_option(packet.data.options)]
     */
    //udhcp_dump_packet(dhcp_pkt);
    result = sendto(fd, &packet, IP_UPD_DHCP_SIZE, 0,
                    (struct sockaddr *) &dest, sizeof(dest));

ret_close:
    close(fd);
    if (result < 0)
    {
ret_msg:
        st_dbg("nc_dhcpd_send_raw_packet error");
    }
    return result;
}



/* send a packet to a specific mac address and ip address by creating our own ip packet */
static int nc_dhcpd_send_pkt_to_client(
    int vlan_idx,
    struct dhcp_packet *dhcp_pkt,
    int force_broadcast
)
{
    const __u8 *chaddr;
    __u32 ciaddr;
    __u32 server_nip = inet_addr(nc_vlans[vlan_idx].address);

    st_dbg("flag = %d,ciaddr = %d\n",dhcp_pkt->flags,dhcp_pkt->ciaddr);

    if (force_broadcast
            || (dhcp_pkt->flags & htons(BROADCAST_FLAG))
            || !dhcp_pkt->ciaddr
       )
    {
        st_dbg("Broadcasting packet to client\n");
        ciaddr = INADDR_BROADCAST;
        chaddr = MAC_BCAST_ADDR;
    }
    else
    {
        st_dbg("Unicasting packet to client ciaddr\n");
        ciaddr = dhcp_pkt->ciaddr;
        chaddr = dhcp_pkt->chaddr;
    }

    return nc_dhcpd_send_raw_packet(
               dhcp_pkt,
               /*src*/ server_nip, SERVER_PORT,
               /*dst*/ ciaddr, CLIENT_PORT, chaddr,
               nc_vlans[vlan_idx].vid,
               nc_dhcp_eth0_45[vlan_idx].ifindex
           );
}

/* add in the bootp options */
static void nc_dhcpd_add_bootp_options(struct dhcp_packet *packet)
{
    __u32 siaddr_nip = inet_addr(NC_DHCPD_SIADDR);
    packet->siaddr_nip = siaddr_nip;
    if (NC_DHCPD_SINAME)
    {
        strncpy((char*)packet->sname, NC_DHCPD_SINAME, sizeof(packet->sname) - 1);
    }
    if (NC_DHCPD_BOOTFILE)
    {
        strncpy((char*)packet->file, NC_DHCPD_BOOTFILE, sizeof(packet->file) - 1);
    }
}

/* send a dhcp packet, if force broadcast is set, the packet will be broadcast to the client */
static int nc_dhcpd_send_packet(
    int vlan_idx,
    struct dhcp_packet *dhcp_pkt,
    int force_broadcast
)
{
    st_dbg("\n");
    if (dhcp_pkt->gateway_nip)
    {
        return nc_dhcpd_send_pkt_to_replay(vlan_idx, dhcp_pkt);
    }
    return nc_dhcpd_send_pkt_to_client(vlan_idx, dhcp_pkt, force_broadcast);
}

static int nc_dhcpd_send_nak(int vlan_idx, struct dhcp_packet *oldpacket)
{
    struct dhcp_packet packet;
    st_dbg("\n");

    nc_dhcpd_init_packet(vlan_idx, &packet, oldpacket, DHCPNAK);

    return nc_dhcpd_send_packet(vlan_idx, &packet, 1);
}


static int nc_dhcpd_send_ack(
    int vlan_idx,
    struct dhcp_packet *oldpacket,
    __u32 yiaddr
)
{
    struct dhcp_packet packet;
    __u32 lease_time_sec;
    int ret = -1;
    const char *p_host_name;
    struct __nc_info ipc_item;
    //struct nc_ipcs_priv *data = NULL;

    st_dbg("\n");

    nc_dhcpd_init_packet(vlan_idx, &packet, oldpacket, DHCPACK);
    packet.yiaddr = yiaddr;
    //packet.flags = 0; //modify by caikun 2015.11.18

    lease_time_sec = nc_dhcpd_select_lease_time(oldpacket);

    add_simple_option(
        packet.options,
        DHCP_LEASE_TIME,
        htonl(lease_time_sec)
    );

    nc_dhcpd_add_subnet(&packet, nc_vlans[vlan_idx].netmask);
    nc_dhcpd_add_gateway(&packet, nc_vlans[vlan_idx].address);

    nc_dhcpd_add_bootp_options(&packet);

    ret = nc_dhcpd_send_packet(vlan_idx, &packet, 0);
    if (0 > ret)
        return -1;

    p_host_name = (const char*) get_option(oldpacket, DHCP_HOST_NAME);

    nc_dhcpd_add_lease(packet.chaddr, packet.yiaddr,
                       lease_time_sec,
                       p_host_name,
                       p_host_name ? (unsigned char)p_host_name[OPT_LEN - OPT_DATA] : 0);

    if (g_fd)
    {
        memcpy(ipc_item.hwaddr, packet.chaddr, 6);
        if (NC_VLAN_IDX_WIRELESS == vlan_idx)
            ipc_item.port_id = -1;
        else
            ipc_item.port_id = vlan_idx - 1;//start 0
        ipc_item.client_ip = yiaddr;

        send(g_fd,(char*)&ipc_item,sizeof(ipc_item),0);
    }

    return ret;
}

#define __NC_NET____END____Packet_________________________________________END


#define __NC_NET____START____DHCP_________________________________________START
#if 0 // nc_ipcs list
struct nc_ipcs_item
{
    struct list_head link_to;
    unsigned long jiffies;
    struct __nc_info info;
};

static inline
void nc_ipcs_item_init(struct nc_ipcs_item *item)
{
    memset(item, 0, sizeof(*item));
    INIT_LIST_HEAD(&item->link_to);
    //item->jiffies = jiffies;
}

static inline
struct nc_ipcs_item *alloc_nc_ipcs_item(void)
{
    struct nc_ipcs_item *item = NULL;

    item = (struct nc_ipcs_item *)xcalloc(1,sizeof(*item));
    if (!item)
    {
        return NULL;
    }

    nc_ipcs_item_init(item);

    return item;
}

static inline
void free_nc_ipcs_item(struct nc_ipcs_item *item)
{
    if (!item)
    {
        return ;
    }

    free(item);
}


struct nc_ipcs_priv
{
    struct list_head link_to;
    struct list_head list_for_nc_info;
    //spinlock_t lock_for_nc_info;
};

static inline
struct nc_ipcs_priv *alloc_nc_ipcs_priv(void)
{
    struct nc_ipcs_priv *data = NULL;

    data = (struct nc_ipcs_priv *)xzalloc(sizeof(*data));
    if (!data)
    {
        return NULL;
    }

    INIT_LIST_HEAD(&data->link_to);
    INIT_LIST_HEAD(&data->list_for_nc_info);
    //spin_lock_init(&data->lock_for_nc_info);

    return data;
}

static inline
void free_nc_ipcs_priv(struct nc_ipcs_priv *data)
{
    struct nc_ipcs_item *pos = NULL, *n = NULL;
    if (!data)
    {
        return ;
    }

    // spin_lock_bh(&data->lock_for_nc_info);
    list_for_each_entry_safe(pos, n, &data->list_for_nc_info, link_to)
    {
        list_del(&pos->link_to);
        free_nc_ipcs_item(pos);
    }
    // spin_unlock_bh(&data->lock_for_nc_info);

    free(data);
}

static struct list_head list_for_nc_ipcs = LIST_HEAD_INIT(list_for_nc_ipcs);
static spinlock_t lock_for_nc_ipcs = __SPIN_LOCK_UNLOCKED(lock_for_nc_ipcs);

#endif


/* 1. None of the callers expects it to ever fail */
/* 2. ip was always INADDR_ANY */
int udhcp_listen_socket(const char *inf, int *dhcpd_rx_flags)
{
    int fd;
    struct ifreq ifr;
    struct sockaddr_in addr;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

    setsockopt_reuseaddr(fd);
    if (setsockopt_broadcast(fd) == -1)
        st_dbg("SO_BROADCAST");

    /* NB: bug 1032 says this doesn't work on ethernet aliases (ethN:M) */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_ifrn.ifrn_name, inf, IFNAMSIZ - 1);
    ifr.ifr_ifrn.ifrn_name[IFNAMSIZ - 1] = '\0';
    if (setsockopt_bindtodevice(fd, (const char*)&ifr, sizeof(ifr)))
    {
        st_dbg("setsockopt_bindtodevice error");
        close(fd);
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    /* addr.sin_addr.s_addr = ip; - all-zeros is INADDR_ANY */
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));

    *dhcpd_rx_flags = 1;

    return fd;
}


static int do_discover(int vlan_idx,
                       struct dhcp_packet* oldpacket)
{
    struct dhcp_packet packet;
    __u32 lease_time_sec = MAX_LEASE_TIME;
    struct in_addr addr;
    struct __nc_info* info = 0;
    struct dyn_lease *lease = NULL;
    const char *p_host_name = NULL;
    __u32 static_lease_nip= 0;

    st_dbg("---------------------------\nmac:");
    st_dbg("%02x:02%x:02%x:02%x:%02x:%02x\n",(oldpacket->chaddr)[0],
           (oldpacket->chaddr)[1],(oldpacket->chaddr)[2],
           (oldpacket->chaddr)[3],(oldpacket->chaddr)[4],
           (oldpacket->chaddr)[5]);
    st_dbg("---------------------------\n");

    nc_dhcpd_init_packet(vlan_idx, &packet, oldpacket, DHCPOFFER);

    if (vlan_idx == NC_VLAN_IDX_WIRELESS) //当前是无线
    {
        pthread_rwlock_rdlock(&rwlock_for_static_nips);
        info = __find_static_nip_by_mac(oldpacket->chaddr);
        if (info)
        {
            static_lease_nip = info->client_ip;
        }
        pthread_rwlock_unlock(&rwlock_for_static_nips);
        if(!static_lease_nip)
        {
            __u8 *req_ip_opt = NULL;
            __u32 req_nip = 0;
            if ((req_ip_opt = get_option(oldpacket, DHCP_REQUESTED_IP)) != NULL
                    /* (read IP) */
                    && (move_from_unaligned32(req_nip, req_ip_opt), 1)
                    /* and the IP is in the lease range */
                    && ntohl(req_nip) >= nc_vlan_wireless_start_ip
                    && ntohl(req_nip) <= nc_vlan_wireless_end_ip
                    /* and is not already taken/offered */
                    && (!(lease = nc_dhcpd_find_lease_by_nip(req_nip))
                        /* or its taken, but expired */
                        || nc_dhcpd_is_expired_lease(lease)&& (!is_reserved_nip(req_nip)))
               )
            {
                st_dbg("\n");
                packet.yiaddr = req_nip;
            }
            /* Otherwise, find a free IP */
            else
            {
                st_dbg("\n");
                packet.yiaddr = nc_dhcpd_find_free_or_expired_nip(
                                    vlan_idx,
                                    oldpacket->chaddr,
                                    nc_vlan_wireless_start_ip,
                                    nc_vlan_wireless_end_ip
                                );
            }
        }
        else
        {
            packet.yiaddr = static_lease_nip;
        }
    }
    else  // 是有线
    {
        packet.yiaddr = htonl(ntohl(inet_addr(nc_vlans[vlan_idx].address)) + 1);
    }

    /* 先查找 */
    lease = find_lease_by_mac(oldpacket->chaddr);
    if(lease) // 如果找到 直接续约
    {
        signed_leasetime_t tmp = lease->expires - time(NULL);
        if (tmp >= 0)
        {
            lease_time_sec = tmp;
        }
    }
    else  // 如果没有找到 表示是个新的discover
    {
        lease_time_sec = nc_dhcpd_select_lease_time(oldpacket);
    }

    // 如果无法分配ip 直接退出
    if (!packet.yiaddr)
    {
        st_dbg("no IP addresses to give - OFFER abandoned\n");
        return -1;
    }

    // 刷新租约
    p_host_name = (const char*) get_option(oldpacket, DHCP_HOST_NAME);
    if (nc_dhcpd_add_lease(packet.chaddr, packet.yiaddr,
                           OFFER_TIME,
                           p_host_name,
                           p_host_name ? (unsigned char)p_host_name[OPT_LEN - OPT_DATA] : 0
                          ) == 0
       )
    {
        st_dbg("lease pool is full - OFFER abandoned\n");
        return -1;
    }


    add_simple_option(
        packet.options,
        DHCP_LEASE_TIME,
        htonl(lease_time_sec)
    );

    nc_dhcpd_add_subnet(&packet, nc_vlans[vlan_idx].netmask);
    nc_dhcpd_add_gateway(&packet, nc_vlans[vlan_idx].address);

    nc_dhcpd_add_bootp_options(&packet);

    memcpy(&addr, &packet.yiaddr, 4);
    st_dbg("Sending OFFER of %s\n", inet_ntoa(addr));

    return nc_dhcpd_send_packet(vlan_idx, &packet, 0);
}


static int do_request(
    int vlan_idx,
    struct dhcp_packet *pkt,
    __u32 server_nip,
    struct dyn_lease *lease
)
{
    __u8 *server_id_opt = NULL, *requested_opt = NULL;
    __u32 server_id_net = 0;
    __u32 requested_nip = 0;

    requested_opt = get_option(pkt, DHCP_REQUESTED_IP);
    server_id_opt = get_option(pkt, DHCP_SERVER_ID);
    if (requested_opt)
    {
        move_from_unaligned32(requested_nip, requested_opt);
    }
    if (server_id_opt)
    {
        move_from_unaligned32(server_id_net, server_id_opt);
    }

    if (lease)
    {
        if (server_id_opt)
        {
            /* SELECTING State */
            if (server_id_net == server_nip
                    && requested_opt
                    && requested_nip == lease->lease_nip
               )
            {
                st_dbg("\n");
                return nc_dhcpd_send_ack(vlan_idx, pkt, lease->lease_nip);
            }
        }
        else if (requested_opt)
        {
            /* INIT-REBOOT State */
            if (lease->lease_nip == requested_nip)
            {
                st_dbg("\n");
                return nc_dhcpd_send_ack(vlan_idx, pkt, lease->lease_nip);
            }
            else
            {
                st_dbg("\n");
                return nc_dhcpd_send_nak(vlan_idx, pkt);
            }
        }
        else if (lease->lease_nip == pkt->ciaddr)
        {
            st_dbg("\n");
            /* RENEWING or REBINDING State */
            return nc_dhcpd_send_ack(vlan_idx, pkt, lease->lease_nip);
        }
        else     /* don't know what to do!!!! */
        {
            st_dbg("\n");
            return nc_dhcpd_send_nak(vlan_idx, pkt);
        }
        st_dbg("oops...\n");
    }
    else if (server_id_opt)
    {
        /* SELECTING State */
        st_dbg("\n");

    }
    else if (requested_opt)
    {
        /* INIT-REBOOT State */
        lease = nc_dhcpd_find_lease_by_nip(requested_nip);
        if (lease)
        {
            if (nc_dhcpd_is_expired_lease(lease))
            {
                /* probably best if we drop this lease */
                st_dbg("\n");
                memset(lease->lease_mac, 0, sizeof(lease->lease_mac));
            }
            else
            {
                /* make some contention for this address */
                st_dbg("\n");
                return nc_dhcpd_send_nak(vlan_idx, pkt);
            }
        }
        else
        {
#if 0
            __u32 r = ntohl(requested_nip);
            if ((r < nc_vlan_wireless_start_ip) || (r > nc_vlan_wireless_end_ip))
            {
                st_dbg("\n");
                return nc_dhcpd_send_nak(vlan_idx, pkt);
            }
            /* else remain silent */
#else
            st_dbg("\n");
            return nc_dhcpd_send_nak(vlan_idx, pkt);
#endif
        }

    }
    else
    {
        /* RENEWING or REBINDING State */
        st_dbg("\n");
    }

    return 0;
}

static int nc_dhcpd_do_inform(int vlan_idx, struct dhcp_packet *oldpacket)
{
    struct dhcp_packet packet;

    st_dbg("\n");

    nc_dhcpd_init_packet(vlan_idx, &packet, oldpacket, DHCPACK);

    nc_dhcpd_add_subnet(&packet, nc_vlans[vlan_idx].netmask);
    nc_dhcpd_add_gateway(&packet, nc_vlans[vlan_idx].address);

    nc_dhcpd_add_bootp_options(&packet);

    return nc_dhcpd_send_packet(vlan_idx, &packet, 0);
}


static int nc_dhcpd_recv(int *fd, int vlan_idx)
{
    __u8 *state = NULL;
    struct dhcp_packet packet;
    struct dyn_lease *lease,fake_lease;
    __u32 server_nip = inet_addr(nc_vlans[vlan_idx].address);
    //__u32 lease_nip = htonl(ntohl(server_nip) + 1);
    int bytes = 0;

    memset(&packet,0,sizeof(packet));
    st_dbg("%d_socket recv!!", vlan_idx);
    bytes = udhcp_recv_kernel_packet(&packet, *fd);
    st_dbg("%d_socket recv %d bytes!!", vlan_idx, bytes);
    if (bytes < 0)
    {
        /* bytes can also be -2 ("bad packet data") */
        if (bytes == -1 && errno != EINTR)
        {
            char ifname[IFNAMSIZ] = {0};
            st_dbg("Read error: %s, reopening socket", strerror(errno));
            close(*fd);
            snprintf(ifname, IFNAMSIZ, NC_NET_INTERFACE".%s", nc_vlans[vlan_idx].vid);
            *fd = udhcp_listen_socket(ifname, (int*)&nc_dhcpd_rx_flags[vlan_idx]);
            if (!(*fd))
            {
                st_dbg("%d:create_socket error!!_nc_dhcpd_recv", vlan_idx);
            }
        }
        goto ret;
    }

    if (packet.hlen != 6)
    {
        st_dbg("MAC length != 6, ignoring packet");
        goto ret;
    }

    state = get_option(&packet, DHCP_MESSAGE_TYPE);
    if (state == NULL)
    {
        st_dbg("no message type option, ignoring packet");
        goto ret;
    }

    if (vlan_idx == NC_VLAN_IDX_WIRELESS)
    {
        struct __nc_info *info = NULL;
        lease = NULL;

        pthread_rwlock_rdlock(&rwlock_for_static_nips);
        /* Look for a static lease */
        info = __find_static_nip_by_mac(packet.chaddr);
        if (info)
        {
            st_dbg("Found static lease: %x", info->client_ip);
            memcpy(fake_lease.lease_mac, packet.chaddr, 6);
            fake_lease.lease_nip = info->client_ip;
            fake_lease.expires = 0;

            lease = &fake_lease;
        }
        pthread_rwlock_unlock(&rwlock_for_static_nips);

        if (!lease)
        {
            lease = find_lease_by_mac(packet.chaddr);
        }
    }
    else
    {
        lease = find_lease_by_mac(packet.chaddr);
    }

    switch (state[0])
    {
    case DHCPDISCOVER:
        st_dbg("Received DISCOVER");
        if (do_discover(vlan_idx, &packet) < 0)
        {
            st_dbg("send OFFER failed");
        }
        break;
    case DHCPREQUEST:
    {
        st_dbg("Received DHCPREQUEST");
        if (do_request(vlan_idx, &packet, server_nip, lease) < 0)
        {
            st_dbg("do_request failed");
        }
        break;
    }
    case DHCPDECLINE:
        st_dbg("Received DECLINE");
        if (lease)
        {
            memset(lease->lease_mac, 0, sizeof(lease->lease_mac));
            lease->expires = time(NULL) + DECLINE_TIME;
        }
        break;
    case DHCPRELEASE:
        st_dbg("Received RELEASE");
        if (lease)
            lease->expires = time(NULL);
        break;
    case DHCPINFORM:
        st_dbg("Received INFORM");
        nc_dhcpd_do_inform(vlan_idx, &packet);
        break;
    default:
        st_dbg("Unsupported DHCP message (%02x) - ignoring", state[0]);
    }

ret:
    return 0;
}

void* nc_dhtcp_recv_thread(void *data)
{
    struct nc_recv_st *p_nc_recv_st = data;
    unsigned timeout_end;
    fd_set rfds;
    int max_sock,retval;
    struct timeval tv;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL); //允许退出线程
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL); //设置立即取消

    if (0 == p_nc_recv_st)
        goto error;

    st_dbg("recv thread begin %d",p_nc_recv_st->vlan_idx);

    timeout_end = monotonic_sec() + nc_dhcp_eth0_45[p_nc_recv_st->vlan_idx].auto_time;
    while (1)
    {
        if (nc_dhcpd_rx_flags[NC_NET_DEVIF_RX_FLAG_EXIT])
        {
            break;
        }
        max_sock = udhcp_sp_fd_set(&rfds, p_nc_recv_st->fd);

        tv.tv_sec = timeout_end - monotonic_sec();
        tv.tv_usec = 0;
        retval = 0;
        if (tv.tv_sec > 0)
        {
            retval = select(max_sock + 1, &rfds, NULL, NULL, &tv);
        }
        if (retval == 0)
        {
            st_dbg("write_leases");
            //write_leases();
            timeout_end = monotonic_sec() + nc_dhcp_eth0_45[p_nc_recv_st->vlan_idx].auto_time;
            continue;
        }
        if (retval < 0 && errno != EINTR)
        {
            st_dbg("Error on select");
            continue;
        }

        switch (udhcp_sp_read(&rfds))
        {
        case SIGUSR1:
            st_dbg("Received a SIGUSR1");
            //write_leases();
            /* why not just reset the timeout, eh */
            timeout_end = monotonic_sec() + nc_dhcp_eth0_45[p_nc_recv_st->vlan_idx].auto_time;
            continue;
        case SIGTERM:
            st_dbg("Received a SIGTERM");
            goto error;
        case 0:	/* no signal: read a packet */
            st_dbg("no signal: read a packet");
            break;
        default: /* signal or error (probably EINTR): back to select */
            st_dbg("default");
            continue;
        }

        nc_dhcpd_recv(&p_nc_recv_st->fd, p_nc_recv_st->vlan_idx);
    }

error:
    st_dbg("recv thread end %d",p_nc_recv_st->vlan_idx);

    pthread_exit(0);
    return 0;
}

int nc_dhcpd_go()
{
    int i = 0;
    int ibIndex = 0;

    if (nc_bwireless)
        ibIndex = NC_VLAN_IDX_WIRELESS;
    else
        ibIndex = NC_VLAN_IDX_RJ45_START;

    // 创建sock
    for (i = ibIndex; i < nc_vlan_cnt; ++i)
    {
        char ifname[IFNAMSIZ] = {0};
        snprintf(ifname, IFNAMSIZ, NC_NET_INTERFACE".%s", nc_vlans[i].vid);
        recv_st[i].fd = udhcp_listen_socket(ifname, (int*)&nc_dhcpd_rx_flags[i]);
        if (!recv_st[i].fd)
        {
            st_dbg("%d:create_socket error!!\n", i);
            goto out;
        }
        st_dbg("create_socket %s!!\n", ifname);
    }

    // 循环监听已经创建的端口
    for (i = ibIndex; i < nc_vlan_cnt; ++i)
    {
        if (nc_dhcpd_rx_flags[i])
        {
            recv_st[i].vlan_idx = i;
            pthread_create(&(recv_st[i].tid), NULL, nc_dhtcp_recv_thread, &recv_st[i]);
            nc_dhcpd_rx_flags[i] = 0;
        }
    }

    return 1;

out:
    for (i = NC_VLAN_IDX_START; i < nc_vlan_cnt; ++i)
    {
        if (0 > recv_st[i].fd)
        {
            continue;
        }
        close(recv_st[i].fd);
        recv_st[i].fd = 0;
    }

    return 0;
}


int udhcp_read_interface(const char *interface,
                         struct nc_dhcp_st* st)
{
    int fd;
    struct ifreq ifr;
    //struct sockaddr_in *our_ip;
    int iret = 0;
    memset(&ifr, 0, sizeof(ifr));
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy_IFNAMSIZ(ifr.ifr_name, interface);

    /*if (ioctl_or_perror(fd, SIOCGIFADDR, &ifr,
    	"is interface %s up and configured?", interface)
    ) {
    	st_dbg("\n");
    		iret = -1;
    		goto error;
    }

    our_ip = (struct sockaddr_in *) &ifr.ifr_addr;
    st->nip = our_ip->sin_addr.s_addr;
    st_dbg("IP %s", inet_ntoa(our_ip->sin_addr));*/

    if (bb_ioctl_or_warn(fd, SIOCGIFINDEX, &ifr) != 0)
    {
        st_dbg("\n");
        iret = -1;
        goto error;
    }

    st_dbg("Adapter index %d", ifr.ifr_ifindex);
    st->ifindex = ifr.ifr_ifindex;

    if (bb_ioctl_or_warn(fd, SIOCGIFHWADDR, &ifr) != 0)
    {
        st_dbg("\n");
        iret = -1;
        goto error;
    }
    memcpy(st->mac, ifr.ifr_hwaddr.sa_data, 6);
    st_dbg("MAC %02x:%02x:%02x:%02x:%02x:%02x",
           st->mac[0], st->mac[1], st->mac[2], st->mac[3], st->mac[4], st->mac[5]);

    if (bb_ioctl_or_warn(fd, SIOCGIFMTU, &ifr) != 0)
    {
        st_dbg("\n");
        iret = -1;
        goto error;
    }
    st_dbg("Adapter mtu %d", ifr.ifr_mtu);
    st->mtu = ifr.ifr_mtu;

    if (bb_ioctl_or_warn(fd, SIOCGIFFLAGS, &ifr) != 0)
    {
        st_dbg("\n");
        iret = -1;
        goto error;
    }

    st->flags = ifr.ifr_flags;

    st->auto_time = 7200;

error:
    close(fd);
    return iret;
}


int nc_dhcp_net_init(int fd, const int max_lan_ip, int bwireless)
{
    int i=0;
    int ibIndex = 0;
    g_fd = 0;
    if (0 != nc_dhcp_eth0)
        return 0;

    st_dbg("nc_dhcp_net_init");

    //int ip_pools = ntohl(~(inet_addr(nc_vlans[NC_VLAN_IDX_WIRELESS].netmask)));

    //ip_pools -= 1; /*减去一个广播地址*/
    //ip_pools -= 1; /*去掉接口地址*/

    nc_vlan_wireless_start_ip = ntohl(inet_addr(nc_vlans[NC_VLAN_IDX_WIRELESS].address));
    nc_vlan_wireless_start_ip += 1;

    nc_vlan_wireless_end_ip = inet_addr(nc_vlans[NC_VLAN_IDX_WIRELESS].address);
    nc_vlan_wireless_end_ip &= inet_addr(nc_vlans[NC_VLAN_IDX_WIRELESS].netmask);
    nc_vlan_wireless_end_ip = ntohl(nc_vlan_wireless_end_ip);
    nc_vlan_wireless_end_ip += ~(ntohl(inet_addr(nc_vlans[NC_VLAN_IDX_WIRELESS].netmask)));
    nc_vlan_wireless_end_ip -= 1;

    nc_vlan_cnt = max_lan_ip + 1; /* 1个wireless口 当不启用无线时，vlan0 不会创建和启用 */

    if (nc_vlan_cnt > NC_VLAN_CNT)
    {
        printf("rj45 range:0->%d\n", NC_VLAN_CNT - 1);
        return -EINVAL;
    }

    NC_NET_MAX_LAN_NIP = max_lan_ip;
    nc_bwireless = bwireless;

    recv_st = (struct nc_recv_st*)xzalloc(nc_vlan_cnt * sizeof(struct nc_recv_st));
    static_nips = (struct __nc_info*)xzalloc(NC_NET_MAX_STATIC_NIP * sizeof(struct __nc_info));
    nc_dhcp_eth0_45 = (struct nc_dhcp_st*)xzalloc(nc_vlan_cnt * sizeof(struct nc_dhcp_st));

    nc_dhcp_eth0 = (struct nc_dhcp_st*)malloc(sizeof(struct nc_dhcp_st));
    if (0 != udhcp_read_interface(NC_NET_INTERFACE ,
                                  nc_dhcp_eth0))
    {
        st_dbg("udhcp_read_interface error\n");
        goto error;
    }

    if (0 != __nc_net_app_apply())
    {
        st_dbg("__nc_net_app_apply error\n");
        goto app_clean;
    }

    if (nc_bwireless)
        ibIndex = NC_VLAN_IDX_WIRELESS;
    else
        ibIndex = NC_VLAN_IDX_RJ45_START;

    for(i = ibIndex; i < nc_vlan_cnt; ++i)
    {
        char ifname[IFNAMSIZ] = {0};
        snprintf(ifname, IFNAMSIZ, NC_NET_INTERFACE".%s", nc_vlans[i].vid);
        if (0 != udhcp_read_interface(ifname ,
                                      &nc_dhcp_eth0_45[i]))
            goto error;
    }

    if (0 != pthread_rwlock_init(&rwlock_for_static_nips,NULL))
        goto error_clean;

    g_leases = (struct dyn_lease*)xzalloc(MAX_LEASE * sizeof(g_leases[0]));

    udhcp_sp_setup();

    g_fd= fd;

    return 1;

error_clean:
    pthread_rwlock_destroy(&rwlock_for_static_nips);
app_clean:
    __nc_net_app_cleanup();
error:
    free(g_leases);
    g_leases = 0;

    free(recv_st);
    recv_st = 0;
    free(static_nips);
    static_nips = 0;
    free(nc_dhcp_eth0_45);
    nc_dhcp_eth0_45 = 0;

    free(nc_dhcp_eth0);
    nc_dhcp_eth0 = 0;

    nc_bwireless = 0;

    NC_NET_MAX_LAN_NIP = 0;

    st_dbg("error init");
    return 0;
}

int nc_dhcp_net_uninit()
{
    int i = 0;
    int ibIndex = 0;
    if (0 == nc_dhcp_eth0)
        return 0;

    if (nc_bwireless)
        ibIndex = NC_VLAN_IDX_WIRELESS;
    else
        ibIndex = NC_VLAN_IDX_RJ45_START;

    nc_dhcpd_rx_flags[NC_NET_DEVIF_RX_FLAG_EXIT] = 1;
    for (i = ibIndex; i < nc_vlan_cnt; ++i)
    {
        if (nc_dhcpd_rx_flags[i])
        {
            pthread_cancel(recv_st[i].tid);
            pthread_join(recv_st[i].tid,NULL);
            close(recv_st[i].fd);
            nc_dhcpd_rx_flags[i] = 0;
        }
    }

    if (g_leases)
    {
        free(g_leases);
        g_leases = NULL;
    }

    free(recv_st);
    recv_st = 0;
    free(static_nips);
    static_nips = 0;
    free(nc_dhcp_eth0_45);
    nc_dhcp_eth0_45 = 0;

    free(nc_dhcp_eth0);
    nc_dhcp_eth0 = 0;

    pthread_rwlock_destroy(&rwlock_for_static_nips);

    g_fd = 0;

    nc_bwireless = 0;

    NC_NET_MAX_LAN_NIP = 0;

    __nc_net_app_cleanup();

    return 1;
}


int nc_dhcp_run()
{
    return nc_dhcpd_go();
}

int get_nc_nvr_max_lan_nip()
{
    return NC_NET_MAX_LAN_NIP;
}


int __nc_nvr_list_static(struct __nc_info *infos, int info_size)
{
    int i;
    int iNum = 0;
    __u8 tmp_mac[6] = {0};
    if (!infos ||
            0 >= info_size
       )
        return -1;

    info_size = NC_NET_MAX_STATIC_NIP < info_size?NC_NET_MAX_STATIC_NIP:info_size;

    pthread_rwlock_wrlock(&rwlock_for_static_nips);
    for (i = 0; i < NC_NET_MAX_STATIC_NIP; ++i)
    {
        struct __nc_info *info = &static_nips[i];
        if(iNum >= info_size)
            break;

        if (memcmp(info->hwaddr, tmp_mac, 6))
        {
            memcpy(&infos[iNum],info,sizeof(struct __nc_info));
            ++iNum;
        }
    }
    pthread_rwlock_unlock(&rwlock_for_static_nips);

    return iNum;
}
int __nc_nvr_add_static_nip(unsigned char *mac, unsigned int ip)
{
    struct __nc_info nc_info_st;
    if (!mac)
        return -1;

    memcpy(nc_info_st.hwaddr,mac,6);
    nc_info_st.port_id = -1;
    nc_info_st.client_ip = ip;

    add_static_nip(&nc_info_st);

    return 0;
}
int __nc_nvr_mod_static_nip(unsigned char *mac, unsigned int ip)
{
    struct __nc_info nc_info_st;
    if (!mac)
        return -1;

    memcpy(nc_info_st.hwaddr,mac,6);
    nc_info_st.port_id = -1;
    nc_info_st.client_ip = ip;

    mod_static_nip(&nc_info_st);

    return 0;
}
int __nc_nvr_del_static_nip(unsigned char *mac)
{
    struct __nc_info nc_info_st;
    if (!mac)
        return -1;

    memcpy(nc_info_st.hwaddr,mac,6);
    nc_info_st.port_id = -1;
    nc_info_st.client_ip = 0;

    del_static_nip(&nc_info_st);

    return 0;
}

int __nc_nvr_clr_static_nip()
{
    clr_static_nip();
    return 0;
}


#define __NC_NET____END____DHCP_________________________________________END

