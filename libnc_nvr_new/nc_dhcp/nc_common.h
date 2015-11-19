#ifndef nc_common_h
#define nc_common_h 1

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>

#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>


#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h> // struct udphdr
#include <netinet/ip.h>  // struct iphdr

#include <netpacket/packet.h>

#include <net/if_arp.h>
#include <net/if.h>

#include <arpa/inet.h>


typedef unsigned char  __u8;
typedef unsigned short __u16;
typedef unsigned int   __u32;
typedef short __s16;
typedef int   __s32;

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/* Octets in one Ethernet addr, from <linux/if_ether.h> */
#define ETH_ALEN	6


#define TYPE_MASK       0x0F
#define ENABLE_FEATURE_UDHCP_RFC3397 0
enum
{
    OPTION_IP = 1,
    OPTION_IP_PAIR,
    OPTION_STRING,
#if ENABLE_FEATURE_UDHCP_RFC3397
    OPTION_STR1035,	/* RFC1035 compressed domain name list */
#endif
    OPTION_BOOLEAN,
    OPTION_U8,
    OPTION_U16,
    OPTION_S16,
    OPTION_U32,
    OPTION_S32,
    OPTION_STATIC_ROUTES,
};

#define SERVER_PORT 67
#define CLIENT_PORT 68

/* Client requests this option by default */
#define OPTION_REQ      0x10
/* There can be a list of 1 or more of these */
#define OPTION_LIST     0x20

/*****************************************************************/
/* Do not modify below here unless you know what you are doing!! */
/*****************************************************************/

/* DHCP protocol -- see RFC 2131 */
#define DHCP_MAGIC		0x63825363

/* DHCP option codes (partial list) */
#define DHCP_PADDING            0x00
#define DHCP_SUBNET             0x01
#define DHCP_TIME_OFFSET        0x02
#define DHCP_ROUTER             0x03
#define DHCP_TIME_SERVER        0x04
#define DHCP_NAME_SERVER        0x05
#define DHCP_DNS_SERVER         0x06
#define DHCP_LOG_SERVER         0x07
#define DHCP_COOKIE_SERVER      0x08
#define DHCP_LPR_SERVER         0x09
#define DHCP_HOST_NAME          0x0c
#define DHCP_BOOT_SIZE          0x0d
#define DHCP_DOMAIN_NAME        0x0f
#define DHCP_SWAP_SERVER        0x10
#define DHCP_ROOT_PATH          0x11
#define DHCP_IP_TTL             0x17
#define DHCP_MTU                0x1a
#define DHCP_BROADCAST          0x1c
#define DHCP_NTP_SERVER         0x2a
#define DHCP_WINS_SERVER        0x2c
#define DHCP_REQUESTED_IP       0x32
#define DHCP_LEASE_TIME         0x33
#define DHCP_OPTION_OVERLOAD    0x34
#define DHCP_MESSAGE_TYPE       0x35
#define DHCP_SERVER_ID          0x36
#define DHCP_PARAM_REQ          0x37
#define DHCP_MESSAGE            0x38
#define DHCP_MAX_SIZE           0x39
#define DHCP_T1                 0x3a
#define DHCP_T2                 0x3b
#define DHCP_VENDOR             0x3c
#define DHCP_CLIENT_ID          0x3d
#define DHCP_FQDN               0x51
#define DHCP_STATIC_ROUTES      0x79
#define DHCP_END                0xFF
/* Offsets in option byte sequence */
#define OPT_CODE                0
#define OPT_LEN                 1
#define OPT_DATA                2
/* Bits in "overload" option */
#define OPTION_FIELD            0
#define FILE_FIELD              1
#define SNAME_FIELD             2

#define BOOTREQUEST             1
#define BOOTREPLY               2

#define ETH_10MB                1
#define ETH_10MB_LEN            6

#define DHCPDISCOVER            1 /* client -> server */
#define DHCPOFFER               2 /* client <- server */
#define DHCPREQUEST             3 /* client -> server */
#define DHCPDECLINE             4 /* client -> server */
#define DHCPACK                 5 /* client <- server */
#define DHCPNAK                 6 /* client <- server */
#define DHCPRELEASE             7 /* client -> server */
#define DHCPINFORM              8 /* client -> server */

struct dhcp_option
{
    __u8 flags;
    __u8 code;
};


#define DHCP_OPTIONS_BUFSIZE  308
#define CONFIG_UDHCPC_SLACK_FOR_BUGGY_SERVERS 80


//TODO: rename ciaddr/yiaddr/chaddr

#define BROADCAST_FLAG 0x8000 /* "I need broadcast replies" */

struct dhcp_packet
{
    __u8 op;      /* 1 = BOOTREQUEST, 2 = BOOTREPLY */
    __u8 htype;   /* hardware address type. 1 = 10mb ethernet */
    __u8 hlen;    /* hardware address length */
    __u8 hops;    /* used by relay agents only */
    __u32 xid;    /* unique id */
    __u16 secs;   /* elapsed since client began acquisition/renewal */
    __u16 flags;  /* only one flag so far: */
    __u32 ciaddr; /* client IP (if client is in BOUND, RENEW or REBINDING state) */
    __u32 yiaddr; /* 'your' (client) IP address */
    /* IP address of next server to use in bootstrap, returned in DHCPOFFER, DHCPACK by server */
    __u32 siaddr_nip;
    __u32 gateway_nip; /* relay agent IP address */
    __u8 chaddr[16];   /* link-layer client hardware address (MAC) */
    __u8 sname[64];    /* server host name (ASCIZ) */
    __u8 file[128];    /* boot file name (ASCIZ) */
    __u32 cookie;      /* fixed first four option bytes (99,130,83,99 dec) */
    __u8 options[DHCP_OPTIONS_BUFSIZE + CONFIG_UDHCPC_SLACK_FOR_BUGGY_SERVERS];
};

struct ip_udp_dhcp_packet
{
    struct iphdr ip;
    struct udphdr udp;
    struct dhcp_packet data;
};

/* Defaults you may want to tweak */
/* Default max_lease_sec */
#define MAX_LEASE_TIME      (60*60*24 * 10)
#define MIN_LEASE_TIME      60
#define OFFER_TIME          60
#define CONFLICT_TIME       3600
#define DECLINE_TIME        3600
#define MAX_LEASE           235

#define SERVER_PORT 67
#define CLIENT_PORT 68

#define NC_DHCPD_SIADDR "0.0.0.0"
#define NC_DHCPD_SINAME ""
#define NC_DHCPD_BOOTFILE ""
#define NC_DHCPD_STATIC_LEASE ""

typedef __u32 leasetime_t;
typedef __s32 signed_leasetime_t;

struct dyn_lease
{
    /* "nip": IP in network order */
    /* Unix time when lease expires. Kept in memory in host order.
     * When written to file, converted to network order
     * and adjusted (current time subtracted) */
    leasetime_t expires;
    __u32 lease_nip;
    /* We use lease_mac[6], since e.g. ARP probing uses
     * only 6 first bytes anyway. We check received dhcp packets
     * that their hlen == 6 and thus chaddr has only 6 significant bytes
     * (dhcp packet has chaddr[16], not [6])
     */
    __u8 lease_mac[6];
    char hostname[20];
    __u8 pad[2];
    /* total size is a multiply of 4 */
};

struct arpMsg
{
    /* Ethernet header */
    __u8  h_dest[6];     /* 00 destination ether addr */
    __u8  h_source[6];   /* 06 source ether addr */
    __u16 h_proto;       /* 0c packet type ID field */

    /* ARP packet */
    __u16 htype;         /* 0e hardware type (must be ARPHRD_ETHER) */
    __u16 ptype;         /* 10 protocol type (must be ETH_P_IP) */
    __u8  hlen;          /* 12 hardware address length (must be 6) */
    __u8  plen;          /* 13 protocol address length (must be 4) */
    __u16 operation;     /* 14 ARP opcode */
    __u8  sHaddr[6];     /* 16 sender's hardware address */
    __u8  sInaddr[4];    /* 1c sender's IP address */
    __u8  tHaddr[6];     /* 20 target's hardware address */
    __u8  tInaddr[4];    /* 26 target's IP address */
    __u8  pad[18];       /* 2a pad for min. ethernet payload (60 bytes) */
};

enum
{
    ARP_MSG_SIZE = 0x2a
};


#define move_from_unaligned_int(v, intp) (memcpy(&(v), (intp), sizeof(int)))
#define move_from_unaligned16(v, u16p) (memcpy(&(v), (u16p), 2))
#define move_from_unaligned32(v, u32p) (memcpy(&(v), (u32p), 4))
#define move_to_unaligned32(u32p, v) do { \
	__u32 __t = (v); \
	memcpy((u32p), &__t, 4); \
} while (0)


struct nc_dhcp_st
{
    int ifindex;
    __u32 nip;
    __u8 mac[6];
    __u32 auto_time;
    __u32 mtu;
    __u16 flags;
};

#endif
