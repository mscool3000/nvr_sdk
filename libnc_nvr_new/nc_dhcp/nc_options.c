/* vi: set sw=4 ts=4: */
/*
 * options.c -- DHCP server option packet tools
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * Licensed under GPLv2, see file LICENSE in this tarball for details.
 */

#include "nc_common.h"
#include "nc_options.h"


/* Supported options are easily added here */
const struct dhcp_option dhcp_options[] =
{
    /* flags                                    code */
    { OPTION_IP                   | OPTION_REQ, 0x01 }, /* DHCP_SUBNET        */
    { OPTION_S32                              , 0x02 }, /* DHCP_TIME_OFFSET   */
    { OPTION_IP | OPTION_LIST     | OPTION_REQ, 0x03 }, /* DHCP_ROUTER        */
    { OPTION_IP | OPTION_LIST                 , 0x04 }, /* DHCP_TIME_SERVER   */
    { OPTION_IP | OPTION_LIST                 , 0x05 }, /* DHCP_NAME_SERVER   */
    { OPTION_IP | OPTION_LIST     | OPTION_REQ, 0x06 }, /* DHCP_DNS_SERVER    */
    { OPTION_IP | OPTION_LIST                 , 0x07 }, /* DHCP_LOG_SERVER    */
    { OPTION_IP | OPTION_LIST                 , 0x08 }, /* DHCP_COOKIE_SERVER */
    { OPTION_IP | OPTION_LIST                 , 0x09 }, /* DHCP_LPR_SERVER    */
    { OPTION_STRING               | OPTION_REQ, 0x0c }, /* DHCP_HOST_NAME     */
    { OPTION_U16                              , 0x0d }, /* DHCP_BOOT_SIZE     */
    { OPTION_STRING | OPTION_LIST | OPTION_REQ, 0x0f }, /* DHCP_DOMAIN_NAME   */
    { OPTION_IP                               , 0x10 }, /* DHCP_SWAP_SERVER   */
    { OPTION_STRING                           , 0x11 }, /* DHCP_ROOT_PATH     */
    { OPTION_U8                               , 0x17 }, /* DHCP_IP_TTL        */
    { OPTION_U16                              , 0x1a }, /* DHCP_MTU           */
    { OPTION_IP                   | OPTION_REQ, 0x1c }, /* DHCP_BROADCAST     */
    { OPTION_STRING                           , 0x28 }, /* nisdomain          */
    { OPTION_IP | OPTION_LIST                 , 0x29 }, /* nissrv             */
    { OPTION_IP | OPTION_LIST     | OPTION_REQ, 0x2a }, /* DHCP_NTP_SERVER    */
    { OPTION_IP | OPTION_LIST                 , 0x2c }, /* DHCP_WINS_SERVER   */
    { OPTION_IP                               , 0x32 }, /* DHCP_REQUESTED_IP  */
    { OPTION_U32                              , 0x33 }, /* DHCP_LEASE_TIME    */
    { OPTION_U8                               , 0x35 }, /* dhcptype           */
    { OPTION_IP                               , 0x36 }, /* DHCP_SERVER_ID     */
    { OPTION_STRING                           , 0x38 }, /* DHCP_MESSAGE       */
    { OPTION_STRING                           , 0x3C }, /* DHCP_VENDOR        */
    { OPTION_STRING                           , 0x3D }, /* DHCP_CLIENT_ID     */
    { OPTION_STRING                           , 0x42 }, /* tftp               */
    { OPTION_STRING                           , 0x43 }, /* bootfile           */
    { OPTION_STRING                           , 0x4D }, /* userclass          */
#if ENABLE_FEATURE_UDHCP_RFC3397
    { OPTION_STR1035 | OPTION_LIST            , 0x77 }, /* search             */
#endif
    { OPTION_STATIC_ROUTES                    , 0x79 }, /* DHCP_STATIC_ROUTES */
    /* MSIE's "Web Proxy Autodiscovery Protocol" support */
    { OPTION_STRING                           , 0xfc }, /* wpad               */

    /* Options below have no match in dhcp_option_strings[],
     * are not passed to dhcpc scripts, and cannot be specified
     * with "option XXX YYY" syntax in dhcpd config file. */

    { OPTION_U16                              , 0x39 }, /* DHCP_MAX_SIZE      */
    { 0, 0 } /* zeroed terminating entry */
};

/* Used for converting options from incoming packets to env variables
 * for udhcpc stript */
/* Must match dhcp_options[] order */
#if 0
const char dhcp_option_strings[] ALIGN1 =
    "subnet" "\0"      /* DHCP_SUBNET         */
    "timezone" "\0"    /* DHCP_TIME_OFFSET    */
    "router" "\0"      /* DHCP_ROUTER         */
    "timesrv" "\0"     /* DHCP_TIME_SERVER    */
    "namesrv" "\0"     /* DHCP_NAME_SERVER    */
    "dns" "\0"         /* DHCP_DNS_SERVER     */
    "logsrv" "\0"      /* DHCP_LOG_SERVER     */
    "cookiesrv" "\0"   /* DHCP_COOKIE_SERVER  */
    "lprsrv" "\0"      /* DHCP_LPR_SERVER     */
    "hostname" "\0"    /* DHCP_HOST_NAME      */
    "bootsize" "\0"    /* DHCP_BOOT_SIZE      */
    "domain" "\0"      /* DHCP_DOMAIN_NAME    */
    "swapsrv" "\0"     /* DHCP_SWAP_SERVER    */
    "rootpath" "\0"    /* DHCP_ROOT_PATH      */
    "ipttl" "\0"       /* DHCP_IP_TTL         */
    "mtu" "\0"         /* DHCP_MTU            */
    "broadcast" "\0"   /* DHCP_BROADCAST      */
    "nisdomain" "\0"   /*                     */
    "nissrv" "\0"      /*                     */
    "ntpsrv" "\0"      /* DHCP_NTP_SERVER     */
    "wins" "\0"        /* DHCP_WINS_SERVER    */
    "requestip" "\0"   /* DHCP_REQUESTED_IP   */
    "lease" "\0"       /* DHCP_LEASE_TIME     */
    "dhcptype" "\0"    /*                     */
    "serverid" "\0"    /* DHCP_SERVER_ID      */
    "message" "\0"     /* DHCP_MESSAGE        */
    "vendorclass" "\0" /* DHCP_VENDOR         */
    "clientid" "\0"    /* DHCP_CLIENT_ID      */
    "tftp" "\0"
    "bootfile" "\0"
    "userclass" "\0"
#if ENABLE_FEATURE_UDHCP_RFC3397
    "search" "\0"
#endif
    "staticroutes" "\0" /* DHCP_STATIC_ROUTES  */
    /* MSIE's "Web Proxy Autodiscovery Protocol" support */
    "wpad" "\0"
    ;
#endif

/* Lengths of the different option types */
const __u8 dhcp_option_lengths[] =
{
    [OPTION_IP] =      4,
    [OPTION_IP_PAIR] = 8,
    [OPTION_BOOLEAN] = 1,
    [OPTION_STRING] =  1,
#if ENABLE_FEATURE_UDHCP_RFC3397
    [OPTION_STR1035] = 1,
#endif
    [OPTION_U8] =      1,
    [OPTION_U16] =     2,
    [OPTION_S16] =     2,
    [OPTION_U32] =     4,
    [OPTION_S32] =     4,
    /* Just like OPTION_STRING, we use minimum length here */
    [OPTION_STATIC_ROUTES] = 5,
};



#if defined CONFIG_UDHCP_DEBUG && CONFIG_UDHCP_DEBUG >= 2
static void log_option(const char *pfx, const __u8 *opt)
{
    if (dhcp_verbose >= 2)
    {
        char buf[256 * 2 + 2];
        *bin2hex(buf, (void*) (opt + OPT_DATA), opt[OPT_LEN]) = '\0';
        //bb_info_msg("%s: 0x%02x %s", pfx, opt[OPT_CODE], buf);
    }
}
#else
# define log_option(pfx, opt) ((void)0)
#endif


/* get an option with bounds checking (warning, result is not aligned). */
__u8* get_option(struct dhcp_packet *packet, int code)
{
    __u8 *optionptr;
    int len;
    int rem;
    int overload = 0;
    enum
    {
        FILE_FIELD101  = FILE_FIELD  * 0x101,
        SNAME_FIELD101 = SNAME_FIELD * 0x101,
    };

    /* option bytes: [code][len][data1][data2]..[dataLEN] */
    optionptr = packet->options;
    rem = sizeof(packet->options);
    while (1)
    {
        if (rem <= 0)
        {
            //bb_error_msg("bogus packet, malformed option field");
            return NULL;
        }
        if (optionptr[OPT_CODE] == DHCP_PADDING)
        {
            rem--;
            optionptr++;
            continue;
        }
        if (optionptr[OPT_CODE] == DHCP_END)
        {
            if ((overload & FILE_FIELD101) == FILE_FIELD)
            {
                /* can use packet->file, and didn't look at it yet */
                overload |= FILE_FIELD101; /* "we looked at it" */
                optionptr = packet->file;
                rem = sizeof(packet->file);
                continue;
            }
            if ((overload & SNAME_FIELD101) == SNAME_FIELD)
            {
                /* can use packet->sname, and didn't look at it yet */
                overload |= SNAME_FIELD101; /* "we looked at it" */
                optionptr = packet->sname;
                rem = sizeof(packet->sname);
                continue;
            }
            break;
        }
        len = 2 + optionptr[OPT_LEN];
        rem -= len;
        if (rem < 0)
            continue; /* complain and return NULL */

        if (optionptr[OPT_CODE] == code)
        {
            log_option("Option found", optionptr);
            return optionptr + OPT_DATA;
        }

        if (optionptr[OPT_CODE] == DHCP_OPTION_OVERLOAD)
        {
            overload |= optionptr[OPT_DATA];
            /* fall through */
        }
        optionptr += len;
    }

    /* log3 because udhcpc uses it a lot - very noisy */
    //log3("Option 0x%02x not found", code);
    return NULL;
}


/* return the position of the 'end' option (no bounds checking) */
int end_option(__u8 *optionptr)
{
    int i = 0;

    while (optionptr[i] != DHCP_END)
    {
        if (optionptr[i] != DHCP_PADDING)
            i += optionptr[i + OPT_LEN] + 1;
        i++;
    }
    return i;
}


/* add an option string to the options */
/* option bytes: [code][len][data1][data2]..[dataLEN] */
int add_option_string(__u8 *optionptr, __u8 *string)
{
    int end = end_option(optionptr);

    /* end position + string length + option code/length + end option */
    if (end + string[OPT_LEN] + 2 + 1 >= DHCP_OPTIONS_BUFSIZE)
    {
        //bb_error_msg("option 0x%02x did not fit into the packet",
        //		string[OPT_CODE]);
        return 0;
    }
    log_option("Adding option", string);
    memcpy(optionptr + end, string, string[OPT_LEN] + 2);
    optionptr[end + string[OPT_LEN] + 2] = DHCP_END;
    return string[OPT_LEN] + 2;
}


/* add a one to four byte option to a packet */
int add_simple_option(__u8 *optionptr, __u8 code, __u32 data)
{
    const struct dhcp_option *dh;

    for (dh = dhcp_options; dh->code; dh++)
    {
        if (dh->code == code)
        {
            __u8 option[6], len;

            option[OPT_CODE] = code;
            len = dhcp_option_lengths[dh->flags & TYPE_MASK];
            option[OPT_LEN] = len;
            if (0)
                data <<= 8 * (4 - len);
            /* Assignment is unaligned! */
            move_to_unaligned32(&option[OPT_DATA], data);
            return add_option_string(optionptr, option);
        }
    }

    //bb_error_msg("can't add option 0x%02x", code);
    return 0;
}

