#include "arp_listen_comm.h"

static int
arp_ListenProbeSockfdCreate(
    int  *piSockfd
)
{
    int iSockfd = 0;

    if(	!piSockfd )
    {
        return ARP_LISTEN_OK;
    }

    (*piSockfd) = socket(AF_INET, SOCK_DGRAM, 0);
    if( *piSockfd < 0 )
    {
        ARP_ERR( "socket" );
        return ARP_LISTEN_ERR;
    }

    return ARP_LISTEN_OK;
}

int
arp_ListenProbeSockfdBind(
    char *sIP,
    int  iSockfd
)
{
    int iRet = 0;
    int iSize = 0;
    struct sockaddr_in struAddr;

    memset( &struAddr, 0, sizeof(struAddr) );
    struAddr.sin_family = AF_INET;
    struAddr.sin_port = htons(3702);
    struAddr.sin_addr.s_addr = inet_addr(sIP);
    ARP_DBG( "sIP = %s\n", sIP );
    iSize = sizeof(struAddr);

    iRet = bind(
               (iSockfd),
               (struct sockaddr*)&struAddr,
               sizeof(struAddr)
           );
    if( iRet == -1 )
    {
        ARP_ERR( "bind" );
        return ARP_LISTEN_ERR;
    }

    return ARP_LISTEN_OK;
}

static int
arp_ListenProbeSockfdOptSet(
    int  iSockfd,
    char *sName
)
{
    int i = 1;
    int iRet = 0;
    struct ifreq struReq;

    iRet = setsockopt(
               iSockfd,
               SOL_SOCKET,
               SO_REUSEADDR,
               &i,
               sizeof(i)
           );
    if( iRet < 0 )
    {
        return ARP_LISTEN_ERR;
    }

    memset( &struReq, 0, sizeof(struReq) );
    memcpy( struReq.ifr_name, sName, strlen(sName) );
    ARP_DBG( "sName = %s\n", sName );
    iRet = setsockopt(
               iSockfd,
               SOL_SOCKET,
               SO_BINDTODEVICE,
               (char *)&struReq,
               sizeof(struReq)
           );
    if( iRet < 0 )
    {
        ARP_ERR( "setsockopt SO_BINDTODEVICE err: " );
        return ARP_LISTEN_OK;
    }

    return ARP_LISTEN_OK;
}

static int
arp_ListenProbeSocketParamSet(
    int  iSockfd,
    char *sNetcardname,
    char *sIP
)
{
    int iRet = 0;

    iRet = arp_ListenProbeSockfdOptSet(
               (iSockfd),
               sNetcardname
           );
    if( iRet != ARP_LISTEN_OK )
    {
        return iRet;
    }
    iRet = arp_ListenProbeSockfdBind(
               sIP,
               (iSockfd)
           );
    if( iRet != ARP_LISTEN_OK )
    {
        return iRet;
    }

    return iRet;
}

int
arp_ListenProbeSocketSet(
    char *sNetcardname,
    char *sIP,
    int  *piSockfd
)
{
    int iRet = 0;

    iRet = arp_ListenProbeSockfdCreate( piSockfd );
    if( iRet != ARP_LISTEN_OK )
    {
        return iRet;

    }
    iRet = arp_ListenProbeSocketParamSet( (*piSockfd), sNetcardname, sIP );
    if( iRet == ARP_LISTEN_OK )
    {
        return iRet;

    }
    return iRet;
}

