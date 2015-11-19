#include "arp_listen_comm.h"


static char *gsBuf = "<?xml version=\"1.0\" encoding=\"utf-8\"?><Envelope xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\" xmlns=\"http://www.w3.org/2003/05/soap-envelope\"><Header><wsa:MessageID xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">uuid:4bae0473-5b94-4fa9-95ba-d683a96a12f1</wsa:MessageID><wsa:To xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action></Header><Body><Probe xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><Types>dn:NetworkVideoTransmitter</Types><Scopes /></Probe></Body></Envelope>";

int
arp_ListenMulticastSend(
    int             iSockfd
)
{
    int iRet = 0;
    struct sockaddr_in struDst;

    memset( &struDst, 0, sizeof(struDst) );
    struDst.sin_family = AF_INET;
    struDst.sin_port = htons(3702);
    struDst.sin_addr.s_addr = inet_addr("239.255.255.250");

    iRet = sendto(
               iSockfd,
               gsBuf,
               strlen(gsBuf),
               0,
               (struct sockaddr*)&struDst,
               sizeof(struct sockaddr_in)
           );
    if( iRet < 0 )
    {
        return ARP_LISTEN_ERR;
    }

    return ARP_LISTEN_OK;
}

static int
__arp_ListenCardMacGet(
    int        iSockfd,
    const char *sName,
    char       *cMac
)
{
    int iRet = 0;
    struct ifreq struReq;

    memset( &struReq, 0, sizeof(struReq) );
    memcpy( struReq.ifr_name, sName, strlen(sName) );

    iRet = ioctl(iSockfd, SIOCGIFHWADDR, &struReq);
    if( iRet < 0 )
    {
        return ARP_LISTEN_ERR;
    }

    memcpy( cMac, struReq.ifr_hwaddr.sa_data, 6 );

    return ARP_LISTEN_OK;
}

static int
arp_ListenCardMacGet(
    const char *sName,
    char       *cMac
)
{
    int iRet = 0;
    int iSockfd = 0;

    iSockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if( iSockfd < 0 )
    {
        ARP_ERR( "socket error: " );
        return ARP_LISTEN_ERR;

    }
    iRet = __arp_ListenCardMacGet( iSockfd, sName, cMac );

    close( iSockfd );
    return iRet;
}

static void
arp_ListenArpPack(
    const char *cMac,
    const char *sSrcIP,
    const char *sDstIP,
    char       *cBuf
)
{
    int iSize = 0;
    unsigned int uiIPAddr = 0;
    char cBCMac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    struct ethhdr *pStruEth = NULL;
    struct arphdr *pStruArp = NULL;

    pStruEth = (struct ethhdr *)cBuf;
    memcpy(pStruEth->h_dest, cBCMac, 6);
    memcpy(pStruEth->h_source, cMac, 6);
    pStruEth->h_proto = htons(ETH_P_ARP);
    iSize = sizeof(struct ethhdr);

    pStruArp = pStruArp = (struct arphdr *)(cBuf + iSize);
    pStruArp->ar_hrd = htons(ARPHRD_ETHER);
    pStruArp->ar_pro = htons(ETH_P_IP);
    pStruArp->ar_hln = 6;
    pStruArp->ar_pln = 4;
    pStruArp->ar_op  = htons(ARPOP_REQUEST);

    iSize += sizeof(struct arphdr);
    memcpy(cBuf + iSize, cMac, 6);
    iSize += 6;
    uiIPAddr = inet_addr(sSrcIP);
    memcpy(cBuf + iSize, &uiIPAddr, 4);
    iSize += 4;
    iSize += 6;
    uiIPAddr = inet_addr(sDstIP);
    memcpy(cBuf + iSize, &uiIPAddr, 4);
}

static int
arp_ListenPackSend(
    int        iSockfd,
    const char *sName,
    const char *cMac,
    const char *cBuf
)
{
    int iRet = 0;
    struct sockaddr_ll  struSockAddr;

    memset( &struSockAddr, 0, sizeof(struSockAddr) );
    struSockAddr.sll_family = AF_PACKET;
    struSockAddr.sll_protocol = htons(ETH_P_ARP);
    struSockAddr.sll_ifindex = if_nametoindex( sName );
    struSockAddr.sll_halen = 6;
    memcpy(struSockAddr.sll_addr, cMac, 6);

    iRet = sendto(
               iSockfd,
               cBuf,
               sizeof(cBuf),
               0,
               (struct sockaddr*)&struSockAddr,
               sizeof(struSockAddr)
           );
    if( iRet < 0 )
    {
        ARP_ERR( "sendto" );
        return ARP_LISTEN_ERR;
    }
    return ARP_LISTEN_OK;
}

static int
__arp_ListenArpReqSend(
    int iSockfd,
    int iPortID,
    char *sDstIP
)
{
    int iRet = 0;
    char sSrcIP[16] = { 0 };
    char cMac[6] = { 0 };
    char sName[IFNAMSIZ] = { 0 };
    char cBuf[64] = { 0 };

    iRet = arp_ListenDefaultNetcardNameGet( iPortID, sName );
    if( iRet != ARP_LISTEN_OK )
    {
        return iRet;
    }
    iRet = arp_ListenDefaultAddressGet( sName, sSrcIP, NULL );
    if( iRet != ARP_LISTEN_OK )
    {
        return iRet;

    }
    iRet = arp_ListenCardMacGet( sName, cMac );
    if( iRet != ARP_LISTEN_OK )
    {
        return iRet;
    }

    arp_ListenArpPack( sSrcIP, cMac, sDstIP, cBuf );

    return arp_ListenPackSend( iSockfd, sName, cMac, cBuf );

}

int
arp_ListenArpReqSend(
    int   iPortID,
    char  *sDstIP
)
{
    int iRet = 0;
    int iSockfd = 0;

    iSockfd = socket( AF_PACKET, SOCK_RAW, htons(ETH_P_ARP) );
    if( iSockfd < 0 )
    {
        ARP_ERR( "socket error" );
        return ARP_LISTEN_ERR;
    }

    iRet = __arp_ListenArpReqSend( iSockfd, iPortID, sDstIP );

    close(iSockfd);
    return iRet;

}

