#include "arp_listen_comm.h"

typedef struct tagARP_LISTEN_DEFAULTNET
{
    char *sNetcard;
    char *sIP;
    char *sPeer;
    int  iPortID;
} ARP_LISTEN_DEFAULTNET, *PARP_LISTEN_DEFAULT;

static ARP_LISTEN_DEFAULTNET gStruDefNet[] =
{
    {"eth0.3249", "172.25.123.1",  NULL,            -1},
    {"eth0.3200", "172.25.123.17", "172.25.123.18", 1},
    {"eth0.3201", "172.25.123.21", "172.25.123.22", 2},
    {"eth0.3202", "172.25.123.25", "172.25.123.26", 3},
    {"eth0.3203", "172.25.123.29", "172.25.123.30", 4},
    {"eth0.3204", "172.25.123.33", "172.25.123.34", 5},
    {"eth0.3205", "172.25.123.37", "172.25.123.38", 6},
    {"eth0.3206", "172.25.123.41", "172.25.123.42", 7},
    {"eth0.3207", "172.25.123.45", "172.25.123.46", 8}
};

int
arpListenDefaultNetcardNumberGet(
    void
)
{
    return 9;
}

static int
arp_ListenDefaultNetcardFind(
    const char            *sNetcard,
    ARP_LISTEN_DEFAULTNET **ppStruDef

)
{
    int i = 0;
    int iLen = 0, iLen2 = 0;
    int iNum = sizeof(gStruDefNet) / sizeof(gStruDefNet[0]);

    ARP_DBG( "\n" );

    iLen = strlen(sNetcard);
    for( ; i < iNum; i++ )
    {
        iLen2 = strlen(gStruDefNet[i].sNetcard);
        if( iLen == iLen2 &&
                !strncmp(gStruDefNet[i].sNetcard,sNetcard,iLen)
          )
        {
            (*ppStruDef) = &gStruDefNet[i];
            ARP_DBG( "\n" );
            return ARP_LISTEN_OK;
        }
    }
    ARP_DBG( "\n" );
    return ARP_LISTEN_ERR;
}

int
arp_ListenDefaultAddressGet(
    const char *sNetcard,
    char       *sIP,
    char       *sPeer
)
{
    int iRet = 0;
    int iLen2 = 0;
    ARP_LISTEN_DEFAULTNET *pStruDef = NULL;

    ARP_DBG( "\n" );
    iRet = arp_ListenDefaultNetcardFind(
               sNetcard,
               &pStruDef
           );
    if( iRet != ARP_LISTEN_OK )
    {
        return iRet;
    }

    if( pStruDef->sIP && sIP )
    {
        iLen2 = strlen(pStruDef->sIP);
        memcpy(sIP, pStruDef->sIP, iLen2);
    }
    if( pStruDef->sPeer &&  sPeer )
    {
        iLen2 = strlen(pStruDef->sPeer);
        memcpy(sPeer,pStruDef->sPeer, iLen2);
    }

    return ARP_LISTEN_OK;
}

int
arp_ListenDefaultNetcardJudge(
    char *sNetcard
)
{
    ARP_LISTEN_DEFAULTNET *pStruDef = NULL;

    return arp_ListenDefaultNetcardFind(
               sNetcard,
               &pStruDef
           );
}

int
arp_ListenDefaultNetcardPortIDGet(
    const char *sNetcard,
    int        *piPortID
)
{
    int iRet = 0;
    ARP_LISTEN_DEFAULTNET *pStruDef = NULL;

    iRet = arp_ListenDefaultNetcardFind(
               sNetcard,
               &pStruDef
           );
    if( iRet != ARP_LISTEN_OK ||
            !pStruDef
      )
    {
        return ARP_LISTEN_ERR;
    }

    (*piPortID) = pStruDef->iPortID;

    return ARP_LISTEN_OK;
}

static int
arp_ListenDefaultNetcardNameFind(
    int  iPortID,
    ARP_LISTEN_DEFAULTNET **ppStruDef
)
{
    int i = 0;
    int iNum = sizeof(gStruDefNet) / sizeof(gStruDefNet[0]);

    for( ; i < iNum; i++ )
    {
        if( iPortID == gStruDefNet[i].iPortID )
        {
            (*ppStruDef) = &gStruDefNet[i];
            return ARP_LISTEN_OK;
        }
    }

    return ARP_LISTEN_ERR;
}

int
arp_ListenDefaultNetcardNameGet(
    int  iPortID,
    char *sNetcard
)
{
    int iRet = 0;
    ARP_LISTEN_DEFAULTNET *pStruDef = NULL;

    iRet = arp_ListenDefaultNetcardNameFind(
               iPortID,
               &pStruDef
           );
    if( iRet != ARP_LISTEN_OK ||
            !pStruDef
      )
    {
        return ARP_LISTEN_ERR;
    }

    memcpy( sNetcard, pStruDef->sNetcard, strlen(pStruDef->sNetcard) );

    return ARP_LISTEN_OK;
}


