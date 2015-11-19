#include "arp_listen_comm.h"
#include "arp_listen_default_net.h"
#include "arp_listen_send.h"
#include "arp_listen_socket.h"
#include "nc_nvr_sdk.h"
#include "st_arp.h"
#include "nc_dhcp.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define NC_DEBUG 1

#ifndef st_dbg
#if NC_DEBUG == 1
#define st_dbg(format, args...) \
            printf("[%05d:%s]"format"\n", \
            __LINE__, \
            __FUNCTION__, \
            ##args)
#else
#define st_dbg(format, args...)
#endif
#endif



#define NC_FD_IDLE         0
#define NC_FD_PEER_CLOSE  1
#define NC_FD_NORMAL       2

struct nc_fd
{
    int iFd;
    int iFlag;
};

struct nc_sdk_handle
{
    int iUserFd[2];				/* 用于和用户通信的文件描述符, 1可以返回给用户 */
    int iDhcpFd[2]; 				/* 用于和dhcp通信的文件描述符, 1可以传递给dhcp模块 */
};

typedef int nc_nvr_recv( int iPortID, int iFd, struct nc_info *pStruInfo );

static struct nc_sdk_handle gStruSdkHandle;
static int  giInitFlag = 0;
char g_tmpdir[256] = {0};

int nc_nvr_sdk_init(const int max_lan_nip, int bwireless, char *tmpdir)
{
    struct stat st;
    int iRet = 0;

    if( giInitFlag == 1 )
    {
        return NC_TRUE;

    }

    if (!tmpdir)
    {
        return NC_FALSE;
    }

    memset(&st, 0, sizeof(st));
    iRet = stat(tmpdir, &st);
    if (iRet < 0)
    {
        return NC_FALSE;
    }
    else
    {
        if (!S_ISDIR(st.st_mode))
        {
            fprintf(stderr, "%s isn't a director!!!\n", tmpdir);
            return NC_FALSE;
        }
    }

    strcpy(g_tmpdir, tmpdir);

    memset( &gStruSdkHandle, 0, sizeof(gStruSdkHandle) );

    iRet = socketpair( AF_UNIX, SOCK_STREAM, 0, gStruSdkHandle.iUserFd);
    if( iRet < 0 )
    {
        perror( "socketpair userfd error: " );
        return NC_FALSE;

    }

    iRet = socketpair( AF_UNIX, SOCK_STREAM, 0, gStruSdkHandle.iDhcpFd );
    if( iRet < 0 )
    {
        perror( "socketpair dhcpfd error: " );
        return NC_FALSE;
    }
    st_dbg( "\n" );

    iRet = nc_dhcp_net_init(gStruSdkHandle.iDhcpFd[1], max_lan_nip, bwireless);
    if( iRet == 0 )
    {
        st_dbg( "nc_dhcp_netinit error \n" );
        return NC_FALSE;
    }
    st_dbg( "\n" );
    iRet = nc_ipcs_table_init(gStruSdkHandle.iDhcpFd[0], gStruSdkHandle.iUserFd[1], max_lan_nip, bwireless );
    if( iRet != 0 )
    {

        st_dbg( "nc_iptable_init error\n" );
        return NC_FALSE;
    }
    st_dbg( "\n" );
    nc_dhcp_run();
    st_dbg( "\n" );
    return NC_TRUE;
}

int
nc_nvr_sdk_uninit(
    void
)
{
    nc_ipcs_table_uninit();
    nc_dhcp_net_uninit();
    return NC_TRUE;
}

NC_HANDLE
nc_nvr_create(
    void
)
{
    NC_HANDLE struHandle;

    struHandle = (unsigned long)&gStruSdkHandle;

    return struHandle;
}

NC_VOID
nc_nvr_destroy(
    NC_HANDLE h
)
{
    struct nc_sdk_handle *pStruHandle = NULL;

    pStruHandle = (struct nc_sdk_handle *)h;
    if( pStruHandle->iDhcpFd[0] > 0 )
    {
        close( pStruHandle->iDhcpFd[0] );
        pStruHandle->iDhcpFd[0] = -1;
    }
    if( pStruHandle->iDhcpFd[1] > 0 )
    {
        close( pStruHandle->iDhcpFd[1] );
        pStruHandle->iDhcpFd[1] = -1;
    }
    if( pStruHandle->iUserFd[0] > 0 )
    {
        close( pStruHandle->iUserFd[0] );
        pStruHandle->iUserFd[0] = -1;
    }
    if( pStruHandle->iUserFd[1] > 0 )
    {
        close( pStruHandle->iUserFd[1] );
        pStruHandle->iUserFd[1] = -1;
    }
}

int
nc_nvr_getfd(
    NC_HANDLE struHandle
)
{

    struct nc_sdk_handle *pStruHandle = NULL;

    pStruHandle = (struct nc_sdk_handle *)struHandle;

    return pStruHandle->iUserFd[0];
}

int
nc_nvr_get_ipc(
    NC_HANDLE struHandle,
    struct nc_info *pStruInfo
)
{
    int iRet = 0;
    int iUserFd = 0;
    struct nc_sdk_handle *pStruHandle = NULL;
    struct nc_new_info struNewInfo;

    if( struHandle != (NC_HANDLE)&gStruSdkHandle )
    {
        return NC_FALSE;
    }

    pStruHandle = (struct nc_sdk_handle *)struHandle;
    memset( &struNewInfo, 0, sizeof(struNewInfo) );
    if( pStruHandle->iUserFd[0] > 0 )
    {
        iRet = __nc_nvr_get_ipc( pStruHandle->iUserFd[0], &struNewInfo );
        if( iRet == 0 )
        {

            pStruInfo->client_ip = struNewInfo.client_ip;
            pStruInfo->port_id   = struNewInfo.port_id;
            pStruInfo->is_lost   = struNewInfo.is_lost;
            memcpy( pStruInfo->hwaddr, struNewInfo.hwaddr, 6 );
            return NC_TRUE;
        }

    }

    return NC_FALSE;
}

int
nc_nvr_list_ipcs(
    NC_HANDLE 	    struHandle,
    struct nc_info *infos,
    int             info_size
)
{
    int ret = -1;

    ret = ipcs_table_manual_refresh(2000);
    if (ret < 0)
    {
        return -1;
    }

    return ipcs_table_list_ipcs(infos, info_size);
}

int nc_nvr_list_static(NC_HANDLE hHandle,struct nc_info *infos, int info_size)
{
    struct __nc_info tmp_infos[NC_NET_MAX_STATIC_NIP];
    int iNum = info_size;
    int i=0;
    if( hHandle != (NC_HANDLE)(&gStruSdkHandle)
      )
    {
        return -1;
    }

    memset(tmp_infos,0,sizeof(tmp_infos));

    iNum = __nc_nvr_list_static(tmp_infos,info_size);
    if (0 >= iNum)
        return iNum;

    for(i = 0; i!=iNum; ++i)
    {
        infos[i].client_ip = tmp_infos[i].client_ip;
        infos[i].port_id = tmp_infos[i].port_id;
        memcpy(infos[i].hwaddr,tmp_infos[i].hwaddr,6);
    }

    return iNum;
}

NC_BOOL nc_nvr_add_static_nip(NC_HANDLE hHandle,unsigned char *mac, unsigned int ip)
{
    if( hHandle != (NC_HANDLE)(&gStruSdkHandle)
      )
    {
        return NC_FALSE;
    }

    if(__nc_nvr_add_static_nip(mac, ip))
    {
        return NC_FALSE;
    }

    return NC_TRUE;
}

NC_BOOL nc_nvr_mod_static_nip(NC_HANDLE hHandle,unsigned char *mac, unsigned int ip)
{
    if( hHandle != (NC_HANDLE)(&gStruSdkHandle)
      )
    {
        return NC_FALSE;
    }

    if(__nc_nvr_mod_static_nip(mac, ip))
    {
        return NC_FALSE;
    }

    return NC_TRUE;
}

NC_BOOL nc_nvr_del_static_nip(NC_HANDLE hHandle,unsigned char *mac)
{
    if( hHandle != (NC_HANDLE)(&gStruSdkHandle)
      )
    {
        return NC_FALSE;
    }

    if(__nc_nvr_del_static_nip(mac))
    {
        return NC_FALSE;
    }

    return NC_TRUE;
}

NC_BOOL nc_nvr_clr_static_nip(NC_HANDLE hHandle)
{
    if( hHandle != (NC_HANDLE)(&gStruSdkHandle)
      )
    {
        return NC_FALSE;
    }

    if(__nc_nvr_clr_static_nip())
    {
        return NC_FALSE;
    }

    return NC_TRUE;
}



