#ifndef __NC_NVR_SDK_H__BY_SONGTAO_2013_12_24__
#define __NC_NVR_SDK_H__BY_SONGTAO_2013_12_24__

#ifndef __KERNEL__
#include <linux/types.h>
#include <linux/if_ether.h>
#endif

#include <time.h>

struct nc_info
{
    __u8 hwaddr[ETH_ALEN];
    __s16 port_id;
    __u32 client_ip;
    int   is_lost;
};


#define SDK_MAP_STATE_IPC_UNCONNECT    0        //无法连接IPC
#define SDK_MAP_STATE_IPC_CONNECT      1        //连接上IPC
#define SDK_MAP_STATE_IPC_PREPARE_RTSP 2        //准备探测IPC
#define SDK_MAP_STATE_IPC_NEW_DHCP     3        //还未获取到IPC

#define SDK_MAP_WAIT_TIME_MAX  6000
#define SDK_MAP_WAIT_TIME_MIN  2

typedef struct tagSDK_IPC_INFO
{
    char             cHwaddr[6];                     //IPC MAC 地址
    unsigned char    ucState;                        //IPC 状态
    unsigned char    ucRes;
    char             sName[32];                      //IPC状态
    char             sHardware[64];                  //IPC硬件类型信息
    unsigned short   usSwitchPort;                   //IPC 交换端口
    unsigned short   usHttpPort;                     //IPC http端口
    unsigned int     uiClientIP;                     //IPC 的IP地址
    unsigned int     usExistTime;                    //IPC 存活时间  暂时没用
    time_t           tStartTime;                     //IPC 被发现的时间 暂时没用
    struct tagSDK_IPC_INFO *pStruNext;               //下一个IPC,主要用于无;
    struct tagSDK_IPC_INFO *pStruCurNext;
    struct tagSDK_IPC_INFO *pStruCurPrev;
} SDK_IPC_INFO, *PSDK_IPC_INFO;



#define WIFILISTMAX 50
#define DHCPLISTMAX 50

typedef enum
{
        WIFI_TYPE_2POINT4G,
        WIFI_TYPE_5G,
        WIFI_TYPE_MAX
}WIFI_TYPE_EN;
typedef enum
{
	CHANNEL_WIDTH_TWENTY,
	CHANNEL_WIDTH_FORTY,
	CHANNEL_WIDTH_ENGHTY,
	CHANNEL_WIDTH_MAX
}CHANNEL_WIDTH_EN;

typedef	struct wifi_list
{
    char id[5];
//	char host[50];
    char mode[20];
    char tx_pack[20];
    char rx_pack[20];
    char signal_strength[5];
    char user_mac[18];
//	char link_time[20];
} wifi_list_st;

typedef struct dhcp_list
{
    char ip[17];
    char mac[18];
    char status[2];
    char reserved[20];
    char host[50];
} dhcp_list_st;

typedef struct nc_net_info
{
    char soft_version[50];
    struct wlan_info
    {
        char connected[2];
        char access_mode[2];
        char conntype[2];
        char ip[17];
        char mask[17];
        char gw[17];
        char wan_mac[18];
        //pppoe
        char pppoe_username[50];
        char pppoe_pwd[50];
        char pppoe_service_name[50];
        char pppoe_ac_name[50];
        char ppp_connect_mode[2];
        char ppp_time[5];
        //static
        char wan_ip[17];
        char wan_mask[17];
        char wan_gw[17];

        char dns_a[17];
        char dns_b[17];

    } wlan_info_st;
    struct lan_info
    {
        char lan_ip[17];
        char lan_mask[17];
        char lan_mac[18];
    } lan_info_st;
    struct wireless_info
    {
        char wl_enable[2];
        char ssid[50];
        char wl_stand[10];
        char net_mode[2];
        char wl_config[2];
        char wl_mac[18];
        char ssid_broad[2];
        char channel_width[2];
        char channel_bind[2];
        char region[2];
        char channel[5];
        char net_type[2];
        char sec_mode[2];
        char key_type[2];
        char pwd[50];
        char key_time[10];

        int user_num;
        wifi_list_st list[WIFILISTMAX];
    } wireless_info_st;
    struct dhcp_server_info
    {
        char dhcp_enable[2];
        char dhcp_start_ip[17];
        char dhcp_end_ip[17];
        char dhcp_time[10];
    } dhcp_server_info_st;

    int dhcp_client_num;
    dhcp_list_st dh_list[DHCPLISTMAX];
    struct wps_info
    {
        char wps_enable[2];
        char wps_mode[20];
        char pin_host[50];
    } wps_info_st;
} nc_net_info_st;
#ifndef __KERNEL__

#define NC_FALSE 0
#define NC_TRUE 1
#define NC_INVALID_HANDLE ((unsigned long)-1)

typedef unsigned long NC_HANDLE;
typedef void NC_VOID;
#ifdef  NC_BOOL
#undef NC_BOOL
#endif
typedef int NC_BOOL;

int nc_nvr_sdk_init(const int max_lan_nip, int bwireless, char *tmpdir);
int nc_nvr_sdk_uninit();

NC_HANDLE nc_nvr_create();
NC_VOID nc_nvr_destroy(NC_HANDLE h);
int nc_nvr_getfd(NC_HANDLE h);
NC_BOOL nc_nvr_get_ipc(NC_HANDLE h, struct nc_info *ipc);
int nc_nvr_list_ipcs(NC_HANDLE h, struct nc_info *infos, int info_size);
int nc_nvr_list_static(NC_HANDLE h, struct nc_info *infos, int info_size);
NC_BOOL nc_nvr_add_static_nip(NC_HANDLE h, __u8 *mac, __u32 ip);
NC_BOOL nc_nvr_mod_static_nip(NC_HANDLE h, __u8 *mac, __u32 ip);
NC_BOOL nc_nvr_del_static_nip(NC_HANDLE h, __u8 *mac);
NC_BOOL nc_nvr_clr_static_nip(NC_HANDLE h);
NC_BOOL nc_nvr_get_ipc2(NC_HANDLE hHandle, SDK_IPC_INFO *pStruIPC );
int nc_nvr_list_ipcs2(NC_HANDLE hHandle, int iWaitTime, SDK_IPC_INFO *pStruInfo, int iInfoSize);



int nc_nvr_set_dhcp_mod(int dhcpDns_enable,char *dns_a,char *dns_b);
int nc_nvr_set_static_mod(char *staticIp,char *staticMask,char *staticGw,char *dns_a,char *dns_b);
int nc_nvr_set_pppoe_mod(char *pppoeId,char *pppoePw,int pppoeMod,int time,
                         int pppoeDns_enable,char *dns_a,char *dns_b);
int nc_nvr_set_broadcast(unsigned int enable);
int nc_nvr_set_wps(unsigned int enable);
int nc_nvr_set_wps_pbc(void);
int nc_nvr_set_channel(unsigned int channel);
int nc_nvr_set_channel_and_region(unsigned int channel,char *region,WIFI_TYPE_EN type);
int nc_nvr_get_net_info(nc_net_info_st *info);

int nc_nvr_set_ssid(char *ssid);
int nc_nvr_set_password(char *password);

int nc_nvr_ap_reboot();

int nc_nvr_set_nvr_devinfo(char *jaIp,char *eseeId,char *port,char *httpPort,char *maxChannel);
int nc_nvr_set_rw_dir(char *dir_name);
int nc_nvr_set_channel_width(CHANNEL_WIDTH_EN width,WIFI_TYPE_EN type);

#endif

#endif
