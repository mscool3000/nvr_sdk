#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "nc_nvr_sdk.h"


#define STATICIP "172.16.171.80"

int netcore_wps(int enable)
{
    int ret;

    ret = nc_nvr_set_broadcast(enable);
    if(ret < 0)
    {
        printf("set broadcast failed!\n");
        return -1;
    }
    sleep(10);
//	ret = nc_nvr_set_wps(enable);
//	if(ret < 0)
//	{
//		printf("set wps failed!\n");
//		return -1;
//	}
//	sleep(20);
    ret = nc_nvr_set_wps_pbc();
    if(ret < 0)
    {
        printf("set pbc failed!\n");
        return -1;
    }

    return 0;
}
int Print(nc_net_info_st *info)
{
    printf("version:               %s\n",info->soft_version);
    printf("-------------------------WLAN BEGIN----------------------------\n");
    printf("connected:               %s\n",info->wlan_info_st.connected);
    printf("access mode:            %s\n",info->wlan_info_st.access_mode);
    printf("conntype:               %s\n",info->wlan_info_st.conntype);
    printf("ip:                     %s\n",info->wlan_info_st.ip);
    printf("mask:                   %s\n",info->wlan_info_st.mask);
    printf("gw:                     %s\n",info->wlan_info_st.gw);
    printf("    ################pppoe##############     \n");
    printf("pppoe username:         %s\n",info->wlan_info_st.pppoe_username);
    printf("pppoe password:         %s\n",info->wlan_info_st.pppoe_pwd);
    printf("pppoe service name:     %s\n",info->wlan_info_st.pppoe_service_name);
    printf("pppoe agent client name:%s\n",info->wlan_info_st.pppoe_ac_name);
    printf("pppoe connect mode:     %s\n",info->wlan_info_st.ppp_connect_mode);
    printf("pppoe time:             %s\n",info->wlan_info_st.ppp_time);
    printf("    ################static##############     \n");
    printf("wan ip:                 %s\n",info->wlan_info_st.wan_ip);
    printf("wan mask:               %s\n",info->wlan_info_st.wan_mask);
    printf("wan gw:                 %s\n",info->wlan_info_st.wan_gw);
    printf("dns1:                   %s\n",info->wlan_info_st.dns_a);
    printf("dns2:                   %s\n",info->wlan_info_st.dns_b);
    printf("wlan mac:               %s\n",info->wlan_info_st.wan_mac);
    printf("-------------------------WLAN END----------------------------\n");
    printf("\n\n");
    printf("-------------------------LAN BEGIN---------------------------\n");
    printf("lan ip:                 %s\n",info->lan_info_st.lan_ip);
    printf("lan mask:               %s\n",info->lan_info_st.lan_mask);
    printf("lan mac:                %s\n",info->lan_info_st.lan_mac);
    printf("-------------------------LAN END----------------------------\n");
    printf("\n\n");
    printf("----------------------WIRELESS BEGIN------------------------\n");
    printf("wireless enable:        %s\n",info->wireless_info_st.wl_enable);
    printf("ssid:                   %s\n",info->wireless_info_st.ssid);
    printf("wireless stand:         %s\n",info->wireless_info_st.wl_stand);
    printf("net mode:               %s\n",info->wireless_info_st.net_mode);
    printf("wireless config:        %s\n",info->wireless_info_st.wl_config);
    printf("wireless mac:           %s\n",info->wireless_info_st.wl_mac);
    printf("ssid broad:             %s\n",info->wireless_info_st.ssid_broad);
    printf("channel width:          %s\n",info->wireless_info_st.channel_width);
    printf("channel bind:           %s\n",info->wireless_info_st.channel_bind);
    printf("region:                 %s\n",info->wireless_info_st.region);
    printf("channel:                %s\n",info->wireless_info_st.channel);
    printf("type:                   %s\n",info->wireless_info_st.net_type);
    printf("sec mode:               %s\n",info->wireless_info_st.sec_mode);
    printf("key type:               %s\n",info->wireless_info_st.key_type);
    printf("password:               %s\n",info->wireless_info_st.pwd);
    printf("key time:               %s\n",info->wireless_info_st.key_time);
    printf("user num:               %d\n",info->wireless_info_st.user_num);

    int i = 0;
    printf("\n");
    for(i = 0; i < info->wireless_info_st.user_num; i++)
    {
        printf("     ################WIFI LIST %d BEGIN##############     \n",i);
        printf("id:             %s\n",info->wireless_info_st.list[i].id);
        //printf("host:           %s\n",info->wireless_info_st.list[i].host);
        printf("mode:           %s\n",info->wireless_info_st.list[i].mode);
        printf("tx_pack:        %s\n",info->wireless_info_st.list[i].tx_pack);
        printf("rc_pack:        %s\n",info->wireless_info_st.list[i].rx_pack);
        printf("signal_strength:%s\n",info->wireless_info_st.list[i].signal_strength);
        printf("mac:            %s\n",info->wireless_info_st.list[i].user_mac);
        //printf("%s\n",info->wireless_info_st.list[i].link_time);
        printf("     ################WIFI LIST %d END###############     \n",i);
    }
    printf("----------------------WIRELESS END------------------------\n");
    printf("\n");
    printf("-----------------------DHCP BEGIN-------------------------\n");
    printf("dhcp enable:     %s\n",info->dhcp_server_info_st.dhcp_enable);
    printf("dhcp start ip:   %s\n",info->dhcp_server_info_st.dhcp_start_ip);
    printf("dhcp end ip:     %s\n",info->dhcp_server_info_st.dhcp_end_ip);
    printf("dhcp time:       %s\n",info->dhcp_server_info_st.dhcp_time);
    printf("-----------------------DHCP END---------------------------\n");

    if(1==atoi(info->dhcp_server_info_st.dhcp_enable))
    {
        printf("----------------------DHCP CLIENT LIST BEGIN------------------------\n");
        printf("dhcp client num:     %d\n",info->dhcp_client_num);
        for(i = 0; i < info->dhcp_client_num; i++)
        {
            printf("dhcp client ip:           %s\n",info->dh_list[i].ip);
            printf("dhcp client mac:          %s\n",info->dh_list[i].mac);
            printf("dhcp client status:       %s\n",info->dh_list[i].status);
            printf("dhcp client reserved:     %s\n",info->dh_list[i].reserved);
            printf("dhcp client host:         %s\n",info->dh_list[i].host);
        }
        printf("----------------------DHCP CLIENT LIST END--------------------------\n");
    }
    printf("-----------------------WPS BEGIN---------------------------\n");
    printf("wps endble:      %s\n",info->wps_info_st.wps_enable);
    /*
    	if(1== atoi(info->wps_info_st.wps_enable))
    	{
    		printf("wps_mode:     %s\n",info->wps_info_st.wps_mode);
    		if(strcmp(info->wps_info_st.wps_mode,"pin") == 0)
    			printf("pin host:     %s\n",info->wps_info_st.pin_host);
    	}
    */
    printf("-----------------------WPS END----------------------------\n");

    printf("\n");
    return 0;
}
/*
	setip 0 static_ip mask gw_ip dns1 dns2  设置为静态ip                                  setip 0 "172.16.171.80" "255.255.255.0" "172.16.171.1" "192.168.2.1" "61.139.2.69"
	setip 1                                 设置为dhcp                                    setip 1
	setip 2 pppoe_name pppoe_pw             设置为 pppoe                                  setip 2 "123" "123"
	setip 3 开启/关闭                       开启wps选项                                   setip 3  1 或者 setip 3 0
	setip 4 开启/关闭                       开启pbc选项                                   setip 4  1 或者 setip 4 0
	setip 5 频道号                          设置频道channel                               setip 5  0～9
	setip 6 开启/关闭                       打开广播                                      setip 6  1 或者 setip 6 0
	setip 7 开启/关闭                       开启wps功能（开启了广播，wps选项和pbc选项）   setip 7  1 或者 setip 7 0
	setip 其他                              查看AP所有的设置信息                          setip 9

*/
int main(int argc,char *argv[])
{
    int ret = 0;
    char ip[16] = {0};
    nc_net_info_st info;

    memset(&info,0,sizeof(info));

    if(argc < 2)
    {
        printf("Uarge:setip 0--9\n\t****0 is static ip****\t\n\t****   1 is dhcp  ****\t\n\t****   2 is pppoe **** \
			                    \t\n\t****3 is wps enable****\t\n\t****  4 is pbc **** \t\n\t****  5 is channel ****\
					\t\n\t****  6 is broadcast ****\t\n\t****  7 is wps ****\t\n\t****  other number is get net info ****\t\n\t\n");
        return -1;
    }
    switch(atoi(argv[1]))
    {
    case 0:
        //ret = nc_nvr_set_static_mod(STATICIP,"255.255.255.0","172.16.171.1","192.168.2.1","61.139.2.69");
        ret = nc_nvr_set_static_mod(argv[2],argv[3],argv[4],argv[5],argv[6]);
        if(ret < 0)
        {
            printf("set static failed!\n");
            return -1;
        }
        break;
    case 1:
        ret = nc_nvr_set_dhcp_mod(atoi(argv[2]),argv[3],argv[4]);
        if(ret < 0)
        {
            printf("set dhcp mode failed!\n");
            return -1;
        }
        break;
    case 2:
        //ret = nc_nvr_set_pppoe_mod("123","123",0,0);
        ret = nc_nvr_set_pppoe_mod(argv[2],argv[3],0,0,0,NULL,NULL);
        if(ret < 0)
        {
            printf("set pppoe failed!\n");
            return -1;
        }
        break;
    case 3:
        ret = nc_nvr_set_wps(atoi(argv[2]));
        if(ret < 0)
        {
            printf("set wps failed!\n");
            return -1;
        }
        break;
    case 4:
        ret = nc_nvr_set_wps_pbc();
        if(ret < 0)
        {
            printf("set pbc failed!\n");
            return -1;
        }
        break;
    case 5:
        ret = nc_nvr_set_channel(atoi(argv[2]));
        if(ret < 0)
        {
            printf("set channel failed!\n");
            return -1;
        }
        break;
    case 6:
        ret = nc_nvr_set_broadcast(atoi(argv[2]));
        if(ret < 0)
        {
            printf("set broadcast failed!\n");
            return -1;
        }
        break;
    case 7:
        ret = netcore_wps(1);
        if(ret < 0)
        {
            printf("set ss wps failed!\n");
            return -1;
        }
        break;
    case 8:
        ret = nc_nvr_set_ssid(argv[2]);
        if(ret < 0)
        {
            printf("set ssid failed!\n");
            return -1;
        }
        break;
    case 9:
        ret = nc_nvr_set_password(argv[2]);
        if(ret < 0)
        {
            printf("set password failed!\n");
            return -1;
        }
        break;
    case 10:
        while(1)
        {

            ret = nc_nvr_get_net_info(&info);
            Print(&info);
            sleep(3);
        }
    case 11:
        //nc_nvr_set_server_ip(argv[2]);
        break;
    case 12:
        //nc_nvr_get_server_ip(ip);
        printf("ip == %s\n",ip);
        break;
    case 13:
        nc_nvr_set_channel_and_region(atoi(argv[2]),argv[3],WIFI_TYPE_5G);
        break;
    case 14:
        nc_nvr_ap_reboot();
        break;
    case 15:
        nc_nvr_set_channel_and_region(atoi(argv[2]),argv[3],WIFI_TYPE_2POINT4G
                                     );
        break;
    case 16:
        nc_nvr_set_channel_width(atoi(argv[2]),WIFI_TYPE_5G);
        break;

    default:
        printf("get net info!!!\n");
        ret = nc_nvr_get_net_info(&info);
        printf("ret = %d\n",ret);
        Print(&info);
        break;
    }
    return 0;
}
