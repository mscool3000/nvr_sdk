#ifndef nc_dhcpd_h
#define nc_dhcpd_h 1

#define NC_NET_MAX_STATIC_NIP 9 // 最大静态IP数量

struct __nc_info
{
    unsigned char hwaddr[6]; // IPC MAC
    unsigned short port_id;	 // NVR 端口号
    unsigned int client_ip;	 // IPC IP
};

//typedef int (*discover_one_ipc)(struct __nc_info* pinfo);

int nc_dhcp_net_init(int fd, const int max_lan_ip, int bwireless);

int nc_dhcp_run();

int nc_dhcp_net_uninit();

int __nc_nvr_list_static(struct __nc_info *infos, int info_size);
int __nc_nvr_add_static_nip(unsigned char *mac, unsigned int ip);
int __nc_nvr_mod_static_nip(unsigned char *mac, unsigned int ip);
int __nc_nvr_del_static_nip(unsigned char *mac);
int __nc_nvr_clr_static_nip();

int get_nc_nvr_max_lan_nip();

#endif
