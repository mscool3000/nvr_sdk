#ifndef ST_ARP_H
#define ST_ARP_H 1

struct nc_new_info
{
    unsigned char hwaddr[6]; // IPC MAC
    unsigned short port_id;	 // NVR ¶Ë¿ÚºÅ
    unsigned int client_ip;	 // IPC IP
    int is_lost;
};



int nc_ipcs_table_init(
    int dhcp_fd,
    int get_fd,
    int wire_cnt,
    int wireless_enable
);

int nc_ipcs_table_uninit( void );

int __nc_nvr_get_ipc(int fd, struct nc_new_info *ipc);

int ipcs_table_list_ipcs(struct nc_info *infos, int info_size);
int ipcs_table_manual_refresh(int wait_ms);

#endif
