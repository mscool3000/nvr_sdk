#ifndef ARP_LISTEN_COMM_H
#define ARP_LISTEN_COMM_H 1

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>


#define ARP_LISTEN_OK              0
#define ARP_LISTEN_ERR             1
#define ARP_LISTEN_PASSWD_USER_ERR 2


#if 0
#define ARP_DBG(fmt, args...) fprintf(stderr, "[%s:%d] -- "fmt, __FUNCTION__, __LINE__, ##args)
#else
#define ARP_DBG(fmt, args...)
#endif

#define ARP_ERR(fmt) fprintf(stderr, "[%s:%d] --"fmt" %s\n", __FUNCTION__, __LINE__, strerror(errno))

#endif
