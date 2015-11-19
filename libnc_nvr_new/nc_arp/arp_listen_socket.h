#ifndef ARP_LISTEN_SOCKET_H
#define ARP_LISTEN_SOCKET_H 1

int
arp_ListenProbeSocketSet(
    char *sNetcardname,
    char *sIP,
    int  *piSockfd
);


#endif
