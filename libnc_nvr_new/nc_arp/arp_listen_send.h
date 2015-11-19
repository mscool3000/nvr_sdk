#ifndef ARP_LISTEN_SEND_H
#define ARP_LISTEN_SEND_H 1

int
arp_ListenMulticastSend(
    int  iSockfd
);

int
arp_ListenArpReqSend(
    int   iPortID,
    char  *sDstIP
);

#endif
