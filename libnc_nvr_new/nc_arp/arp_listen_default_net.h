#ifndef NC_LIATEN_DEFAULT_NET_H
#define NC_LIATEN_DEFAULT_NET_H 1

int
arp_ListenDefaultAddressGet(
    const char *sNetcard,
    char       *sIP,
    char       *sPeer
);

int
arp_ListenDefaultNetcardJudge(
    char *sNetcard
);

int
arp_ListenDefaultNetcardPortIDGet(
    const char *sNetcard,
    int        *piPortID
);

int
arp_ListenDefaultNetcardNameGet(
    int  iPortID,
    char *sNetcard
);

int
arpListenDefaultNetcardNumberGet(
    void
);

#endif
