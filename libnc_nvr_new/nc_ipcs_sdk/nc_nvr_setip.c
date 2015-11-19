#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <linux/route.h>
#include <sys/ioctl.h>
//#include <setjmp.h>
#include "nc_nvr_sdk.h"
#include "nc_nvr_urlEncode.h"

#define CGISTRING_SETINFO "/cgi-bin-igd/netcore_set.cgi"
#define CGISTRING_GETINFO "/cgi-bin-igd/netcore_get.cgi"
#define HOST1 "172.20.14.1"
#define HOST2 "172.25.123.1"
#define DATAMAXLEN (1024)  //数据的buf最大长度
#define LIST_DATA__MAX (1024*10) //list数据映射到内存的最大长度
#define PACKET_SIZE 1024


//#define DHCPSTRING "mode_name=netcore_set&conntype=1&save_wan_set=undefined&wsc-config=1&wsc_config_by_ext_reg=0&wan_set=1&repeater_enable=0&rp_wl_enable=0&default_flag=1"
#define DHCPSTRING "mode_name=netcore_set&conntype=1&wan_set=1"


static int g_sockfd = 0;
static char can_rw_dir[256];

unsigned short nc_cal_chksum(unsigned short *addr, int len)
{
    int nleft=len;
    int sum=0;
    unsigned short *w=addr;
    unsigned short answer=0;
    while(nleft>1)
    {
        sum+=*w++;
        nleft-=2;
    }
    if( nleft==1)
    {
        *(unsigned char *)(&answer)=*(unsigned char *)w;
        sum+=answer;
    }
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    answer=~sum;
    return answer;
}

int nc_pack(void* _buf)
{
    int packsize;
    int datalen = 56;
    struct icmp *icmp;
    struct timeval *tval;
    icmp=(struct icmp*)_buf;
    icmp->icmp_type=ICMP_ECHO;
    icmp->icmp_code=0;
    icmp->icmp_cksum=0;
    icmp->icmp_seq=0;
    icmp->icmp_id=getpid();
    packsize = 8 + datalen;
    tval= (struct timeval *)icmp->icmp_data;
    gettimeofday(tval,NULL);
    icmp->icmp_cksum=nc_cal_chksum( (unsigned short *)icmp,packsize);
    return packsize;
}

int nc_unpack(char *buf,int len)
{
    int iphdrlen;
    struct ip *ip;
    struct icmp *icmp;
    ip=(struct ip *)buf;
    iphdrlen=ip->ip_hl<<2;
    icmp=(struct icmp *)(buf+iphdrlen);
    len-=iphdrlen;
    if(len<8)
    {
        printf("ICMP packets\'s length is less than 8\n");
        return -1;
    }
    if( (icmp->icmp_type==ICMP_ECHOREPLY) && (icmp->icmp_id==getpid()) )
    {
        return 0;
    }
    else
    {
        printf("Not my response\n");
        return -1;
    }
}

int set_gateway_ip(char *gateway)
{
    if(gateway == NULL)
    {
        return -1;
    }

    int fd = 0;
    int ret = 0;
    struct sockaddr_in sin;
    struct rtentry rt;

    fd = socket(AF_INET,SOCK_DGRAM,0);
    if(fd < 0)
    {
        return -1;
    }

    memset(&sin,0,sizeof(sin));
    memset(&rt,0,sizeof(rt));

    if((inet_aton(gateway,&sin.sin_addr)) < 0)
    {
        perror("inet_aton:");
        return -1;
    }
    sin.sin_family = AF_INET;
    sin.sin_port = 0;

    memcpy(&rt.rt_gateway,&sin,sizeof(sin));
    ((struct sockaddr_in *)&rt.rt_dst)->sin_family=AF_INET;
    ((struct sockaddr_in *)&rt.rt_genmask)->sin_family=AF_INET;
    rt.rt_flags = RTF_GATEWAY;

    if(ioctl(fd,SIOCADDRT,&rt) < 0)
    {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int get_local_ip(char *ifc,char *ip)
{

    if(ip == NULL)
    {
        return -1;
    }
    int sock_get_ip;
    char ipaddr[50];

    struct   sockaddr_in *sin;
    struct   ifreq ifr_ip;

    if ((sock_get_ip=socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("socket create failse...GetLocalIp!\n");
        return -1;
    }

    memset(&ifr_ip, 0, sizeof(ifr_ip));
    strncpy(ifr_ip.ifr_name, ifc, sizeof(ifr_ip.ifr_name) - 1);

    if( ioctl( sock_get_ip, SIOCGIFADDR, &ifr_ip) < 0 )
    {
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr_ip.ifr_addr;
    strcpy(ipaddr,inet_ntoa(sin->sin_addr));

    printf("local ip:%s\n",ipaddr);
    close( sock_get_ip );

    strcpy(ip,ipaddr);
    return 0;
}

int GetDhcpString(int dhcpDns_enable,char *dns_a,char *dns_b,char *string)
{
    if(dhcpDns_enable != 0 && dhcpDns_enable != 1)
        return -1;
    if(string == NULL)
        return -1;
    if(dhcpDns_enable == 0)
    {
        sprintf(string,"mode_name=netcore_set&conntype=1&dns_a=&dns_b=&wan_set=1");
    }
    else
    {
        if(dns_a == NULL && dns_b == NULL)
            return -1;
        sprintf(string,"mode_name=netcore_set&conntype=1&dns_a=%s&dns_b=%s&wan_set=1",dns_a,dns_b);
    }

    return 0;
}
int GetStaticString(char *staticIp,char *staticMask,char *staticGw,char* dns_a,char *dns_b,char *string)
{
    char dns1[50] = {0};
    char dns2[50] = {0};

    if(NULL == staticIp || NULL == staticMask || NULL == staticGw)
        return -1;


    if(NULL == dns_a)
    {
        memset(dns1,0,50);
        strcpy(dns1,"192.168.2.1");
    }
    else
    {
        strncpy(dns1,dns_a,50);
    }
    if(NULL == dns_b)
    {
        memset(dns2,0,50);
        strcpy(dns2,"61.139.2.69");
    }
    else
    {
        strncpy(dns2,dns_b,50);
    }
    if(NULL != string)
    {
        sprintf(string,"mode_name=netcore_set&conntype=0&wan_ip=%s&wan_mask=%s&wan_gw=%s&dns_a=%s&dns_b=%s&wan_set=1",staticIp,staticMask,staticGw,dns1,dns2);
    }
    else
        return -1;

    //printf("Static String:%s\n",string);
    return 0;
}
int GetPppoeString(char *pppoeId,char *pppoePw,int pppoeMode,int time,int pppoeDns_enable,char *dns_a,char *dns_b,char *string)
{
    if(NULL == pppoeId || NULL == pppoePw)
        return -1;
    if(strlen(pppoeId) > 127 || strlen(pppoePw) > 127)
    {
        printf("pppoeId or pppoePw too long!\n");
        return -1;
    }
    if(pppoeDns_enable != 0 && pppoeDns_enable != 1)
    {
        return -1;
    }

    int len = 0;
    char dns_str[256] = {0};

    len = strspn(pppoeId,"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~`！@#$%^&*()-_=+|{[]}:;<,.>?/");
    if(len != strlen(pppoeId))
    {
        printf("Cannot contain special characters\n");
        return -1;
    }
    len = strspn(pppoePw,"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~`！@#$%^&*()-_=+|{[]}:;<,.>?/");
    if(len != strlen(pppoePw))
    {
        printf("Cannot contain special characters\n");
        return -1;
    }
    char *name= NULL;
    char *passwd = NULL;
    int new_len = 0;
    name = nc_nvr_url_encode(pppoeId,strlen(pppoeId),&new_len);
    if(name == NULL)
        return -1;
    passwd = nc_nvr_url_encode(pppoePw,strlen(pppoePw),&new_len);
    if(passwd == NULL)
        return -1;
    int wrong_mod = 0;

    if(pppoeDns_enable == 0)
    {
        strcpy(dns_str,"&dns_a=&dns_b=");
    }
    else
    {
        if(dns_a == NULL && dns_b == NULL)
            return -1;
        sprintf(dns_str,"&dns_a=%s&dns_b=%s",dns_a,dns_b);
    }
    if(NULL != string)
    {
        switch(pppoeMode)
        {
        case 0:
            sprintf(string,"mode_name=netcore_set&conntype=3&pppoe_username=%s&pppoe_pwd=%s&ppp_connect_mode=0&wan_set=1",name,passwd);
            break;
        case 1:
            sprintf(string,"mode_name=netcore_set&conntype=3&pppoe_username=%s&pppoe_pwd=%s&ppp_connect_mode=1&wan_set=1&ppp_time=%d",name,passwd,time);
            break;

        case 2:
            sprintf(string,"mode_name=netcore_set&conntype=3&pppoe_username=%s&pppoe_pwd=%s&ppp_connect_mode=2&wan_set=1",name,passwd);
            break;
        default:
            wrong_mod = 1;
            break;
        }
    }
    strcat(string,dns_str);
    if(name != NULL)
    {
        free(name);
        name = NULL;
    }
    if(passwd != NULL)
    {
        free(passwd);
        passwd = NULL;
    }
    if(wrong_mod)
        return -1;
    return 0;
}

int GetBroadcastString(unsigned int enable,char *string)
{
    if(enable == 0)
    {
        //关闭广播
        if(NULL != string)
        {
            sprintf(string,"wl_base_set=ap&ssid_broad=%d",enable);
        }
    }
    else if(enable == 1)
    {
        if(NULL != string)
        {
            sprintf(string,"wl_base_set=ap&ssid_broad=1");
        }
    }
    else
        return -1;
    return 0;
}
int GetWpsString(unsigned int enable,char *string)
{
    if(enable == 0)
    {
        //关闭wps
        if(NULL != string)
        {
            sprintf(string,"wps_set=ap&wps_mode=enable&wps_enable=%d&wlan_idx_num=0",enable);
        }
    }
    else if(enable == 1)
    {
        if(NULL != string)
        {
            sprintf(string,"wps_set=ap&wps_enable=1&wps_mode=enable&wlan_idx_num=0");
        }
    }
    else
        return -1;
    //printf("wps string:%s\n",string);
    return 0;
}
int GetPbcString(char *string)
{
    if(NULL != string)
    {
        sprintf(string,"wps_set=ap&wps_mode=pbc&wlan_idx_num=0");
    }
    //printf("pbc string:%s\n",string);
    return 0;
}

int GetChannelString(unsigned int channel,char *string)
{
    if(channel > 9)
        return -1;
    sprintf(string,"wl_base_set=ap&channel=%d",channel);
    return 0;
}

int GetChannelAndRegionString(unsigned int channel,unsigned int region,char *string)
{
    switch(region)
    {
    case 1:
        if(channel > 11)
            return -1;
        break;
    case 3:
        if(channel > 13)
            return -1;
        break;
    case 6:
        if(channel > 14)
            return -1;
        break;
    default:
        return -1;
    }
    sprintf(string,"wl_base_set=ap&channel=%d&region=%d",channel,region);

    return 0;
}
int GetChannelWidthString(unsigned int width,char *string)
{
    if(width >=0 && width <= 2)
        sprintf(string,"wl_base_set=ap&channel_width=%d",width);

    return 0;
}

int Get5gChannelAndRegionString(unsigned int channel,unsigned int region,char *string)
{
    const int FCC_legal_channel[] = {0,36,40,44,48,149,153,157,161,165};
    const int EU_legal_channel[] = {0,36,40,44,48,149,153,157,161};
    const int MKK_legal_channel[] = {0,36,40,44,48};
    int i = 0,len = 0;
    switch(region)
    {
    case 1:
        len =  sizeof(FCC_legal_channel) / sizeof(int);
        for(i = 0; i < len; i++)
        {
            if(channel == FCC_legal_channel[i])
                break;
        }
        if( i == len)
        {
            return -1;
        }
        break;
    case 3:
        len =  sizeof(EU_legal_channel) / sizeof(int);
        for(i = 0; i < len; i++)
        {
            if(channel == EU_legal_channel[i])
                break;
        }
        if( i == len)
        {
            return -1;
        }
        break;
    case 6:
        len =  sizeof(MKK_legal_channel) / sizeof(int);
        for(i = 0; i < len; i++)
        {
            if(channel == MKK_legal_channel[i])
                break;
        }
        if( i == len)
        {
            return -1;
        }
        break;
    default:
        return -1;
    }
    sprintf(string,"wl_base_set=ap&channel=%d&region=%d",channel,region);

    return 0;
}

int GetSsidString(char* ssid,char *string)
{
    if(ssid == NULL)
        return -1;

    sprintf(string,"wl_base_set=ap&ssid=%s",ssid);
    return 0;
}

int GetPasswordString(char *password,char *string)
{
    if(password == NULL)
        return -1;

    if(strlen(password) < 8 || strlen(password) > 63)
        return -1;
    sprintf(string,"wl_sec_set=ap&sec_mode=3&key_mode_wpa=1&key_type=2&key_wpa=%s",password);
    return 0;
}

int GetNVRDevInfoString(char *jaIp,char *eseeId,char *port,char *httpPort,char *maxChannel,char *string)
{
    if(jaIp == NULL || port == NULL || httpPort == NULL || maxChannel == NULL)
        return -1;
    sprintf(string,
            "nvr_devinfo_set=1&nvr_id=%s&nvr_port=%s&nvr_httpport=%s&nvr_chanel=%s&nvr_jiaip=%s",
            eseeId,
            port,
            httpPort,
            maxChannel,
            jaIp);
    return 0;
}

int check_server_ip(char *server_ip)
{
    int is_using = 0;
    int sockfd = -1;
    do
    {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP/*protocol->p_proto*/);
        if(sockfd < 0)
        {
            printf("sockfd error, errno=%d\n", errno);
            break;
        }

        unsigned long inaddr = inet_addr(server_ip);
        if(inaddr == INADDR_NONE)
        {
            printf("inet_addr error\n");
            break;
        }

        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(struct sockaddr_in));
        dest_addr.sin_family=AF_INET;
        memcpy(&dest_addr.sin_addr, &inaddr, sizeof(inaddr));

        char sendpacket[PACKET_SIZE];
        int packetsize = nc_pack(sendpacket);
        int ret = sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        if(ret != packetsize)
        {
            //printf("sendto error, errno=%d\n", errno);
            break;
        }

        usleep(100*1000);//send second packet
        ret = sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        if(ret != packetsize)
        {
            //printf("sendto error, errno=%d\n", errno);
            break;
        }

        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        char recvpacket[PACKET_SIZE];


        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 1000;
        fd_set rfd_set;
        FD_ZERO(&rfd_set);
        FD_SET(sockfd, &rfd_set);
        ret = select(sockfd + 1, &rfd_set, NULL, NULL, &timeout);
        if(ret < 0)
        {
            printf("select error, errno=%d\n", errno);
            break;
        }

        if(ret == 0)
        {
            break;
        }

        if(ret > 0 && FD_ISSET(sockfd, &rfd_set))
        {
            ret = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, &fromlen);
            if(ret > 0)
            {
                ret = nc_unpack(recvpacket, ret);
                if(ret != -1)
                {
                    is_using = 1;
                    break;
                }
                else
                {
                    printf("not my pack\n");
                }
            }
        }
    }
    while(0);

    if(sockfd != -1)
    {
        close(sockfd);
    }

    return is_using;
}
int check_server(char *ip)
{
    if(ip == NULL)
    {
        return -1;
    }


    if(check_server_ip(HOST1) == 1)
    {
        strncpy(ip,HOST1,strlen(HOST1));
    }
    else if(check_server_ip(HOST2) == 1)
    {
        strncpy(ip,HOST2,strlen(HOST2));
    }
    else
    {
        printf("default!!\n");
        strncpy(ip,HOST1,strlen(HOST1));
    }

    system("route del default");
    set_gateway_ip(ip);
    return 0;
}

int ConnectServer(char *serip)
{
    int ret = 0;
    int sockfd = 0;
    int nType = 0;
    int error,len = sizeof(int);
    int reuse = 1;
    struct sockaddr_in localAddr;
    struct sockaddr_in servAddr;
    struct timeval tm;
    fd_set set;

    bzero(&localAddr,sizeof(localAddr));
    bzero(&servAddr,sizeof(servAddr));

    sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd < 0)
    {
        printf("get socket fd failed!\n");
        return -1;
    }

    nType = fcntl(sockfd,F_GETFL,0);
    fcntl(sockfd,F_SETFL,nType|O_NONBLOCK);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));
    g_sockfd = sockfd;
    localAddr.sin_family = AF_INET;
    servAddr.sin_family = AF_INET;
    //inet_pton(AF_INET,"172.20.14.2",&localAddr.sin_addr);
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    inet_pton(AF_INET,serip,&servAddr.sin_addr);
    servAddr.sin_port = htons(80);

    ret = bind(sockfd,(const struct sockaddr *)&localAddr,sizeof(localAddr));
    if(ret < 0)
    {
        printf("bind failed:%s\n",strerror(errno));
        close(sockfd);
        return -1;
    }

    ret = connect(sockfd,(const struct sockaddr *)&servAddr,sizeof(servAddr));
    if(ret < 0)
    {
        if(errno != EINPROGRESS)
        {
            printf("connect failed!:%s\n",strerror(errno));
            close(sockfd);
            return -1;
        }
#if 1
        memset(&tm,0,sizeof(tm));
        tm.tv_sec = 8;
        tm.tv_usec = 0;
        FD_ZERO(&set);
        FD_SET(sockfd, &set);
        if( select(sockfd+1, NULL, &set, NULL, &tm) > 0)
        {
            if(getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len) < 0)
            {
                printf("getsockopt failed!:%s\n",strerror(errno));
                return -1;
            }
            if(error == 0)
                goto out;
            else
            {
                close(sockfd);
                printf("connect timeout!!:%s\n",strerror(errno));
                return -1;
            }
        }
        else
            return -1;
#endif
    }
out:
    //fcntl(sockfd,F_SETFL,nType);
    return 0;
}
int unConnectServer()
{
    if(g_sockfd)
        close(g_sockfd);
    return 0;
}
int sendData(int sockfd,char *strCGI,char *strHost,char *strData)
{
    int ret = 0;
    char HttpData[1024] = {0};
    char HostStr[30] = {0};
    char contentLenStr[30] = {0};

    sprintf(HostStr,"Host: %s\r\n",strHost);
    sprintf(contentLenStr,"Content-Length: %d\r\n",strlen(strData));
    sprintf(HttpData,"POST %s HTTP/1.1\r\n",strCGI);
    strcat(HttpData,"Content-Type: application/x-www-form_urlencoded; charset=UTF-8\r\n");
    strcat(HttpData,contentLenStr);
    strcat(HttpData,"Connection: Keep-Alive\r\n");
    strcat(HttpData,"Accept-Encoding: gzib\r\n");
    strcat(HttpData,"Accept-Language: zh_CN,en,*\r\n");
    strcat(HttpData,"User-Agent: Mozilla/5.0\r\n");
    strcat(HttpData,HostStr);
    strcat(HttpData,"Pragma: no-cache\r\n\r\n");
    strcat(HttpData,strData);


    ret = send(sockfd,HttpData,strlen(HttpData),0);
    if(ret < 0)
    {
        printf("send error\n");
        return -1;
    }
    return 0;
}

int paruseInfo(char *buf,char *key,char *result,int len)
{
    char *p1 = NULL,*p2 = NULL,*p3= NULL;

    if(NULL == buf || key == NULL || result == NULL || len <= 0)
        return -1;
    p1 = strstr(buf,key);
    if(NULL == p1)
        return -1;
    p2 = strstr(p1,":\"");
    if(NULL == p2)
        return -1;
    p3 = strstr(p2,"\",");
    if(NULL == p3)
        return -1;
    if(len > (p3-p2-strlen(":\"")))
        strncpy(result,p2+strlen(":\""),p3-p2-strlen(":\""));
    //printf("paruse info:%s\n",result);
    return 0;
}

ssize_t readn(int fd, void *ptr, size_t n)
{
    size_t        nleft;
    ssize_t        nread;
    int readerr_times = 0;

    nleft = n;
    while (nleft > 0)
    {
        if ((nread = read(fd, ptr, nleft)) < 0)
        {

            if(EAGAIN == errno)
            {
                readerr_times ++ ;
                if(readerr_times > 20)
                    break;
                continue;
            }
            if (nleft == n)
                return(-1);
            else
            {
                break;
            }
        }
        else if (nread == 0)
        {
            break; /* EOF */
        }
        nleft -= nread;
        ptr += nread;
    }
    return(n - nleft);
}
ssize_t writen(int fd, void *vptr, size_t n)
{
    size_t      nleft;
    ssize_t     nwritten;
    const char  *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0)
    {
        if ( (nwritten = write(fd, ptr, nleft)) <= 0)
        {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0;       /* and call write() again */
            else
                return(-1);         /* error */
        }

        nleft -= nwritten;
        ptr   += nwritten;
    }
    return(n);
}
int get_value_str(char *buf,char *name,char *value)
{
    if(NULL == buf || NULL == name)
        return -1;
    char *p1 = NULL, *p2 = NULL;

    p1 = strstr(buf,name);
    if(NULL == p1)
    {
        return -1;
    }
    p2 = strstr(p1,"}],");
    if(NULL == p2)
    {
        return -1;
    }
    strncpy(value,p1+strlen(name),p2-p1-strlen(name));

    return 0;
}
int get_wifi_list_info(char *str,wifi_list_st *list)
{
    int ret = 0;
    if(str == NULL)
        return -1;
    ret = paruseInfo(str,"\"id\"",list->id,sizeof(list->id));
    if(ret < 0)
    {
        //printf("get wifi list id failed!\n");
        //return -1;
    }
    // ret = paruseInfo(str,"\"host\"",list->host,sizeof(list->host));
    //if(ret < 0)
    //{
    //printf("get wifi list host failed!\n");
    // return -1;
    //}
    ret = paruseInfo(str,"\"mode\"",list->mode,sizeof(list->mode));
    if(ret < 0)
    {
        //printf("get wifi list mode failed!\n");
        // return -1;
    }
    ret = paruseInfo(str,"\"tx_pack\"",list->tx_pack,sizeof(list->tx_pack));
    if(ret < 0)
    {
        //printf("get wifi list tx_pack failed!\n");
        // return -1;
    }
    ret = paruseInfo(str,"\"rx_pack\"",list->rx_pack,sizeof(list->rx_pack));
    if(ret < 0)
    {
        //printf("get wifi list rx_pack failed!\n");
        // return -1;
    }
    ret = paruseInfo(str,"\"speed\"",list->signal_strength,sizeof(list->signal_strength));
    if(ret < 0)
    {
        //printf("get wifi list speed failed!\n");
        // return -1;
    }
    ret = paruseInfo(str,"\"mac\"",list->user_mac,sizeof(list->user_mac));
    if(ret < 0)
    {
        //printf("get wifi list mac failed!\n");
        //return -1;
    }
    //	ret = paruseInfo(str,"\"link_time\"",list->link_time);
    //	if(ret < 0)
    //	{
    //		printf("get wifi list link_time failed!\n");
    //		return -1;
    //	}

    return 0;

}
int get_dhcp_list_info(char *str,dhcp_list_st *list)
{
    int ret = 0;
    if(NULL == str || NULL == list)
        return -1;
    ret = paruseInfo(str,"\"ip\"",list->ip,sizeof(list->ip));
    if(ret < 0)
    {
        //printf("get dhcp list ip failed!\n");
    }
    ret = paruseInfo(str,"\"mac\"",list->mac,sizeof(list->mac));
    if(ret < 0)
    {
        //printf("get dhcp list mac failed!\n");
    }
    ret = paruseInfo(str,"\"status\"",list->status,sizeof(list->status));
    if(ret < 0)
    {
        //printf("get dhcp list status failed!\n");
    }
    ret = paruseInfo(str,"\"reserved\"",list->reserved,sizeof(list->reserved));
    if(ret < 0)
    {
        //printf("get dhcp list reserved failed!\n");
    }
    ret = paruseInfo(str,"\"host\"",list->host,sizeof(list->host));
    if(ret < 0)
    {
        //printf("get dhcp list host failed!\n");
    }
    return 0;
}




int paruse_info(char *buf,nc_net_info_st* info)
{
    int ret = 0;
    int num = 0,retu = 0;
    char value[LIST_DATA__MAX] = {0};
    char name[50] = {0};
    char *p = NULL;
    int i = 0;
    //vsesion
    ret = paruseInfo(buf,"\"version\"",info->soft_version,sizeof(info->soft_version));
    if(ret < 0)
    {
        //printf("get soft version failed!\n");
    }
    //wlan
    ret = paruseInfo(buf,"\"connected\"",info->wlan_info_st.connected,sizeof(info->wlan_info_st.connected));
    if(ret < 0)
    {
        //printf("get net connected failed!\n");
    }
    ret = paruseInfo(buf,"\"access_mode\"",info->wlan_info_st.access_mode,sizeof(info->wlan_info_st.access_mode));
    if(ret < 0)
    {
        //printf("get net access mode failed!\n");
    }
    ret = paruseInfo(buf,"\"conntype\"",info->wlan_info_st.conntype,sizeof(info->wlan_info_st.conntype));
    if(ret < 0)
    {
        //printf("get net conntect mode failed!\n");
    }
    if(strlen(info->wlan_info_st.ip) == 0)//保存第一个"ip"的值，不让后面的覆盖,因为只有“ip”这一个重复字段
    {
        ret = paruseInfo(buf,"\"ip\"",info->wlan_info_st.ip,sizeof(info->wlan_info_st.ip));
        if(ret < 0)
        {
            //printf("get  ip failed!\n");
        }
    }
    ret = paruseInfo(buf,"\"mask\"",info->wlan_info_st.mask,sizeof(info->wlan_info_st.mask));
    if(ret < 0)
    {
        //printf("get  mask failed!\n");
    }
    ret = paruseInfo(buf,"\"gw\"",info->wlan_info_st.gw,sizeof(info->wlan_info_st.gw));
    if(ret < 0)
    {
        //printf("get  gw failed!\n");
    }
    ret = paruseInfo(buf,"\"wan_ip\"",info->wlan_info_st.wan_ip,sizeof(info->wlan_info_st.wan_ip));
    if(ret < 0)
    {
        // printf("get wan_ip failed!\n");
    }
    ret = paruseInfo(buf,"\"wan_mask\"",info->wlan_info_st.wan_mask,sizeof(info->wlan_info_st.wan_mask));
    if(ret < 0)
    {
        //printf("get wan_mask failed!\n");
    }
    ret = paruseInfo(buf,"\"wan_gw\"",info->wlan_info_st.wan_gw,sizeof(info->wlan_info_st.wan_gw));
    if(ret < 0)
    {
        // printf("get wan_gw failed!\n");
    }
    ret = paruseInfo(buf,"\"dns_a\"",info->wlan_info_st.dns_a,sizeof(info->wlan_info_st.dns_a));
    if(ret < 0)
    {
        // printf("get dns_a failed!\n");
    }
    ret = paruseInfo(buf,"\"dns_b\"",info->wlan_info_st.dns_b,sizeof(info->wlan_info_st.dns_b));
    if(ret < 0)
    {
        // printf("get dns_b failed!\n");
    }
    ret = paruseInfo(buf,"\"pppoe_username\"",info->wlan_info_st.pppoe_username,sizeof(info->wlan_info_st.pppoe_username));
    if(ret < 0)
    {
        //printf("get pppoe_username failed!\n");
    }
    ret = paruseInfo(buf,"\"pppoe_pwd\"",info->wlan_info_st.pppoe_pwd,sizeof(info->wlan_info_st.pppoe_pwd));
    if(ret < 0)
    {
        // printf("get pppoe_pwd failed!\n");
    }
    ret = paruseInfo(buf,"\"ppp_connect_mode\"",info->wlan_info_st.ppp_connect_mode,sizeof(info->wlan_info_st.ppp_connect_mode));
    if(ret < 0)
    {
        //printf("get ppp_connect_mode failed!\n");
    }
    ret = paruseInfo(buf,"\"ppp_time\"",info->wlan_info_st.ppp_time,sizeof(info->wlan_info_st.ppp_time));
    if(ret < 0)
    {
        //printf("get ppp_time failed!\n");
    }
    ret = paruseInfo(buf,"\"pppoe_service_name\"",info->wlan_info_st.pppoe_service_name,sizeof(info->wlan_info_st.pppoe_service_name));
    if(ret < 0)
    {
        //printf("get pppoe service name failed!\n");
    }
    ret = paruseInfo(buf,"\"pppoe_ac_name\"",info->wlan_info_st.pppoe_ac_name,sizeof(info->wlan_info_st.pppoe_ac_name));
    if(ret < 0)
    {
        // printf("get pppoe agent client name failed!\n");
    }
    ret = paruseInfo(buf,"\"mac_addr\"",info->wlan_info_st.wan_mac,sizeof(info->wlan_info_st.wan_mac));
    if(ret < 0)
    {
        // printf("get wlan mac failed!\n");
    }
    //lan
    ret = paruseInfo(buf,"\"lan_ip\"",info->lan_info_st.lan_ip,sizeof(info->lan_info_st.lan_ip));
    if(ret < 0)
    {
        // printf("get lan ip failed!\n");
    }
    ret = paruseInfo(buf,"\"lan_mask\"",info->lan_info_st.lan_mask,sizeof(info->lan_info_st.lan_mask));
    if(ret < 0)
    {
        // printf("get lan mask failed!\n");
    }
    ret = paruseInfo(buf,"\"lan_mac\"",info->lan_info_st.lan_mac,sizeof(info->lan_info_st.lan_mac));
    if(ret < 0)
    {
        // printf("get lan mac failed!\n");
    }
    //dhcp server
    ret = paruseInfo(buf,"\"dhcp_enable\"",info->dhcp_server_info_st.dhcp_enable,sizeof(info->dhcp_server_info_st.dhcp_enable));
    if(ret < 0)
    {
        // printf("get dhcp enable failed!\n");
    }
    if(1 == atoi(info->dhcp_server_info_st.dhcp_enable))
    {
        ret = paruseInfo(buf,"\"dhcp_start_ip\"",info->dhcp_server_info_st.dhcp_start_ip,sizeof(info->dhcp_server_info_st.dhcp_start_ip));
        if(ret < 0)
        {
            //      printf("get dhcp start ip failed!\n");
        }
        ret = paruseInfo(buf,"\"dhcp_end_ip\"",info->dhcp_server_info_st.dhcp_end_ip,sizeof(info->dhcp_server_info_st.dhcp_end_ip));
        if(ret < 0)
        {
            //    printf("get dhcp end ip failed!\n");
        }
        ret = paruseInfo(buf,"\"dhcp_time\"",info->dhcp_server_info_st.dhcp_time,sizeof(info->dhcp_server_info_st.dhcp_time));
        if(ret < 0)
        {
            //  printf("get dhcp time failed!\n");
        }
    }
    //dhcp client list
    memset(value,0,sizeof(value));
    memset(name,0,sizeof(name));
    strcpy(name,"\"dhcp_client_list\":[{");
    // printf("%s\n",name);
    i = 0;
    ret = get_value_str(buf,name,value);
    //value[strlen(value)] = ',';
    //printf("value=%s\n",value);
    p = value;
    if(ret == 0)
    {
        do
        {
            ret = get_dhcp_list_info(p,&(info->dh_list[i]));
            if(ret < 0)
                break;
            //printf(":::%s\n",p);
            i++;
            p = strstr(p,"},{"); //+ strlen("},{");
            if(p != NULL)
                p += strlen("},{");
            //printf("::------:%s\n",p);
        }
        while(p != NULL);
        info->dhcp_client_num = i;
    }
    //wps
    ret = paruseInfo(buf,"\"wps_enable\"",info->wps_info_st.wps_enable,sizeof(info->wps_info_st.wps_enable));
    if(ret < 0)
    {
        // printf("get wps enable failed!\n");
    }
    if(1 == atoi(info->wps_info_st.wps_enable))
    {
        ret = paruseInfo(buf,"\"wps_mode\"",info->wps_info_st.wps_mode,sizeof(info->wps_info_st.wps_mode));
        if(ret < 0)
        {
            // printf("get wps mode failed!\n");
        }
        if(strcmp(info->wps_info_st.wps_mode,"pin") == 0)
        {
            ret = paruseInfo(buf,"\"pin_host\"",info->wps_info_st.pin_host,sizeof(info->wps_info_st.pin_host));
            if(ret < 0)
            {
                // printf("get pin host failed!\n");
            }
        }
    }
    //wireless

    ret = paruseInfo(buf,"\"wl_enable\"",info->wireless_info_st.wl_enable,sizeof(info->wireless_info_st.wl_enable));
    if(ret < 0)
    {
        // printf("get wireless enable failed!\n");
    }
    //printf("wl_enable = %s\n",info->wireless_info_st.wl_enable);
    if(1 == atoi(info->wireless_info_st.wl_enable))
    {

        ret = paruseInfo(buf,"\"ssid\"",info->wireless_info_st.ssid,sizeof(info->wireless_info_st.ssid));
        if(ret < 0)
        {
            // printf("get wireless ssid failed!\n");
        }
        ret = paruseInfo(buf,"\"wl_stand\"",info->wireless_info_st.wl_stand,sizeof(info->wireless_info_st.wl_stand));
        if(ret < 0)
        {
            // printf("get wireless stand failed!\n");
        }
        ret = paruseInfo(buf,"\"net_mode\"",info->wireless_info_st.net_mode,sizeof(info->wireless_info_st.net_mode));
        if(ret < 0)
        {
            //printf("get wireless net mode failed!\n");
        }
        ret = paruseInfo(buf,"\"wl_config\"",info->wireless_info_st.wl_config,sizeof(info->wireless_info_st.wl_config));
        if(ret < 0)
        {
            // printf("get wireless config failed!\n");
        }
        ret = paruseInfo(buf,"\"wl_mac\"",info->wireless_info_st.wl_mac,sizeof(info->wireless_info_st.wl_mac));
        if(ret < 0)
        {
            // printf("get wireless mac failed!\n");
        }
        ret = paruseInfo(buf,"\"ssid_broad\"",info->wireless_info_st.ssid_broad,sizeof(info->wireless_info_st.ssid_broad));
        if(ret < 0)
        {
            // printf("get wireless broad failed!\n");
        }
        ret = paruseInfo(buf,"\"channel_width\"",info->wireless_info_st.channel_width,sizeof(info->wireless_info_st.channel_width));
        if(ret < 0)
        {
            // printf("get wireless channel width failed!\n");
        }
        ret = paruseInfo(buf,"\"channel_bind\"",info->wireless_info_st.channel_bind,sizeof(info->wireless_info_st.channel_bind));
        if(ret < 0)
        {
            // printf("get wireless channel bind failed!\n");
        }
        ret = paruseInfo(buf,"\"region\"",info->wireless_info_st.region,sizeof(info->wireless_info_st.region));
        if(ret < 0)
        {
            // printf("get wireless  region failed!\n");
        }
        ret = paruseInfo(buf,"\"channel\"",info->wireless_info_st.channel,sizeof(info->wireless_info_st.channel));
        if(ret < 0)
        {
            // printf("get wireless channel failed!\n");
        }
        ret = paruseInfo(buf,"\"net_type\"",info->wireless_info_st.net_type,sizeof(info->wireless_info_st.net_type));
        if(ret < 0)
        {
            // printf("get wireless net type failed!\n");
        }
        ret = paruseInfo(buf,"\"sec_mode\"",info->wireless_info_st.sec_mode,sizeof(info->wireless_info_st.sec_mode));
        if(ret < 0)
        {
            // printf("get wireless sec_mode failed!\n");
        }
        if(0 != atoi(info->wireless_info_st.sec_mode))
        {
            ret = paruseInfo(buf,"\"key_type\"",info->wireless_info_st.key_type,sizeof(info->wireless_info_st.key_type));
            if(ret < 0)
            {
                // printf("get wireless key type failed!\n");
            }
            ret = paruseInfo(buf,"\"key_time\"",info->wireless_info_st.key_time,sizeof(info->wireless_info_st.key_time));
            if(ret < 0)
            {
                // printf("get wireless key time failed!\n");
            }
        }
        if(0 == atoi(info->wireless_info_st.sec_mode))
        {
            ret = paruseInfo(buf,"\"key_wep\"",info->wireless_info_st.pwd,sizeof(info->wireless_info_st.pwd));
            if(ret < 0)
            {
                // printf("get wireless key wep failed!\n");
            }

        }
        else
        {
            ret = paruseInfo(buf,"\"key_wpa\"",info->wireless_info_st.pwd,sizeof(info->wireless_info_st.pwd));
            if(ret < 0)
            {
                // printf("get wireless key wpa failed!\n");
            }

        }
        do
        {
            memset(value,0,sizeof(value));
            memset(name,0,sizeof(name));
            sprintf(name,"\"wl_link_ap%d_list\":[{",num);
            i = 0;
            retu = get_value_str(buf,name,value);
            //value[strlen(value)] = ',';
            //printf("value = %s,%d,,%d\n",value,strlen(value),retu);
            p = value;
            if(retu == 0)
            {
                do
                {
                    ret = get_wifi_list_info(p,&(info->wireless_info_st.list[i]));
                    if(ret < 0)
                        break;
                    //	printf("p:::%s\n",p);
                    i++;
                    p = strstr(p,"},{"); //+ strlen("},{");
                    if(p != NULL)
                        p += strlen("},{");
                    //	printf("p::------:%s\n",p);
                }
                while(p != NULL);
                info->wireless_info_st.user_num = i;
            }
            //printf("|||||%d\n",info->wireless_info_st.user_num);

            num++;
        }
        while(0);   //当前只设置了查看ap0的信息，即主ap的信息
    }
    return 0;
}

int GetResult(int sockfd,int taget,nc_net_info_st* info)
{

    char buf[DATAMAXLEN] = {0};
    char *p = NULL,*q = NULL,*r = NULL;
    int nType = 0;
    fd_set rdfds;
    struct timeval tv;
    int ret = 0;
    int readSize = 0;
    int writeSize = 0;
    long int allSize = 0;
    char *pos_start = NULL,*pos_end = NULL;
    int grabage_len = 0;
    int padding_len = 0;
    char buf_tmp[DATAMAXLEN] = {0};
    char grabage_str[DATAMAXLEN] = {0};
    int wifi_list_target = 0;
    int dhcp_list_target = 0;
    int list_fd = 0;
    char *list_data = NULL;
    char list_file_name[256] = {0};
    int list_data_tag = 0;//表明是list数据，当来了是wireless list数据的时候，该buf没有完整的list数据，所以接着去下载完整wireless list数据到文件，但是可能此时下载的数据中又
    //包含了dhcp list的数据，当去确定p指针的位置时，会跳到dhcp list的数据位置了，而找wireless list的终点位置时却找不到而导致解析不成功。这个标识用于				//当出现list数据的时候就直接下载完当前list的数据

    nType = fcntl(sockfd,F_GETFL,0);
    fcntl(sockfd,F_SETFL,nType|O_NONBLOCK);


    if(strlen(can_rw_dir) == 0)
    {
        strcpy(can_rw_dir,"/tmp");
    }
    sprintf(list_file_name,"%s/%s",can_rw_dir,"listFile");
    unlink(list_file_name);
    list_fd = open(list_file_name,O_RDWR|O_CREAT|O_TRUNC);
    if(list_fd == -1)
    {
        if(errno == EEXIST)
        {
            list_fd = open(list_file_name,O_RDWR|O_TRUNC);
            if(list_fd == -1)
            {
                fprintf(stderr,"open file failed!:%s\n",strerror(errno));
                return -1;
            }
        }
        else
        {
            fprintf(stderr,"open file failed!:%s\n",strerror(errno));
            return -1;
        }
    }
#if 0
    sockfd = open("./1.txt",O_RDONLY);
    if(sockfd < 0)
    {
        fprintf(stderr,"open file failed!\n");
        return -1;
    }
#endif


    do
    {
        //wifi_list_target = 0;
        //dhcp_list_target = 0;

        FD_ZERO(&rdfds);
        FD_SET(sockfd,&rdfds);
        if(taget == 0)
        {
            tv.tv_sec = 0;
            tv.tv_usec = 500*1000;
        }
        else
        {
            tv.tv_sec = 10;
            tv.tv_usec = 0;
        }

        ret = select(sockfd+1,&rdfds,NULL,NULL,&tv);
        if(ret < 0)
        {
            printf("select error!\n");
            return -1;
        }
        else if(ret == 0)
        {
            if(taget == 0)
                return -1;
            else
                return 0;
        }
        if(!(FD_ISSET(sockfd,&rdfds)))
            continue;
        readSize = readn(sockfd, buf+padding_len, DATAMAXLEN-padding_len-1);
        if(readSize < 0)
        {
            printf("read error\n");
            return -1;
        }
        else if(readSize == 0)
        {
            if(padding_len == 0)
                break;
            else
            {
                if(taget)
                    return -1;
                ret = paruse_info(buf,info);
                if(ret < 0)
                {
                    fprintf(stderr,"paruse info failed!\n");
                }
                padding_len = 0;
                break;
            }

        }
        else
        {
            if(taget)   //set param
            {
                if(strstr(buf,"SUCCESS") != NULL)
                {
                    return 1;
                }
                else
                {
                    fprintf(stderr,"set failed!\n");
                    return -1;
                }
            }
            else if (0 == taget)     //get param
            {
                //printf("buf = %s\n\n",buf);

                pos_start = buf + padding_len;
                pos_end = pos_start + (readSize-1);
                q = pos_start;//如果是list数据，q会重新赋值，如果不是list数据，q是从新收到的数据开始，用于确认对list数据的末端位置

                p = strrchr(buf,',');//p是指向垃圾数据的起始位置，正常的数据的垃圾起始位置是数据的倒数‘，’之后的数据
                if(p == NULL)
                    return -1;
                if(list_data_tag == 0)//如果之前没有收到list数据
                {
                    if(( q = strstr(pos_start,"\"wl_link_ap0_list\":")) != NULL)//让list中 的东西是完整的，list的东西最大不能超过DATAMAXLEN
                    {
                        if((strstr(pos_start,"\"wl_link_ap0_list\":[]")) == NULL)
                        {
                            wifi_list_target = 1;
                            list_data_tag = 1;
                        }
                    }
                    else if (( q = strstr(pos_start,"\"dhcp_client_list\":")) != NULL)
                    {
                        if((strstr(pos_start,"\"dhcp_client_list\":[]")) == NULL)
                        {
                            dhcp_list_target = 1;
                            list_data_tag = 1;
                        }
                    }
                }
                if(wifi_list_target == 1 || dhcp_list_target == 1)//如果有list数据
                {
                    writeSize = writen(list_fd,buf,readSize+padding_len);//将所有buf数据都写入文件
                    if(writeSize != readSize+padding_len)
                    {
                        fprintf(stderr,"write error!\n");
                    }
                    if((r = strstr(q,"}],")) == NULL)//q指向list数据的末尾
                    {
                        padding_len = 0;
                        memset(buf,0,sizeof(buf));
                        continue;//list 数据没有读完，继续读
                    }
                    //数据读完之后，映射内存
                    p = r+2;//p == ','list数据之后就是正常的数据，这些数据将会在下一次解析
                    /*
                             list_data = mmap(NULL,LIST_DATA__MAX,PROT_READ|PROT_WRITE, MAP_SHARED ,list_fd ,0);
                             if(list_data == (void *)-1)
                             {
                                 fprintf(stderr,"mmap failed!:%s\n",strerror(errno));
                             }
                    */
                    list_data = (char *)malloc(LIST_DATA__MAX);
                    if(list_data == NULL)
                    {
                        printf("malloc failed!\n");
                        return -1;
                    }
                    lseek(list_fd,0,SEEK_SET);
                    read(list_fd,list_data,LIST_DATA__MAX);
                }

                memset(buf_tmp,0,sizeof(buf_tmp));
                if((p-buf) >= 0)
                    memcpy(buf_tmp,buf,(p-buf)+1);
                if(wifi_list_target == 1 || dhcp_list_target == 1)
                {
                    //如果是list数据，解析文件中的完整的list数据，而buf_tmp中的数据可能只是list数据中的一部分
                    ret = paruse_info(list_data,info);
                    if(ret < 0)
                    {
                        fprintf(stderr,"paruse info failed!\n");
                        free(list_data);
                        return -1;
                    }
                    /*
                            //list 数据处理完之后，munmap
                            if(munmap(list_data, LIST_DATA__MAX) == -1)
                            {
                                fprintf(stderr,"munmap failed!\n");
                            }
                            */
                    free(list_data);
                    // close(list_fd);

                    lseek(list_fd,0,SEEK_SET);
                    wifi_list_target = 0;
                    dhcp_list_target = 0;
                    list_data_tag = 0;
                }
                else
                {
                    //处理正常的数据
                    ret = paruse_info(buf_tmp,info);
                    if(ret < 0)
                    {
                        fprintf(stderr,"paruse info failed!\n");
                        return -1;
                    }
                }
                grabage_len = (pos_end - p) + 1;
                memset(grabage_str,0,sizeof(grabage_str));
                memcpy(grabage_str,p,grabage_len);
                memset(buf,0,sizeof(buf));
                padding_len = grabage_len;
                memcpy(buf,grabage_str,grabage_len);

            }
        }
        allSize += readSize;
    }
    while(1);
    close(list_fd);

    //printf("get result success!\n");
    return 0;
}

int nc_nvr_set_dhcp_mod(int dhcpDns_enable,char *dns_a,char *dns_b)
{
    int ret = 0;
    char dhcpStr[1024] = {0};
    char server_ip[16] = {0};

    if(dhcpDns_enable != 1 && dhcpDns_enable != 0)
    {
        fprintf(stderr,"enable must be 0 or 1\n");
        return -1;
    }

    ret = GetDhcpString(dhcpDns_enable,dns_a,dns_b,dhcpStr);
    if(ret < 0)
    {
        fprintf(stderr,"get dhcp string failed!\n");
        return -1;
    }
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,dhcpStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        // printf("set dhcp mod failed!\n");
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}
int nc_nvr_set_static_mod(char *staticIp,char *staticMask,char *staticGw,char *dns_a,char *dns_b)
{
    int ret = 0;
    char staticStr[1024] = {0};
    char server_ip[16] = {0};

    if(NULL == staticIp || NULL == staticMask || NULL == staticGw)
        return -1;

    ret = GetStaticString(staticIp,staticMask,staticGw,dns_a,dns_b,staticStr);
    if(ret < 0)
    {
        printf("get static string failed!\n");
        return -1;
    }
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,staticStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        // printf("set static mod failed!\n");
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}
int nc_nvr_set_pppoe_mod(char *pppoeId,char *pppoePw,int pppoeMod,int time,
                         int pppoeDns_enable,char *dns_a,char *dns_b)
{
    int ret = 0;
    char pppoeStr[1024] = {0};
    char server_ip[16] = {0};


    if(NULL == pppoeId || NULL == pppoePw)
        return -1;
    ret = GetPppoeString(pppoeId,pppoePw,pppoeMod,time,pppoeDns_enable,dns_a,dns_b,pppoeStr);
    if(ret < 0)
    {
        printf("get pppoe string failed!\n");
        return -1;
    }
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,pppoeStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        //printf("set pppoe mod failed!\n");
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}

int nc_nvr_set_broadcast(unsigned int enable)
{
    int ret = 0;
    char broadcastStr[1024] = {0};
    char server_ip[16] = {0};

    ret = GetBroadcastString(enable,broadcastStr);
    if(ret < 0)
        return -1;
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,broadcastStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        //printf("get result failed!\n");
        unConnectServer();
        return 0;
    }
    else if(ret == 0)
    {
        //printf("set boardcast failed!\n");
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}
int nc_nvr_set_wps(unsigned int enable)
{
    int ret = 0;
    char wpsStr[1024] = {0};
    char server_ip[16] = {0};

    ret = GetWpsString(enable,wpsStr);
    if(ret < 0)
        return -1;
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,wpsStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        //printf("set wps failed!\n");
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}
int nc_nvr_set_wps_pbc(void)
{
    int ret = 0;
    char pbcStr[1024] = {0};
    char server_ip[16] = {0};

    ret = GetPbcString(pbcStr);
    if(ret < 0)
    {
        return -1;
    }
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,pbcStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        //printf("set wps pbc failed!\n");
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}

int nc_nvr_set_channel(unsigned int channel)
{
    int ret = 0;
    char channelStr[1024] = {0};
    char server_ip[16] = {0};

    ret = GetChannelString(channel,channelStr);
    if(ret < 0)
        return -1;
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,channelStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        //printf("set channel failed!\n");
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}

int nc_nvr_set_channel_and_region(unsigned int channel,char *region,WIFI_TYPE_EN type)
{
    int ret = 0;
    int reg = 0;
    char channelRegionStr[1024] = {0};
    char server_ip[16] = {0};

    if(region == NULL)
        reg = 1;

    if(strcmp(region,"FCC") == 0)
    {
        reg = 1;
    }
    else if(strcmp(region,"EU") == 0)
    {
        reg = 3;
    }
    else if(strcmp(region,"MKK") == 0)
    {
        reg = 6;
    }
    else
    {
        return -1;
    }
    switch(type)
    {
    case WIFI_TYPE_2POINT4G:
        ret = GetChannelAndRegionString(channel,reg,channelRegionStr);
        if(ret < 0)
        {
            printf("GetChannelAndRegionString failed!\n");
            return -1;
        }
        break;
    case WIFI_TYPE_5G:
        ret = Get5gChannelAndRegionString(channel,reg,channelRegionStr);
        if(ret < 0)
        {
            printf("Get5gChannelAndRegionString failed!\n");
            return -1;
        }
        break;
    default:
        return -1;
    }
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,channelRegionStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        //printf("set channel failed!\n");
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}

int nc_nvr_set_channel_width(CHANNEL_WIDTH_EN width,WIFI_TYPE_EN type)
{
    int ret = 0;
    char channelWidthStr[1024] = {0};
    char server_ip[16] = {0};


    if(width != CHANNEL_WIDTH_TWENTY &&
            width != CHANNEL_WIDTH_FORTY  &&
            width != CHANNEL_WIDTH_ENGHTY)
    {
        printf("width:%d[width range is 20,40 or 80!]\n",width);
        return -1;
    }
    if(type == WIFI_TYPE_2POINT4G && width == CHANNEL_WIDTH_ENGHTY)
    {
        printf("2.4g not support channel width 80 !\n");
        return -1;
    }

    ret = GetChannelWidthString(width,channelWidthStr);
    if(ret < 0)
    {
        printf("GetChannelWidthString failed!\n");
        return -1;
    }

    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,channelWidthStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        //printf("set channel failed!\n");
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}

int nc_nvr_set_ssid(char *ssid)
{
    int ret = 0;
    char ssidStr[1024] = {0};
    char server_ip[16] = {0};

    ret = GetSsidString(ssid,ssidStr);
    if(ret < 0)
        return -1;
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,ssidStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}

int nc_nvr_set_password(char *password)
{
    int ret = 0;
    char passwordStr[1024] = {0};
    char server_ip[16] = {0};

    ret = GetPasswordString(password,passwordStr);
    if(ret < 0)
        return -1;
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,passwordStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}

int nc_nvr_ap_reboot()
{
    int ret = 0;
    char rebootStr[1024] = {0};
    char server_ip[16] = {0};

    strcpy(rebootStr,"mode_name=netcore_set&reboot_set=1&reboot=1");
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,rebootStr);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    unConnectServer();
    return 0;
}

int nc_nvr_set_nvr_devinfo(char *jaIp,char *eseeId,char *port,char *httpPort,char *maxChannel)
{
    int ret = 0;
    char server_ip[16] = {0};
    char nvr_dev_info_str[1024] = {0};

    ret = GetNVRDevInfoString(jaIp,eseeId,port,httpPort,maxChannel,nvr_dev_info_str);
    if(ret < 0)
        return -1;
    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_SETINFO,server_ip,nvr_dev_info_str);
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,1,NULL);
    if(ret < 0)
    {
        printf("get result failed!\n");
        unConnectServer();
        return -1;
    }
    else if(ret == 0)
    {
        unConnectServer();
        return 0;
    }
    else
    {
        unConnectServer();
        return 0;
    }
    return 0;
}

int nc_nvr_get_net_info(nc_net_info_st *info)
{
    int ret = 0;
    char server_ip[16] = {0};

    if(NULL == info)
        return -1;

    ret = check_server(server_ip);
    if(ret < 0)
    {
        return -1;
    }
    ret = ConnectServer(server_ip);
    if(ret < 0)
    {
        printf("connect server failed!\n");
        return -1;
    }
    ret = sendData(g_sockfd,CGISTRING_GETINFO,server_ip,"wl_link=0");
    if(ret < 0)
    {
        printf("send data failed!\n");
        unConnectServer();
        return -1;
    }
    ret = GetResult(g_sockfd,0,info);
    if(ret < 0)
    {
        printf("get net info result failed!\n");
        unConnectServer();
        return -1;
    }

    unConnectServer();
    return 0;

}

int nc_nvr_set_rw_dir(char *dir_name)
{
    if(dir_name == NULL)
    {
        strcpy(can_rw_dir,"/tmp");
    }
    strncpy(can_rw_dir,dir_name,sizeof(dir_name));

    return 0;
}
