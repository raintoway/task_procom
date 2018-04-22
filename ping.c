#ifndef __PING_H__  
#define __PING_H__  
  
#include <stdio.h>  
#include <sys/time.h>  
#include <netdb.h>  
#include <stdlib.h>  
#include <sys/socket.h>  
#include <arpa/inet.h>  
#include <string.h>  
#include <netinet/ip_icmp.h>  
#include <sys/types.h>  
#include <unistd.h>  
#include <sys/socket.h>  
#include <signal.h>  
#include <math.h>  
  
#define ICMP_DATA_LEN 56        //ICMP默认数据长度  
#define ICMP_HEAD_LEN 8         //ICMP默认头部长度  
#define ICMP_LEN  (ICMP_DATA_LEN + ICMP_HEAD_LEN)    //64 bytes
#define SEND_NUM 5            //发送报文数  
#define MAX_WAIT_TIME 3  
#define WAIT_TIME 5
#define SEND_BUFFER_SIZE 128        //发送缓冲区大小  
#define RECV_BUFFER_SIZE 128        //接收缓冲区大小
  
extern struct hostent *pHost;  
extern int sock_icmp;  
extern int numSend;
int numRecv = 0;                 //实际接收到的报文数   
extern char *IP; 
char SendBuffer[SEND_BUFFER_SIZE];  
char RecvBuffer[RECV_BUFFER_SIZE]; 
struct timeval FirstSendTime;   //用以计算总的时间  
struct timeval LastRecvTime;   
     
#endif  //__PING_H__ 
  
//计算校验和  这段算法是网上的  
u_int16_t checksum(struct icmp *pIcmp)  
{  
    //将icmp的点分十进制转化为网络字节序
    //检查校验和网站https://blog.csdn.net/wswit/article/details/46822189
    u_int16_t *data = (u_int16_t *)pIcmp;  
    int len = ICMP_LEN;  
    u_int32_t sum = 0;  
      
    while (len > 1)  
    {  
        sum += *data;
	*data++; 
        len =len-2;  
    }  
    if (len == 1)  
    {  
        u_int16_t tmp = *data;  
        tmp &= 0xff00;  
        sum =sum+tmp;  
    }  
    //检查icmp中的checksum是否正确  
    while (sum >> 16)  
        sum = (sum >> 16) + (sum & 0x0000ffff);  
    sum = ~sum;  
      
    return sum;  
}  
  
void Set(u_int16_t seq)  
{  
    struct icmp *pIcmp;  
    struct timeval *pTime;  
  
    pIcmp = (struct icmp*)SendBuffer;  
      
    /* 类型和代码分别为ICMP_ECHO,0代表请求回送 */  
    pIcmp->icmp_type = ICMP_ECHO;  
    pIcmp->icmp_code = 0;  
    pIcmp->icmp_cksum = 0;       //校验和  
    pIcmp->icmp_seq = seq;       //序号  
    pIcmp->icmp_id = getpid();   //取进程号作为标志  
    pTime = (struct timeval *)pIcmp->icmp_data; //********************必须得先设置成0  然后在后面调用否则 set报头将失败 
    gettimeofday(pTime, NULL);  //数据段存放发送时间  
    pIcmp->icmp_cksum = checksum(pIcmp);  
      

	//取第一个包发送时间为总开始时间
    if (1 == seq)  
        FirstSendTime = *pTime;  
}  
  
//参数：socket_fd 目标套接字地址 发送的包的数量 
void Send(int sock_icmp, struct sockaddr_in *dest_addr, int numSend)  
{  
    /*Set(numSend); 
    //sendto 函数参数：socket_fd 发送缓存区 icmp报文长度 （默认0） 目标地址  地址长度 
    //将sendbuffer中数据发送到socket_fd中 
    sendto(sock_icmp, SendBuffer, ICMP_LEN, 0,  
        (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) ;*/
	Set(numSend);  
    if (sendto(sock_icmp, SendBuffer, ICMP_LEN, 0,  
        (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) < 0)  
    {  
        perror("sendto");  
        return;  
    }   
}  
  

//tiemval有两个元素  一个是sec  一个是usec 
double rtt(struct timeval *RecvTime, struct timeval *SendTime)  
{  
	//接受时间不可以轻易改变所以得用temp
    struct timeval temp = *RecvTime;  
  
	//如果rec.usec<send.usec  则类似于十进制减法
    if ((temp.tv_usec -= SendTime->tv_usec) < 0)  
    {  
        --(temp.tv_sec);  
        temp.tv_usec += 1000000;  
    }  
    temp.tv_sec -= SendTime->tv_sec;  
      
	//转换单位为毫秒
    double res=temp.tv_sec * 1000.0 + temp.tv_usec / 1000.0;
    return res; 
} 



//拆除报头
int unpack(struct timeval *RecvTime)  
{  
    struct ip *Ip = (struct ip *)RecvBuffer;  //将接受缓存区中的数据转换中ip形式
    struct icmp *Icmp;  
    int ipHeadLen;   
  
    ipHeadLen = Ip->ip_hl << 2;    //ip_hl字段单位为4字节  
    Icmp = (struct icmp *)(RecvBuffer + ipHeadLen);  
  
    //判断接收到的报文是否是自己所发报文的响应  
    //通过判断接受到的type是否为接受类型的icmp报文 以及程序id是否和发送时的程序id一样
    if ((Icmp->icmp_type == ICMP_ECHOREPLY) && Icmp->icmp_id == getpid())  
    {  
        struct timeval *SendTime = (struct timeval *)Icmp->icmp_data;  
              
        printf("%u bytes from %s: icmp_seq=%u ttl=%u time=%.1f ms\n",  
            ntohs(Ip->ip_len) - ipHeadLen,  
            inet_ntoa(Ip->ip_src),  
            Icmp->icmp_seq,  
            Ip->ip_ttl,  
            rtt(RecvTime, SendTime));   

        return 0;  
    }  
          
    return -1;  
}

void Statistics()  
{         
          
    printf("%d packets transmitted, %d received, %d%% packet loss, time %dms\n",numSend,numRecv,(numSend-numRecv)/numSend*100,(int)rtt(&LastRecvTime, &FirstSendTime));    
      
    close(sock_icmp);  
    exit(0);  
}

int Recve(int sock_icmp, struct sockaddr_in *dest_addr)  
{    
    int addrlen = sizeof(struct sockaddr_in);  
    struct timeval RecvTime;  
   
    signal(SIGALRM, Statistics);
    alarm(WAIT_TIME); 
   //recvfrom函数参数： socket_fd 接受缓存区 大小 默认0 目标地址  地址长度
   //读取socket_fd中的数据进入recvbuffer中 
   recvfrom(sock_icmp, RecvBuffer, 128,  
            0, (struct sockaddr *)dest_addr, &addrlen);
  
    //接受时间
    gettimeofday(&RecvTime, NULL);   
    LastRecvTime = RecvTime;   //用于计算总时间
    int ret=unpack(&RecvTime);
    if (ret == -1)  
    {  
        return -1;   
    }  
    numRecv++; 
  
} 
struct hostent * pHost = NULL;      //保存主机信息  
int sock_icmp;              //icmp套接字   
char *IP = NULL;  
int numSend = 0;
  
void Call(int argc, char *argv[])  
{  
  
    struct protoent *protocol;  
    struct sockaddr_in dest_addr;   //IPv4专用socket地址,保存目的地址  
  
    in_addr_t inaddr;       //ip地址（网络字节序）  
  
    if (argc < 2)  
    {  
        printf("Usage: %s [hostname/IP address]\n", argv[0]);  
        exit(EXIT_FAILURE);   
    }  
  
    if ((protocol = getprotobyname("icmp")) == NULL)  
    {  
        perror("getprotobyname");  
        exit(EXIT_FAILURE);  
    }  
  
    /* 创建ICMP套接字 */  
    //AF_INET:IPv4, SOCK_RAW:IP协议数据报接口, IPPROTO_ICMP:ICMP协议  
    if ((sock_icmp = socket(PF_INET, SOCK_RAW, protocol->p_proto/*IPPROTO_ICMP*/)) < 0)  
    {  
        perror("socket");  
        exit(EXIT_FAILURE);  
    }  
    dest_addr.sin_family = AF_INET;  
  
    /* 将点分十进制ip地址转换为网络字节序 */  
    if ((inaddr = inet_addr(argv[1])) == INADDR_NONE)  
    {  
        /* 转换失败，表明是主机名,需通过主机名获取ip */  
        if ((pHost = gethostbyname(argv[1])) == NULL)  
        {  
            herror("gethostbyname()");  
            exit(EXIT_FAILURE);  
        }  
        memmove(&dest_addr.sin_addr, pHost->h_addr_list[0], pHost->h_length);  
    }  
    else  
    {  
        memmove(&dest_addr.sin_addr, &inaddr, sizeof(struct in_addr));  
    }  
  
    if (NULL != pHost)  
        printf("PING %s", pHost->h_name);  
    else  
        printf("PING %s", argv[1]);  
    printf("(%s) %d bytes of data.\n", inet_ntoa(dest_addr.sin_addr), ICMP_LEN);  
  
    IP = argv[1];  
	signal(SIGINT, Statistics); 
    while (numSend < SEND_NUM)  
    {       
	int unpack_ret;
        Send(sock_icmp, &dest_addr, numSend);  
       
        unpack_ret = Recve(sock_icmp, &dest_addr);  
        if (-1 == unpack_ret)   //（ping回环时）收到了自己发出的报文,重新等待接收  
            Recve(sock_icmp, &dest_addr);
              
  
        sleep(1);  
        numSend++;  
    }  
      
    Statistics();  //输出信息，关闭套接字  
}  
  

//输入ip地址或者url argc代表字符串 argv代表其在内存中的地址
int main(int argc, char *argv[])  
{  
    Call(argc, argv);  
  
    return 0;  
}  
  
