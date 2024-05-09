#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h> // 用于获取当前时间

// 以太网头部结构体
typedef struct EthernetHeader {
    u_char deth_dsthost[6];
    u_char eth_srchost[6];
    u_short eth_type;
} ethhdr;

// IPv4协议头部结构体
typedef struct IPHeader {
    u_char ip_hlv;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_foff;
    u_char ip_ttl;
    u_char ip_pro;
    u_short ip_checksum;
    u_char ip_src[4];
    u_char ip_dst[4];
} iphdr;

// TCP协议头部结构体
typedef struct TCPHeader {
    u_short tcp_srcport;
    u_short tcp_dstport;
    u_int tcp_seq;
    u_int tcp_ack;
    u_char tcp_headlen;
    u_char tcp_flag;
    u_short tcp_win;
    u_short tcp_checksum;
    u_short tcp_urp;
} tcphdr;

// UDP协议头部结构体
typedef struct UDPHeader {
    u_short udp_srcport;
    u_short udp_dstport;
    u_short udp_len;
    u_short udp_checksum;
} udphdr;


// 全局变量，用于存储文件名
char filename[32] = "";

// 生成文件名
void generate_filename() {
    time_t now = time(NULL);
    struct tm *tm_info;
    tm_info = localtime(&now);

    // 创建名为 "output" 的文件夹
    mkdir("output", 0777);

    // 格式化时间字符串
    snprintf(filename, sizeof(filename), "output/capture_%04d_%02d_%02d_%02d_%02d_%02d.txt",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
}

// 将数据包信息写入文件
void write_packet_info(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port) {
    FILE *file = fopen(filename, "a"); // 以追加方式打开文件
    if (file != NULL) {
        fprintf(file, "Source IP: %s\n", src_ip);
        fprintf(file, "Destination IP: %s\n", dst_ip);
        fprintf(file, "Source Port: %d\n", src_port);
        fprintf(file, "Destination Port: %d\n", dst_port);
        fprintf(file, "------------------------\n");
        fclose(file);
    } else {
        printf("Error opening file %s\n", filename);
    }
}

// 处理捕获到的数据包
void ethernet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    ethhdr *ethernet_header = (ethhdr *)packet;
    iphdr *ip_header = (iphdr *)(packet + sizeof(ethhdr));

    // 获取源IP和目的IP
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, ip_header->ip_dst, dst_ip, INET_ADDRSTRLEN);

    if (ip_header->ip_pro == IPPROTO_TCP) {
        tcphdr *tcp_header = (tcphdr *)(packet + sizeof(ethhdr) + (ip_header->ip_hlv & 0x0F) * 4);
        uint16_t src_port = ntohs(tcp_header->tcp_srcport);
        uint16_t dst_port = ntohs(tcp_header->tcp_dstport);

        // 写入信息到文件
        write_packet_info(src_ip, dst_ip, src_port, dst_port);
    } else if (ip_header->ip_pro == IPPROTO_UDP) {
        udphdr *udp_header = (udphdr *)(packet + sizeof(ethhdr) + (ip_header->ip_hlv & 0x0F) * 4);
        uint16_t src_port = ntohs(udp_header->udp_srcport);
        uint16_t dst_port = ntohs(udp_header->udp_dstport);

        // 写入信息到文件
        write_packet_info(src_ip, dst_ip, src_port, dst_port);
    } else {
        printf("Unknown Protocol!\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *alldevs;
    pcap_if_t *d = alldevs;
    int i = 0;
    int choice;
    struct bpf_program filter; // 过滤器
    char filter_exp[] = "tcp or udp and dst port 443"; // 设置过滤条件

    // 查找网络接口设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Not Found Devs!\n");
        return 1;
    }

    // 输出网络接口设备信息
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        printf("%d: %s", ++i, d->name);
        if (d->description)
            fprintf(stdout, "%s\n", d->description);
        else
            fprintf(stdout, "No description");

        // 输出接口的地址信息
        for (pcap_addr_t *addr = d->addresses; addr != NULL; addr = addr->next) {
            // 检查地址族
            if (addr->addr->sa_family == AF_INET) {
                // 输出 IPv4 地址信息
                char ipv4[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &((struct sockaddr_in *)addr->addr)->sin_addr, ipv4, sizeof(ipv4)) != NULL) {
                    printf("    IPv4 Address: %s\n", ipv4);
                }
                printf("    IPv4 Address: %s\n", inet_ntoa(((struct sockaddr_in *)addr->addr)->sin_addr));
            } else if (addr->addr->sa_family == AF_INET6) {
                // 输出 IPv6 地址信息
                char ipv6[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addr->addr)->sin6_addr), ipv6, INET6_ADDRSTRLEN) != NULL) {
                    printf("    IPv6 Address: %s\n", ipv6);
                }
            }
        }
        printf("\n");
    }

    printf("your choice:");
    scanf("%d", &choice);

    // 用户选择网络接口设备
    if (choice > 0 && choice <= i) {
        int j;
        for (j = 1, d = alldevs; d != NULL && j < choice; d = d->next, j++)
            ;
        printf("\nyou have select %s\n", d->name);
    }

    // 打开网络接口设备
    handle = pcap_open_live(d->name, 65536, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stdout, "Unable to open the adapter %s!", d->name);
        pcap_freealldevs(alldevs);
    }
    printf("\nlistening on %s...\n", d->name);
    pcap_freealldevs(alldevs);

    // 编译过滤器规则
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // 设置过滤器规则
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // 生成文件名
    generate_filename();
    printf("File name: %s\n", filename);

    FILE *file = fopen(filename, "a");
    fprintf(file, "filter: %s\n------------------------\n", filter_exp);
    fclose(file);

    // 开始抓包
    pcap_loop(handle, 40, ethernet_callback, NULL);
    pcap_close(handle);
    return 0;
}