#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

// 以太网数据帧头部结构体
typedef struct EthernetHeader {
    u_char destination_mac[6];
    u_char source_mac[6];
    u_short ether_type;
} EthernetHeader;

// IPv4数据报头部结构体
typedef struct IPHeader {
    u_char version_header_length;
    u_char differentiated_services;
    u_short total_length;
    u_short identification;
    u_short flags_fragment_offset;
    u_char time_to_live;
    u_char protocol;
    u_short header_checksum;
    u_char source_ip[4];
    u_char destination_ip[4];
} IPHeader;

// TCP数据报头部结构体
typedef struct TCPHeader {
    u_short source_port;
    u_short destination_port;
    u_int32_t sequence_number;
    u_int32_t acknowledgment_number;
    u_char data_offset;
    u_char flags;
    u_short window_size;
    u_short checksum;
    u_short urgent_pointer;
} TCPHeader;

// 回调函数，处理捕获到的每个数据包
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    EthernetHeader *eth_header;
    IPHeader *ip_header;
    TCPHeader *tcp_header;
    FILE *fp;
    char filename[50];
    time_t current_time;
    struct tm *timeinfo;

    eth_header = (EthernetHeader *)packet;
    
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (IPHeader *)(packet + sizeof(EthernetHeader));
        
        tcp_header = (TCPHeader *)(packet + sizeof(EthernetHeader) + (ip_header->version_header_length & 0x0F) * 4);

        // 获取当前时间
        time(&current_time);
        timeinfo = localtime(&current_time);

        // 创建output文件夹
        mkdir("output", 0777);

        // 生成文件名
        strftime(filename, sizeof(filename), "output/capture_%Y_%m_%d_%H_%M_%S.txt", timeinfo);

        // 打开文件，追加模式写入
        fp = fopen(filename, "a");
        if (fp == NULL) {
            fprintf(stderr, "Error opening file %s\n", filename);
            return;
        }

        // 写入四元组信息到文件
        fprintf(fp, "Source IP: %d.%d.%d.%d\n", ip_header->source_ip[0], ip_header->source_ip[1], ip_header->source_ip[2], ip_header->source_ip[3]);
        fprintf(fp, "Destination IP: %d.%d.%d.%d\n", ip_header->destination_ip[0], ip_header->destination_ip[1], ip_header->destination_ip[2], ip_header->destination_ip[3]);
        fprintf(fp, "Source Port: %d\n", ntohs(tcp_header->source_port));
        fprintf(fp, "Destination Port: %d\n", ntohs(tcp_header->destination_port));
        fprintf(fp, "-----------------\n");

        // 关闭文件
        fclose(fp);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;
    pcap_if_t *alldevs;
    pcap_if_t *d;

    // 获取网络设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    // 打开第一个网络设备
    if ((pcap_handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "Error opening adapter %s: %s\n", alldevs->name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // 循环捕获数据包，交给回调函数处理
    pcap_loop(pcap_handle, 50, packet_handler, NULL);

    // 关闭捕获器
    pcap_close(pcap_handle);
    pcap_freealldevs(alldevs);

    return 0;
}
