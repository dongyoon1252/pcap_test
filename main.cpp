#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    printf("Dmac : %02x:%02x:%02x:%02x:%02x:%02x\n", *packet, *(packet+1), *(packet+2), *(packet+3), *(packet+4), *(packet+5));
    printf("Smac : %02x:%02x:%02x:%02x:%02x:%02x\n", *(packet+6), *(packet+7), *(packet+8), *(packet+9), *(packet+10), *(packet+11));
    int verifyIp = (*(packet+12) << 8) | *(packet+13);
    int lengthIp = (*(packet+14)&0x0f)*4;
    int verifyTcp = (*(packet+23));
    int lengthTcp = ((*(packet+46)&0xf0) >> 4)*4;
    //int verifyHttp =;
    //printf("%d\n", verifyIp);
    //printf("TCP : %d\n", verifyTcp);


    if(verifyIp == 0x0800){
        printf("This is IPv4 Packet.\n");
        printf("Length of IP Header = %d\n", lengthIp);
        printf("Sip : %d.%d.%d.%d\n", *(packet+26), *(packet+27), *(packet+28), *(packet+29));
        printf("Dip : %d.%d.%d.%d\n", *(packet+30), *(packet+31), *(packet+32), *(packet+33));
        if(verifyTcp == 0x0006){
            printf("This is TCP Packet.\n");
            printf("Length of TCP Header = %d\n", lengthTcp);
            printf("Sport : %d\n", (*(packet + 34) << 8 ) | *(packet+35));
            printf("Dport : %d\n", (*(packet + 36) << 8 ) | *(packet+37));
            printf("Data : %x%x%x%x%x%x%x%x%x%x\n", (*(packet + 66)), (*(packet + 67)), (*(packet + 68)), (*(packet + 69))
                   , (*(packet + 70)), (*(packet + 71)), (*(packet + 72)), (*(packet + 73)), (*(packet + 74)), (*(packet + 75)));
        } else {
            printf("This is not TCP packet.\n");
        }
    } else {
        printf("This is not IPv4 packet.\n");
    }

    packet = NULL;
  }




  pcap_close(handle);
  return 0;
}
