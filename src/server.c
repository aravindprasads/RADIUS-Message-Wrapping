#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#define MSG_SIZE 55000

typedef struct _radius_pkt_t
{
    uint8_t code;
    uint8_t id;
    uint16_t length;
    char auth[16];
    char avp[14];
}rad_pkt_t;

int main(int argc, char**argv)
{
    long long sockfd,n;
    uint8_t recvd_pkt_id = 0;
    struct sockaddr_in servaddr,cliaddr;
    socklen_t len;
    char mesg[MSG_SIZE]= {0};
    char reply_msg[MSG_SIZE]= {0};
    char authentic[16] = {0xec, 0xfe, 0x3d, 0x2f, 0xe4, 0x47, 0x3e, 0xc6, 0x29, 0x90, 
                          0x95, 0xee, 0x46, 0xae, 0xdf, 0x77};
    char avp[14] = {0x05, 0x06, 0x00, 0x00, 0x10, 0x7f, 
                    0x01, 0x08, 0x61, 0x64, 0x6d, 0x69, 0x6e, '\0'};
    long long data_len, msg_start;
    uint16_t packet_len = 0;
    long long msg_no = 0;

    sockfd=socket(AF_INET,SOCK_DGRAM,0);

    memset(&servaddr,0,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    servaddr.sin_port=htons(1812);
    bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));

    //keep the reply msg ready
    rad_pkt_t *pkt;
    pkt = (rad_pkt_t *)reply_msg;
    pkt->code = 2;
    pkt->id = 1;
    memcpy(&pkt->auth, authentic, sizeof(authentic));
    memcpy(&pkt->avp, avp, sizeof(avp));
    pkt->length = htons(sizeof(rad_pkt_t));
    for (;;)
    {
        printf("\n\r=====Listening to Client Messages====\n\r");
        len = sizeof(cliaddr);
        data_len = recvfrom(sockfd,mesg,MSG_SIZE,0, (struct sockaddr *)&cliaddr,&len);
        printf("\n\rdata_len = %llu\n\r", data_len);

        msg_start = 0;
        msg_no = 0;
        while(msg_start < data_len)
        {
            recvd_pkt_id = mesg[msg_start +1];
            pkt->id = recvd_pkt_id;
            printf("\n\rmsg_start = %llu\n\r", msg_start);
            packet_len = (mesg[msg_start + 2] * 256) + mesg[msg_start + 3];
            printf("\n\rpacket_len = %d\n\r", packet_len);
            msg_start += packet_len;
            sendto(sockfd,reply_msg,sizeof(rad_pkt_t),0,(struct sockaddr *)&cliaddr,sizeof(cliaddr));
            msg_no++;
            printf("\n\r!!!Replied back to the Client %llu!!!\n\r", msg_no);
        }
        memset(mesg, 0, sizeof(mesg));
    }
}




