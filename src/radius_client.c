/*
 * example RADIUS client
 *
 * send a message to a local RADIUS accounting server
 *
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "include/radlib.h"
#include "include/radlib_private.h"
#include <sys/socket.h>
#include <sys/select.h>
#include <stdbool.h>

#define TRACE_ENABLE 0
#define TRACE(args...) if(TRACE_ENABLE) printf(args)

#define LOG_ENABLE 1
#define LOG(args...) if(LOG_ENABLE) printf(args)

struct rad_handle * my_rad_init(void);

void my_rad_add_request(unsigned char *msg, long long *len, struct rad_handle *h);

int my_rad_send_request(struct rad_handle *h, unsigned char *msg, long long len,
                        uint proto_tcp, long long msg_count);

int main() 
{
    struct rad_handle *rad_h1 = NULL;
    struct rad_handle *rad_h = NULL;
    long long  rc = 0, ret_value, i =0;
    uint proto_tcp = 0;
    long long no_clients;
    unsigned char msg[MSGSIZE] = {0};
    long long len = 0;

    LOG("\n\rTransport Protocol - UDP(0)/TCP(1) ?\n\r");
    scanf("%d", &proto_tcp);
    if ((proto_tcp < 0) || (proto_tcp > 1)){
        LOG("\n\rInvalid Transport Protocol selected. Exiting !!\n\r\n\r");
        return 0;
    }

    LOG("\n\rNo of Clients (1 - 1000) ? \n\r");
    scanf("%llu", &no_clients);
    if ((no_clients < 1) || (no_clients > 1000)){
        LOG("\n\rInvalid number of Clients selected. Exiting !!\n\r\n\r");        
        return 0;
    }

    for(i=0; i<no_clients; i++)
    {
        rad_h1 = my_rad_init();
        if(rad_h1 == NULL)
        {
            LOG("\n\rInit failed\n\r");
            return 0;
        }
        my_rad_add_request(msg, &len, rad_h1);
    }
    if ((rad_h = rad_auth_open ()) == NULL)
    {
        LOG("Authentication init failure");
        return 0;
    }
    /** Read the configuration data from radius.conf file */
    if ((ret_value = rad_config (rad_h, NULL)) != 0)
    {
        LOG("Authentication configuration "
                "failure %llu", ret_value);
        rad_h = NULL;
        return 0;
    }

    TRACE("\n\r!!!!Passing len =%llu to final Msg", len);
    switch((rc = my_rad_send_request(rad_h, msg, len, proto_tcp, no_clients)))
    {
        case -1:
            fprintf(stderr, "Processing Error : %s\n", rad_strerror(rad_h));
            break;
        case RAD_ACCESS_ACCEPT:
            rc = 0;
            LOG("\n\r\n\r================================================");
            LOG("\n\rReceived %lld Reply Messages from Server", no_clients);
            LOG("\n\r================================================\n\r\n\r");
            break;
        default:
            TRACE("\n\rmessage code %llu", rc);
            fprintf(stderr, "invalid message type in response: %llu\n", rc);
            rc = -1;
    }

    rad_close(rad_h);

    return rc;
}
