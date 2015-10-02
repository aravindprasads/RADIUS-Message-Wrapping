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

struct rad_handle * my_rad_init(void);

int main() 
{
    struct rad_handle *rad_h1 = NULL;
    struct rad_handle *rad_h = NULL;
    long long  rc = 0, ret_value, i =0;
    uint proto_tcp = 0;
    long long no_clients;
    unsigned char msg[MSGSIZE] = {0};
    long long len = 0;

    printf("\n\rNo of Client ? \n\r");
    scanf("%llu", &no_clients);
    printf("\n\rUDP(0)/TCP(1) ?\n\r");
    scanf("%d", &proto_tcp);

    for(i=0; i<no_clients; i++)
    {
        rad_h1 = my_rad_init();
        if(rad_h1 == NULL)
        {
            printf("\n\rInit failed\n\r");
            return 0;
        }
        my_rad_add_request(&msg, &len, rad_h1);
    }
    if ((rad_h = rad_auth_open ()) == NULL)
    {
        printf("Authentication init failure");
        return;
    }
    /** Read the configuration data from radius.conf file */
    if ((ret_value = rad_config (rad_h, NULL)) != 0)
    {
        printf("Authentication configuration "
                "failure %llu", ret_value);
        rad_h = NULL;
        return;
    }

    //proto_tcp = false;
    printf("\n\r!!!!Passing len =%llu to final Msg", len);
    switch((rc = my_rad_send_request(rad_h, &msg, len, proto_tcp, no_clients)))
    {
        case RAD_ACCOUNTING_RESPONSE:
            printf("server response okay.\n");
            rc = 0;
            break;
        case -1:
            fprintf(stderr, "error : %s\n", rad_strerror(rad_h));
            break;
        case RAD_ACCESS_ACCEPT:
            printf("server response -- ACCEPT.\n");
            rc = 0;
            break;
        default:
            printf("\n\rmessage code %llu", rc);
            fprintf(stderr, "invalid message type in response: %llu\n", rc);
            rc = -1;
    }

    rad_close(rad_h);

    return rc;
}
