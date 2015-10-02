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
#include <sys/socket.h>
#include <sys/select.h>

int main() 
{
	struct rad_handle *rad_h = NULL;
	int rc = 0;
    int no_clients = 2, i = 0;

    printf("\n\rNo of Clients ?\n\r");
    scanf("%d", &no_clients);
    for (i = 0; i < no_clients; i++)
    {
        if ((rad_h = rad_auth_open ()) == NULL)
        {
            printf("Authentication init failure");
            return;
        }
        /** Read the configuration data from radius.conf file */
        if ((rad_config (rad_h, NULL)) != 0)
        {
            printf("\n\rconfiguration failure");
            rad_h = NULL;
            return;
        }

        if (rad_create_request(rad_h, RAD_ACCESS_REQUEST)) {
            fprintf(stderr, "failed to add server: %s\n", rad_strerror(rad_h));
            return -1;	
        }

        rad_put_string(rad_h, RAD_USER_NAME, "admin");
        rad_put_string(rad_h, RAD_USER_PASSWORD, "admin");
        rad_put_int(rad_h, RAD_NAS_PORT, 4223);

        switch((rc = rad_send_request(rad_h))) 
        {
            case RAD_ACCESS_ACCEPT:
                printf("server response -- ACCEPT.\n");
                rc = 0;
                break;
            case -1:
                fprintf(stderr, "error while receiving response: %s\n", rad_strerror(rad_h));
                break;
            default:
                fprintf(stderr, "invalid message type in response: %d\n", rc);
                rc = -1;
        }

        rad_close(rad_h);
    }
    return rc;
}
