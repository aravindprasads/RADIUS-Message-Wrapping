/*-
 * Copyright 1998 Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef WITH_SSL
#include <openssl/hmac.h>
#include <openssl/md5.h>
#else
#define MD5_DIGEST_LENGTH 16
#include "md5/md5.h"
#endif

#define	MAX_FIELDS	7

/* We need the MPPE_KEY_LEN define - but we don't have netgraph/ng_mppc.h */
#define MPPE_KEY_LEN	16

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include "include/radlib_private.h"

#ifndef __printflike
#define __printflike(m, n) __attribute__((format(printf, m, n)));
#endif

#define TRACE_ENABLE 0
#define TRACE(args...) if(TRACE_ENABLE) printf(args)

#define LOG_ENABLE 1
#define LOG(args...) if(LOG_ENABLE) printf(args) 

void     generr(struct rad_handle *, const char *, ...)
                    __printflike(2, 3);
void     insert_scrambled_password(struct rad_handle *, int);
void     insert_message_authenticator(struct rad_handle *, int);
void     insert_request_authenticator(struct rad_handle *, int);


/* Initialiaze RADIUS Msg Handle */
struct rad_handle *my_rad_init(void)
{
    int srv;
    time_t now;
    struct sockaddr_in sin;
    int n, cur_srv;
    int rc = 0, ret_value;
    struct rad_handle *h = NULL;
    TRACE("\n\rentering %s\n\r", __FUNCTION__);
    /** Get Handle from LIBRADIUS library */
    if ((h = rad_auth_open ()) == NULL)
    {
        LOG("Authentication init failure");
        return NULL;
    }
    /** Read the configuration data from radius.conf file */
    if ((ret_value = rad_config (h, NULL)) != 0)
    {
        LOG("Authentication configuration "
                "failure %d", ret_value);
        return NULL;
    }
    /** Construct a new RADIUS Authentication Request */
    if ((ret_value =
                rad_create_request (h, RAD_ACCESS_REQUEST)) != 0)
    {
        LOG("Message creation failure %d",
                ret_value);
        return NULL;
    }

    rad_put_string(h, RAD_USER_NAME, "admin");
    rad_put_string(h, RAD_USER_PASSWORD, "admin");
    rad_put_int(h, RAD_NAS_PORT, 4223);

    /* Fill in the length field in the message */
    h->out[POS_LENGTH] = h->out_len >> 8;
    h->out[POS_LENGTH+1] = h->out_len;

    h->srv = 0;
    now = time(NULL);
    for (srv = 0;  srv < h->num_servers;  srv++)
        h->servers[srv].num_tries = 0;
    /* Find a first good server. */
    for (srv = 0;  srv < h->num_servers;  srv++) {
        if (h->servers[srv].is_dead == 0)
            break;
        if (h->servers[srv].dead_time &&
                h->servers[srv].next_probe <= now) {
            h->servers[srv].is_dead = 0;
            break;
        }
        h->srv++;
    }

    /* If all servers was dead on the last probe, try from beginning */
    if (h->srv == h->num_servers) {
        for (srv = 0;  srv < h->num_servers;  srv++) {
            h->servers[srv].is_dead = 0;
            h->servers[srv].next_probe = 0;
        }
        h->srv = 0;
    }

    /*
     * Scan round-robin to the next server that has some
     * tries left.  There is guaranteed to be one, or we
     * would have exited this loop by now.
     */
    cur_srv = h->srv;
    now = time(NULL);
    if (h->servers[h->srv].num_tries >= h->servers[h->srv].max_tries) {
        /* Set next probe time for this server */
        if (h->servers[h->srv].dead_time) {
            h->servers[h->srv].is_dead = 1;
            h->servers[h->srv].next_probe = now +
                h->servers[h->srv].dead_time;
        }
        do {
            h->srv++;
            if (h->srv >= h->num_servers)
                h->srv = 0;
            if (h->servers[h->srv].is_dead == 0)
                break;
            if (h->servers[h->srv].dead_time &&
                    h->servers[h->srv].next_probe <= now) {
                h->servers[h->srv].is_dead = 0;
                h->servers[h->srv].num_tries = 0;
                break;
            }
        } while (h->srv != cur_srv);

        if (h->srv == cur_srv) {
            generr(h, "No valid RADIUS responses received");
            LOG("\n\rNo valid RADIUS responses received\n\r");
            return NULL;
        }
    }

    if (h->out[POS_CODE] == RAD_ACCESS_REQUEST) {
        /* Insert the scrambled password into the request */
        if (h->pass_pos != 0)
            insert_scrambled_password(h, h->srv);
    }
    insert_message_authenticator(h, 0);

    if (h->out[POS_CODE] != RAD_ACCESS_REQUEST) {
        /* Insert the request authenticator into the request */
        memset(&h->out[POS_AUTH], 0, LEN_AUTH);
        insert_request_authenticator(h, 0);
    }
    TRACE("\n\rExiting %s\n\r", __FUNCTION__);
    return h;
}

/* Add Message to final Message to be sent to Server */
void my_rad_add_request(unsigned char *msg, long long *len, struct rad_handle *h)
{
    TRACE("\n\rEntering %s\n\r", __FUNCTION__);
    TRACE("\n\rin %s len %llu radlen %int\n\r", __FUNCTION__, *len, h->out_len);
    memcpy(msg + *len, &(h->out), h->out_len);
    *len = *len + h->out_len;
}

/* Initialize Final Msg handler that will hold the final message to sent to server */
int my_rad_add_send_request(struct rad_handle *h, unsigned char *msg, long long len, 
                            long long  *fd, struct timeval *tv, uint proto_tcp)
{
    int srv;
    time_t now;
    struct sockaddr_in sin;
    int n, cur_srv, ret_value = 0;

    /* Make sure we have a socket to use */
    if (h->fd == -1) 
    {
        if(proto_tcp)
        {
            if ((h->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
            {
                generr(h, "Cannot create socket: %s", strerror(errno));
                return -1;
            }
        }
        else
        {
            if ((h->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) 
            {
                generr(h, "Cannot create socket: %s", strerror(errno));
                return -1;
            }
        }
        memset(&sin, 0, sizeof sin);
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = h->bindto;
        sin.sin_port = htons(0);
        if (bind(h->fd, (const struct sockaddr *)&sin,
                    sizeof sin) == -1) {
            generr(h, "bind: %s", strerror(errno));
            LOG("\n\r!!bind error %s!!!\n\r", strerror(errno));
            close(h->fd);
            h->fd = -1;
            return -1;
        }
    }

    h->srv = 0;
    now = time(NULL);
    for (srv = 0;  srv < h->num_servers;  srv++)
        h->servers[srv].num_tries = 0;
    /* Find a first good server. */
    for (srv = 0;  srv < h->num_servers;  srv++) {
        if (h->servers[srv].is_dead == 0)
            break;
        if (h->servers[srv].dead_time &&
                h->servers[srv].next_probe <= now) {
            h->servers[srv].is_dead = 0;
            break;
        }
        h->srv++;
    }

    /* If all servers was dead on the last probe, try from beginning */
    if (h->srv == h->num_servers) {
        for (srv = 0;  srv < h->num_servers;  srv++) {
            h->servers[srv].is_dead = 0;
            h->servers[srv].next_probe = 0;
        }
        h->srv = 0;
    }

    /*
     * Scan round-robin to the next server that has some
     * tries left.  There is guaranteed to be one, or we
     * would have exited this loop by now.
     */
    cur_srv = h->srv;
    now = time(NULL);
    if (h->servers[h->srv].num_tries >= h->servers[h->srv].max_tries) {
        /* Set next probe time for this server */
        if (h->servers[h->srv].dead_time) {
            h->servers[h->srv].is_dead = 1;
            h->servers[h->srv].next_probe = now +
                h->servers[h->srv].dead_time;
        }
        do {
            h->srv++;
            if (h->srv >= h->num_servers)
                h->srv = 0;
            if (h->servers[h->srv].is_dead == 0)
                break;
            if (h->servers[h->srv].dead_time &&
                    h->servers[h->srv].next_probe <= now) {
                h->servers[h->srv].is_dead = 0;
                h->servers[h->srv].num_tries = 0;
                break;
            }
        } while (h->srv != cur_srv);

        if (h->srv == cur_srv) {
            generr(h, "No valid RADIUS responses received");
            return (-1);
        }
    }

    /* Rebind */
    if (h->bindto != h->servers[h->srv].bindto) {
        h->bindto = h->servers[h->srv].bindto;
        close(h->fd);
        if(proto_tcp)
        {
            if ((h->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                generr(h, "Cannot create socket: %s", strerror(errno));
                LOG("\n\rCannot create socket: %s", strerror(errno));
                return -1;
            }
        }
        else
        {
            if ((h->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
                generr(h, "Cannot create socket: %s", strerror(errno));
                LOG("\n\rCannot create socket: %s", strerror(errno));
                return -1;
            }
        }
        memset(&sin, 0, sizeof sin);
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = h->bindto;
        sin.sin_port = 0;
        if (bind(h->fd, (const struct sockaddr *)&sin,
                    sizeof sin) == -1) {
            generr(h, "bind: %s", strerror(errno));
            LOG("\n\rbind: %s", strerror(errno));
            close(h->fd);
            h->fd = -1;
            return (-1);
        }
    }

    memcpy(&(h->out), msg, len);
    h->out_len = len;

    if(proto_tcp)
    {
        TRACE("\n\rconnect called\n\r");
        if(connect(h->fd, (const struct sockaddr *)&h->servers[h->srv].addr,
                    sizeof h->servers[h->srv].addr) != 0)
        {
            LOG("\n\rconnect failed\n\r");
            return -1;
        }
    }

    /* Send the request */
    n = sendto(h->fd, h->out, h->out_len, 0,
            (const struct sockaddr *)&h->servers[h->srv].addr,
            sizeof h->servers[h->srv].addr);
    TRACE("\n\rlen = %d out_len %d\n\r", n, h->out_len);
    if (n != h->out_len)
        tv->tv_sec = 1; /* Do not wait full timeout if send failed. */
    else
        tv->tv_sec = h->servers[h->srv].timeout;
    h->servers[h->srv].num_tries++;
    tv->tv_usec = 0;
    *fd = h->fd;

    return 0;
}

/* Receive incoming Msg or resend the msg to Server */
int my_rad_continue_send_request(struct rad_handle *h, long long selected, long long *fd,
                             struct timeval *tv, uint proto_tcp, long long msg_count,
                             long long *recv_msg_count)
{
    long long n, cur_srv;
    time_t now;
    struct sockaddr_in sin;
    uint8_t header[4];
    long long data_len, msg_start = 0;
    uint16_t packet_len = 0;
    uint8_t recvd_pkt_id = 0;
    if (selected) {
        TRACE("\n\rselected is set\n\r");
        struct sockaddr_in from;
        socklen_t fromlen;

        fromlen = sizeof from;
        if(proto_tcp)
        {
            /* Peek the received Msg and Get the length */
            data_len = recvfrom(h->fd, header, sizeof(header), MSG_PEEK,
                    NULL, NULL);
            LOG("\n\r====== RECEIVED TCP MSG FROM SERVER ======");
            TRACE("\n\rdata_len = %llu\n\r", data_len);
            packet_len = (header[2] * 256) + header[3];
            TRACE("\n\rpacket_len = %d\n\r", packet_len);

            if(header[0] == 2)
            LOG("\n\rReceived RADIUS ACCEPT (Code = %d)", h->in[POS_CODE]);
            recvd_pkt_id = header[1];
            LOG("\n\rPacket ID %d", recvd_pkt_id);
            LOG("  Packet Len = %d", packet_len);
            /* Receive the msg upto packet length */
            h->in_len=recvfrom(h->fd,h->in,packet_len,0,NULL, NULL);
            TRACE("\n\rrecvfrom in_len %d\n\r", h->in_len);
            if (h->in_len == -1) {
                generr(h, "recvfrom: %s", strerror(errno));
                return -1;
            }
            TRACE("\n\rReceived Code %d Line %d from-h %d", 
                    h->in[POS_CODE], __LINE__, h->in[0]);
//            if (h->in[POS_CODE] == 2)
  //              LOG("\n\rReceived RADIUS ACCEPT (Code = %d)", h->in[POS_CODE]);
            (*recv_msg_count)++;
            return h->in[POS_CODE];
        }
        else
        {
            LOG("\n\r====== RECEIVED UDP MSG FROM SERVER ======");
            memset(h->in, 0, MSGSIZE);
            h->in_len=recvfrom(h->fd,h->in,MSGSIZE,0,NULL, NULL);
            TRACE("\n\rrecvfrom in_len %d\n\r", h->in_len);
            if (h->in_len == -1) {
                generr(h, "recvfrom: %s", strerror(errno));
                return -1;
            }
            data_len = h->in_len;
            msg_start = 0;
            while(msg_start < data_len)
            {
                TRACE("\n\r!!!!received code %d Line %d",
                        h->in[msg_start], __LINE__);
                if (h->in[msg_start] == 2)
                    LOG("\n\rReceived RADIUS ACCEPT (Code = %d)", h->in[POS_CODE]);
                recvd_pkt_id = h->in[msg_start+1];
                LOG("\n\rPacket ID %d", recvd_pkt_id);
                packet_len = (h->in[msg_start + 2] * 256) + h->in[msg_start + 3];
                LOG("  Packet Len = %d", packet_len);
                msg_start += packet_len;
                (*recv_msg_count)++;
            }
            TRACE("\n\r!!!!received code %d Line %d from-h %d", 
                    h->in[POS_CODE], __LINE__, h->in[0]);
            return h->in[POS_CODE];
        }
    }

    /*
     * Scan round-robin to the next server that has some
     * tries left.  There is guaranteed to be one, or we
     * would have exited this loop by now.
     */
    cur_srv = h->srv;
    now = time(NULL);
    if (h->servers[h->srv].num_tries >= h->servers[h->srv].max_tries) {
        /* Set next probe time for this server */
        if (h->servers[h->srv].dead_time) {
            h->servers[h->srv].is_dead = 1;
            h->servers[h->srv].next_probe = now +
                h->servers[h->srv].dead_time;
        }
        do {
            h->srv++;
            if (h->srv >= h->num_servers)
                h->srv = 0;
            if (h->servers[h->srv].is_dead == 0)
                break;
            if (h->servers[h->srv].dead_time &&
                    h->servers[h->srv].next_probe <= now) {
                h->servers[h->srv].is_dead = 0;
                h->servers[h->srv].num_tries = 0;
                break;
            }
        } while (h->srv != cur_srv);

        if (h->srv == cur_srv) {
            generr(h, "No valid RADIUS responses received");
            return (-1);
        }
    }

    /* Rebind */
    if (h->bindto != h->servers[h->srv].bindto) {
        h->bindto = h->servers[h->srv].bindto;
        close(h->fd);
        if(proto_tcp)
        {
            if ((h->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                generr(h, "Cannot create socket: %s", strerror(errno));
                return -1;
            }
        }
        else
        {
            if ((h->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
                generr(h, "Cannot create socket: %s", strerror(errno));
                return -1;
            }
        }
        memset(&sin, 0, sizeof sin);
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = h->bindto;
        sin.sin_port = 0;
        if (bind(h->fd, (const struct sockaddr *)&sin,
                    sizeof sin) == -1) {
            generr(h, "bind: %s", strerror(errno));
            close(h->fd);
            h->fd = -1;
            return (-1);
        }
    }

    if (h->out[POS_CODE] == RAD_ACCESS_REQUEST) {
        /* Insert the scrambled password into the request */
        if (h->pass_pos != 0)
            insert_scrambled_password(h, h->srv);
    }
    insert_message_authenticator(h, 0);

    if (h->out[POS_CODE] != RAD_ACCESS_REQUEST) {
        /* Insert the request authenticator into the request */
        memset(&h->out[POS_AUTH], 0, LEN_AUTH);
        insert_request_authenticator(h, 0);
    }

    if(proto_tcp)
    {
        TRACE("\n\rconnect called %s\n\r", __FUNCTION__);
        if(connect(h->fd, (const struct sockaddr *)&h->servers[h->srv].addr,
                    sizeof h->servers[h->srv].addr) != 0)
        {
            LOG("\n\rconnect failed\n\r");
            return -1;
        }
    }

    /* Send the request */
    n = sendto(h->fd, h->out, h->out_len, 0,
            (const struct sockaddr *)&h->servers[h->srv].addr,
            sizeof h->servers[h->srv].addr);
    TRACE("\n\rlen = %llu out_len %d\n\r", n, h->out_len);
    if (n != h->out_len)
        tv->tv_sec = 1; /* Do not wait full timeout if send failed. */
    else
        tv->tv_sec = h->servers[h->srv].timeout;
    h->servers[h->srv].num_tries++;
    tv->tv_usec = 0;
    *fd = h->fd;

    return 0;
}

/* Send the Message to RADIUS Server */
int my_rad_send_request(struct rad_handle *h, unsigned char *msg, long long len, 
                        uint proto_tcp, long long msg_count)
{
    struct timeval timelimit;
    struct timeval tv;
    long long fd;
    long long n;
    long long reply_recvd = 0;

    n = my_rad_add_send_request(h, msg, len, &fd, &tv, proto_tcp);
    if (n != 0)
        return n;

    gettimeofday(&timelimit, NULL);
    timeradd(&tv, &timelimit, &timelimit);

    for ( ; ; ) {
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);

        n = select(fd + 1, &readfds, NULL, NULL, &tv);

        if (n == -1) {
            generr(h, "select: %s", strerror(errno));
            LOG("\n\rselect: %s\n\r", strerror(errno));
            return -1;
        }

        if (!FD_ISSET(fd, &readfds)) 
        {
            /* Compute a new timeout */
            gettimeofday(&tv, NULL);
            timersub(&timelimit, &tv, &tv);
            if (tv.tv_sec > 0 || (tv.tv_sec == 0 && tv.tv_usec > 0))
            {
                LOG("\n\rcontinue the select\n\r");
                /* Continue the select */
                continue;
            }
        }

        reply_recvd = 0;
        while(reply_recvd < msg_count)
        {
            n = my_rad_continue_send_request(h, n, &fd, &tv, proto_tcp, 
                    msg_count, &reply_recvd);
            //            reply_recvd++;
            LOG("\n\rMessage count - %llu\n\r", reply_recvd);
        }

        if (n != 0)
            return n;

        gettimeofday(&timelimit, NULL);
        timeradd(&tv, &timelimit, &timelimit);
    }
}
