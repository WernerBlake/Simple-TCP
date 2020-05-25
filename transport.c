/*
 * transport.c
 *
 * CPSC4510: Project 3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file.
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"


enum { CSTATE_ESTABLISHED, SYN_SEND, SYN_RECV, LISTEN, CSTATE_CLOSED };    /* you should have more states */
const int SIZE = 536; //maximum segment size
const long WINDOWLENGTH = 3072;

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    unsigned int next_sequence_num;      // next sequence number to send
    unsigned int rec_sequence_num;  // next wanted sequence number
    unsigned int rec_window_size;
    /* any other connection-wide global variables go here */
} context_t;

typedef struct
{
    tcphdr hdr;
    char buff[SIZE];
} packet;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
bool sendACK(mysocket_t sd, context_t* ctx);
STCPHeader* createACK(unsigned int seq, unsigned int ack);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;
    packet *pack;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    pack = (packet *) calloc(1, sizeof(packet));
    assert(pack);
    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

     if(is_active){
       //build SYN packet and send it
       pack->hdr.th_seq = ctx->initial_sequence_num;
       //pack->hdr.th_ack = "\0";
       pack->hdr.th_flags = TH_SYN;
       pack->hdr.th_win = htonl(WINDOWLENGTH);
       stcp_network_send(sd, (void *) pack, sizeof(packet), NULL);

       ctx->connection_state = SYN_SEND;

       //wait for acknowledgement
       tcp_seq ack_expected = pack->hdr.th_seq+1;
       stcp_wait_for_event(sd, NETWORK_DATA|APP_CLOSE_REQUESTED, NULL);

       //recieved acknowledgement
       stcp_network_recv(sd, (void *) pack, sizeof(packet));

       //build acknowledgement packet and send it
       pack->hdr.th_seq = pack->hdr.th_seq;
       pack->hdr.th_ack = pack->hdr.th_seq + 1;
       pack->hdr.th_flags = TH_ACK;
       pack->hdr.th_win = htonl(WINDOWLENGTH);
       stcp_network_send(sd, (void *) pack, sizeof(packet),NULL);
     }
     //not active and must listen
     else
     {
       ctx->connection_state = LISTEN;
       stcp_wait_for_event(sd, NETWORK_DATA|APP_CLOSE_REQUESTED, NULL);

       stcp_app_recv(sd, (void *) pack, sizeof(packet));
       ctx->connection_state = SYN_RECV;

       if(pack->hdr.th_flags & TH_SYN)
       {
         pack->hdr.th_ack = pack->hdr.th_seq + 1;
         pack->hdr.th_seq = ctx->initial_sequence_num;
         pack->hdr.th_flags = TH_ACK|TH_SYN;
         pack->hdr.th_win = htonl(WINDOWLENGTH);
         stcp_network_send(sd, (void *) pack, sizeof(packet), NULL);

         //wait for response
         stcp_wait_for_event(sd, NETWORK_DATA|APP_CLOSE_REQUESTED, NULL);
         stcp_app_recv(sd, (void *) pack, sizeof(packet));
       }
     }
    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    srand(time(0));
    ctx->initial_sequence_num = rand() % 256;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    assert(!ctx->done);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, 0, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
        }
        if (event & NETWORK_DATA)
        {
            char payload[SIZE];

            ssize_t network_bytes = stcp_network_recv(sd, payload, SIZE);
            if (network_bytes < sizeof(STCPHeader))
            {
                free(ctx);
                return;
            }

            STCPHeader* payloadHeader = (STCPHeader*)payload;
            ctx->rec_sequence_num = ntohl(payloadHeader->th_seq);
            ctx->rec_window_size = ntohs(payloadHeader->th_win);

            if (payloadHeader->th_flags == TH_FIN)
            {
                sendACK(sd, ctx);
                stcp_fin_received(sd);
                ctx->connection_state = CSTATE_CLOSED;
                return;
            }

            if (network_bytes - sizeof(STCPHeader))
            {
                stcp_app_sent(sd, payload + sizeof(STCPHeader), network_bytes - sizeof(STCPHeader));
                sendACK(sd, ctx);
            }
        }

        if (event & APP_CLOSE_REQUESTED)
        {

        }
        /* etc. */
    }
}

bool sendACK(mysocket_t sd, context_t* ctx)
{
    // printf("Sending ACK\n");
    // Create ACK Packet
    STCPHeader* ACK_packet =
        createACK(ctx->next_sequence_num, ctx->rec_sequence_num + 1);

    // Send ACK packet
    ssize_t sentBytes =
        stcp_network_send(sd, ACK_packet, sizeof(STCPHeader), NULL);

    // Verify sending of ACK packet
    if (sentBytes > 0)
    {  // If ACK packet suucessfully sent
        free(ACK_packet);
        return true;
    }
    else
    {
        free(ACK_packet);
        free(ctx);
        // stcp_unblock_application(sd);
        errno = ECONNREFUSED;  // TODO
        return false;
    }
}

STCPHeader* createACK(unsigned int seq, unsigned int ack)
{
    STCPHeader* ACK = (STCPHeader*)malloc(sizeof(STCPHeader));
    ACK->th_flags = TH_ACK;
    ACK->th_seq = htonl(seq);
    ACK->th_ack = htonl(ack);
    ACK->th_off = htons(5);
    ACK->th_win = htons(WINDOWLENGTH);
    return ACK;
}
/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 *
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}
