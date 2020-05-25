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


enum { CSTATE_ESTABLISHED, SYN_SEND, SYN_RECV, LISTEN, CSTATE_CLOSED, FIN_SENT, ACK_SEND, ACK_RECV };    /* you should have more states */
const int SIZE = 536; //maximum segment size
const long WINDOWLENGTH = 3072;

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    unsigned int sequence_num;      // next sequence number to send
    unsigned int rec_sequence_num;  // next wanted sequence number
    unsigned int rec_window_size;
    /* any other connection-wide global variables go here */
} context_t;

typedef struct
{
    STCPHeader hdr;
    char buff[SIZE];
} packet;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
bool sendACK(mysocket_t sd, context_t* ctx);
packet* createACK(unsigned int seq, unsigned int ack);
packet* createFIN(unsigned int seq, unsigned int ack);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
 void transport_init(mysocket_t sd, bool_t is_active)
 {
     context_t *ctx;
     packet *pack;
     unsigned int event;

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
      printf("establishing connection\n");
      if(is_active){
        printf("is active, building and sending SYN\n");
        //build SYN packet and send it
        pack->hdr.th_seq = ctx->initial_sequence_num;
        pack->hdr.th_ack = NULL;
        pack->hdr.th_flags = TH_SYN;
        pack->hdr.th_win = htonl(WINDOWLENGTH);
        ssize_t sent = stcp_network_send(sd, (void *) pack, sizeof(packet), NULL);
        if (sent < 0){
          free(ctx);
          free(pack);
          return;
        }

        ctx->connection_state = SYN_SEND;

        //wait for acknowledgement
        tcp_seq ack_expected = pack->hdr.th_seq+1;
        event = stcp_wait_for_event(sd, NETWORK_DATA|APP_CLOSE_REQUESTED, NULL);
        if (event == APP_CLOSE_REQUESTED)
        {
          free(ctx);
          free(pack);
          return;
        }

        //recieved acknowledgement
        ssize_t recv = stcp_network_recv(sd, (void *) pack, sizeof(packet));
        ctx->connection_state = ACK_RECV;
        if((unsigned int)recv < sizeof(packet)){
          free(ctx);
          free(pack);
          return;
        }
        printf("Recieved packet with seq: %i \n", (int)pack->hdr.th_seq);
        printf("Recieved packet with seq: %i \n", (int)pack->hdr.th_ack);
        //build acknowledgement packet and send it
        pack->hdr.th_seq = pack->hdr.th_seq;
        pack->hdr.th_ack = pack->hdr.th_seq + 1;
        pack->hdr.th_flags = TH_ACK;
        pack->hdr.th_win = htonl(WINDOWLENGTH);
        sent = stcp_network_send(sd, (void *) pack, sizeof(packet),NULL);
        ctx->connection_state = ACK_SEND;
        if (sent < 0)
        {
          free(ctx);
          free(pack);
          return;
        }
      }
      //not active and must listen
      else
      {
        printf("Listening\n");
        ctx->connection_state = LISTEN;
        event = stcp_wait_for_event(sd, NETWORK_DATA|APP_CLOSE_REQUESTED, NULL);
        if (event == APP_CLOSE_REQUESTED)
        {
          free(ctx);
          free(pack);
          return;
        }
        stcp_network_recv(sd, (void *) pack, sizeof(packet));
        ctx->connection_state = SYN_RECV;

        if(pack->hdr.th_flags == TH_SYN)
        {
          pack->hdr.th_ack = pack->hdr.th_seq + 1;
          pack->hdr.th_seq = ctx->initial_sequence_num;
          pack->hdr.th_flags = TH_ACK|TH_SYN;
          pack->hdr.th_win = htonl(WINDOWLENGTH);
          stcp_network_send(sd, (void *) pack, sizeof(packet), NULL);
          ctx->connection_state = ACK_SEND;

          //wait for response
          event = stcp_wait_for_event(sd, NETWORK_DATA|APP_CLOSE_REQUESTED, NULL);
          if (event == APP_CLOSE_REQUESTED)
          {
            free(ctx);
            free(pack);
            return;
          }
          ssize_t recv = stcp_network_recv(sd, (void *) pack, sizeof(packet));
          ctx->connection_state = ACK_RECV;
          if((unsigned int) recv < sizeof(packet))
          {
            free(ctx);
            free(pack);
            return;
          }
        }
      }
      printf("Connection established, entering control loop\n");
     ctx->connection_state = CSTATE_ESTABLISHED;
     stcp_unblock_application(sd);

     control_loop(sd, ctx);

     /* do any cleanup here */
     free(ctx);
     free(pack);
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
                continue;
            }

            STCPHeader* payloadHeader = (STCPHeader*)payload;
            ctx->rec_sequence_num = ntohl(payloadHeader->th_seq);
            ctx->rec_window_size = ntohs(payloadHeader->th_win);

            if (payloadHeader->th_flags == TH_FIN)
            {
                sendACK(sd, ctx);
                stcp_fin_received(sd);
                ctx->connection_state = CSTATE_CLOSED;
                continue;
            }

            if (network_bytes - sizeof(STCPHeader) != 0)
            {
                stcp_app_sent(sd, payload + sizeof(STCPHeader), network_bytes - sizeof(STCPHeader));
                sendACK(sd, ctx);
            }
        }

        if (event & APP_CLOSE_REQUESTED)
        {
            if (ctx->connection_state == CSTATE_ESTABLISHED)
            {
                packet* FIN_packet = createFIN(ctx->sequence_num, ctx->rec_sequence_num + 1);
                ctx->sequence_num++;

                ssize_t sentBytes = stcp_network_send(sd, FIN_packet, sizeof(STCPHeader), NULL);

                free(FIN_packet);

                if (sentBytes > 0){
                    ctx->connection_state = FIN_SENT;
                    wait_for_ACK(sd, ctx);
                    continue;
                }

                free(FIN_packet);
                free(ctx);
                errno = ECONNREFUSED;
                break;
            }
        }
        /* etc. */
    }
}

bool sendACK(mysocket_t sd, context_t* ctx)
{

    // Create ACK Packet
    packet* ACK_packet = createACK(ctx->sequence_num, ctx->rec_sequence_num + 1);

    // Send ACK
    ssize_t sentBytes = stcp_network_send(sd, ACK_packet, sizeof(STCPHeader), NULL);

    free(ACK_packet);

    if (sentBytes > 0)
    {
        return false;
    }

    free(ctx);
    errno = ECONNREFUSED;
    return true;

}

packet* createACK(unsigned int seq, unsigned int ack)
{
    packet* ACK = (STCPHeader*)malloc(sizeof(STCPHeader));
    ACK->hdr.th_flags = TH_ACK;
    ACK->hdr.th_seq = htonl(seq);
    ACK->hdr.th_ack = htonl(ack);
    ACK->hdr.th_off = htons(5);
    ACK->hdr.th_win = htons(WINDOWLENGTH);
    return ACK;
}

void wait_for_ACK(mysocket_t sd, context_t* ctx)
{
    char buffer[sizeof(STCPHeader)];

    unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

    ssize_t receivedBytes = stcp_network_recv(sd, buffer, SIZE);

    if (receivedBytes < sizeof(STCPHeader))
    {
        free(ctx);
        errno = ECONNREFUSED;
        return;
    }

    STCPHeader* receivedPacket = (STCPHeader*)buffer;

    if (receivedPacket->th_flags == TH_ACK)
    {
        ctx->rec_sequence_num = ntohl(receivedPacket->th_seq);
        ctx->rec_window_size = ntohs(receivedPacket->th_win) > 0 ? ntohs(receivedPacket->th_win) : 1;
        if (ctx->connection_state == FIN_SENT)
        {
            ctx->connection_state = CSTATE_CLOSED;
        }
    }
}

packet* createFIN(unsigned int seq, unsigned int ack)
{
    packet* FIN = (STCPHeader*)malloc(sizeof(STCPHeader));
    FIN->hdr.th_flags = TH_FIN;
    FIN->hdr.th_seq = htonl(seq);
    FIN->hdr.th_ack = htonl(ack);
    FIN->hdr.th_off = htons(5);
    FIN->hdr.th_win = htons(WINDOWLENGTH);
    return FIN;
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
