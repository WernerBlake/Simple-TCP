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

    tcp_seq sequence_num;      // next sequence number to send
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
void wait_for_ACK(mysocket_t sd, context_t* ctx);


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
      ctx->sequence_num = ctx->initial_sequence_num;
      if(is_active){
        printf("___is active___\n");
        ctx->sequence_num = 1;
        //build SYN packet and send it
        pack->hdr.th_seq = htonl(ctx->initial_sequence_num);
        pack->hdr.th_flags = TH_SYN;
        pack->hdr.th_win = htonl(WINDOWLENGTH);
        pack->hdr.th_off = 5;
        printf("Sent packet with seq: %i \n", (int)pack->hdr.th_seq);
        printf("Sent packet with ack: %i \n", (int)pack->hdr.th_ack);
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
        printf("Recieved packet with seq: %i \n", (int)ntohl(pack->hdr.th_seq));
        printf("Recieved packet with ack: %i \n", (int)ntolh(pack->hdr.th_ack));

        if(ntohl(pack->hdr.th_ack) != ack_expected){
          printf("Unexpected acknowledgement, closing down")
          free(ctx);
          free(pack);
          return;
        }
        //build acknowledgement packet and send it
        ctx->sequence_num++;
        pack->hdr.th_ack = htonl(ntohl(pack->hdr.th_seq) + 1);
        pack->hdr.th_seq = htonl(ctx->sequence_num);
        pack->hdr.th_flags = TH_ACK;
        pack->hdr.th_win = htonl(WINDOWLENGTH);
        pack->hdr.th_off = 5;
        sent = stcp_network_send(sd, (void *) pack, sizeof(packet),NULL);
        printf("Sent packet with seq: %i \n", (int)pack->hdr.th_seq);
        printf("Sent packet with ack: %i \n", (int)pack->hdr.th_ack);
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
        printf("___Listening___\n");
        ctx->connection_state = LISTEN;
        event = stcp_wait_for_event(sd, NETWORK_DATA|APP_CLOSE_REQUESTED, NULL);
        if (event == APP_CLOSE_REQUESTED)
        {
          free(ctx);
          free(pack);
          return;
        }
        if(event & NETWORK_DATA)
        {
          stcp_network_recv(sd, (void *) pack, sizeof(packet));
          printf("Recieved packet with seq: %i \n", (int)pack->hdr.th_seq);
          printf("Recieved packet with ack: %i \n", (int)pack->hdr.th_ack);
          if(pack->hdr.th_flags == TH_SYN)
          {
            ctx->connection_state = SYN_RECV;
            printf("SYN flag Recieved \n");
            pack->hdr.th_ack = htonl(ntohl(pack->hdr.th_seq) + 1);
            pack->hdr.th_seq = htonl(ctx->initial_sequence_num);
            pack->hdr.th_flags = TH_ACK|TH_SYN;
            pack->hdr.th_win = htonl(WINDOWLENGTH);
            pack->hdr.th_off = 5;
            printf("Sent packet with seq: %i \n", (int)pack->hdr.th_seq);
            printf("Sent packet with ack: %i \n", (int)pack->hdr.th_ack);
            stcp_network_send(sd, (void *) pack, sizeof(packet), NULL);
            ctx->sequence_num++;
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
            printf("Recieved packet with seq: %i \n", (int)pack->hdr.th_seq);
            printf("Recieved packet with ack: %i \n", (int)pack->hdr.th_ack);
            ctx->connection_state = ACK_RECV;
            if((unsigned int) recv < sizeof(packet))
            {
              free(ctx);
              free(pack);
              return;
            }
          }
        }
      }
      printf("-----------------------------------------------\n");
      printf("Connection established, entering control loop\n");
     ctx->connection_state = CSTATE_ESTABLISHED;
     stcp_unblock_application(sd);

     control_loop(sd, ctx);

     /* do any cleanup here */
     free(ctx);
     free(pack);
     printf("---------------------CLOSED-------------------\n");
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
        printf("Waiting for event\n");
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
        printf("recieved event: %i\n", event);
        /* check whether it was the network, app, or a close request */
        // I'm going to kms this project omg
        if (event & APP_DATA)
        {
           printf("control_loop: APP_DATA\n");
            if (ctx->connection_state != CSTATE_ESTABLISHED){
                printf("APP_DATA: wrong connection state: %d\n", ctx->connection_state);
                continue;
            }
            //Sends data from app
            packet *send_segment;
            send_segment=(packet*)malloc(sizeof(packet));
            size_t data_length = stcp_app_recv(sd, (void *)send_segment->buff, SIZE-1);
            printf("recieved data from app : %s \n", send_segment->buff);
            printf("buffer data transfered : %d \n", data_length);

            send_segment->hdr.th_seq = ctx->sequence_num;
            send_segment->hdr.th_win = htonl(WINDOWLENGTH);
            send_segment->hdr.th_off = 5;
            stcp_network_send(sd, send_segment, sizeof(packet), NULL);
            printf("Sent packet with seq: %i \n", (int)send_segment->hdr.th_seq);
            ctx->sequence_num++;
            wait_for_ACK(sd, ctx);
            //Keep recieving data from application and sending it until no more
            while ((int) data_length > SIZE-1)
            {
              data_length = stcp_app_recv(sd, (void *)send_segment->buff, SIZE-1);
              printf("recieved data from app : %s \n", send_segment->buff);
              printf("buffer data transfered : %d \n", data_length);

              send_segment->hdr.th_seq=ctx->sequence_num;
              send_segment->hdr.th_win=htonl(WINDOWLENGTH);
              send_segment->hdr.th_off=5;
              stcp_network_send(sd, (void *)send_segment, sizeof(packet), NULL);
              printf("Sent packet with seq: %i \n", (int)send_segment->hdr.th_seq);
              //ctx->initial_sequence_num+=strlen(send_segment->buff);
              ctx->sequence_num++;
              wait_for_ACK(sd, ctx);
            }
            //finished transfering data now we gotta send a FIN packet
            printf("done transfering data \n");
            send_segment->hdr.th_seq = ctx->sequence_num;
            send_segment->hdr.th_flags = TH_FIN;
            stcp_network_send(sd, send_segment, sizeof(packet), NULL);
            printf("Sent packet with seq: %i \n", (int)send_segment->hdr.th_seq);
            printf("Sent TH_FIN flag\n");
            // wait for server to acknowledge our FIN then begin closing
            wait_for_ACK(sd, ctx);
            ctx->done = true;
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            free(send_segment);
            printf("CLOSING!\n");
        }
        if (event & NETWORK_DATA)
        {
            printf("control loop: NETWORK_DATA\n");
            char payload[SIZE];

            packet* pack;
            packet* send_pack;
            pack = (packet *) calloc(1, sizeof(packet));
            send_pack = (packet *) calloc(1, sizeof(packet));

            ssize_t network_bytes = stcp_network_recv(sd, (void *) pack, sizeof(packet));
            printf("recieved packet with seq: %i \n", (int)pack->hdr.th_seq);
            if (pack->hdr.th_flags == TH_FIN){
              printf("FIN recieved closing!\n");

              send_pack->hdr.th_seq = ctx->sequence_num;
              send_pack->hdr.th_flags = TH_ACK;
              send_pack->hdr.th_ack = pack->hdr.th_seq + 1;
              stcp_network_send(sd, (void *) send_pack, sizeof(packet), NULL);
              ctx->sequence_num++;
               //send FIN
              send_pack->hdr.th_seq = ctx->sequence_num;
              send_pack->hdr.th_flags = TH_FIN;
              stcp_network_send(sd, send_pack, sizeof(packet), NULL);
              ctx->sequence_num++;
              //wait for ACK
              wait_for_ACK(sd, ctx);
              //We are done and can close
              ctx->done = true;
              free(pack);
              free(send_pack);
            }

            else{
              //recieved data from server
              printf("data in packet: %s \n", pack->buff);
              stcp_app_send(sd, (void *) pack->buff, SIZE);
              send_pack->hdr.th_seq = ctx->sequence_num;
              send_pack->hdr.th_flags = TH_ACK;
              send_pack->hdr.th_ack = pack->hdr.th_seq + 1;
              stcp_network_send(sd, (void *) send_pack, sizeof(packet), NULL);
              ctx->sequence_num++;
              printf("sending ACK: %d \n", send_pack->hdr.th_ack);
            }
            /*
            printf("pack seq : %i \n", pack->hdr.th_seq);
            if (network_bytes < sizeof(STCPHeader))
            {
                free(pack);
                ctx->done = true;
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
                ctx->done = true;
                continue;
            }

            if (network_bytes - sizeof(STCPHeader) != 0)
            {
                stcp_app_send(sd, payload + sizeof(STCPHeader), network_bytes - sizeof(STCPHeader));
                sendACK(sd, ctx);
            }*/
        }

        if (event & APP_CLOSE_REQUESTED)
        {
            printf("control loop: APP_CLOSE_REQUESTED");
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
                errno = ECONNREFUSED;
                ctx->done = true;
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

    //free(ctx);
    errno = ECONNREFUSED;
    return true;

}

packet* createACK(unsigned int seq, unsigned int ack)
{
    packet* ACK = (packet*)malloc(sizeof(packet));
    ACK->hdr.th_flags = TH_ACK;
    ACK->hdr.th_seq = htonl(seq);
    ACK->hdr.th_ack = htonl(ack);
    ACK->hdr.th_off = htons(5);
    ACK->hdr.th_win = htons(WINDOWLENGTH);
    return ACK;
}

void wait_for_ACK(mysocket_t sd, context_t* ctx)
{
    printf("waiting for ACK \n");
    char buffer[sizeof(STCPHeader)];

    unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

    ssize_t receivedBytes = stcp_network_recv(sd, buffer, SIZE);

    printf("if 1 \n");
    if (receivedBytes < sizeof(STCPHeader))
    {
        //free(ctx);
        errno = ECONNREFUSED;
        return;
    }

    printf("if 1 end \n");
    STCPHeader* receivedPacket = (STCPHeader*)buffer;

    printf("if 2 \n");
    if (receivedPacket->th_flags == TH_ACK)
    {
        ctx->rec_sequence_num = ntohl(receivedPacket->th_seq);
        ctx->rec_window_size = ntohs(receivedPacket->th_win) > 0 ? ntohs(receivedPacket->th_win) : 1;

        printf("if 3 \n");
        if (ctx->connection_state == FIN_SENT)
        {
            ctx->connection_state = CSTATE_CLOSED;
        }
    }
    printf("end of wait \n");

}

packet* createFIN(unsigned int seq, unsigned int ack)
{
    packet* FIN = (packet*)malloc(sizeof(packet));
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
