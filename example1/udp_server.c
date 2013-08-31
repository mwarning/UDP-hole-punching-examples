// UDP hole punching example, server code
// Base UDP code stolen from http://www.abc.se/~m6695/udp.html
// By Oscar Rodriguez
// This code is public domain, but you're a complete lunatic
// if you plan to use this code in any real program.
 
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
 
#define BUFLEN 512
#define NPACK 10
#define PORT 9930
 
// A small struct to hold a UDP endpoint. We'll use this to hold each client's endpoint.
struct client
{
    int host;
    short port;
};
 
// Just a function to kill the program when something goes wrong.
void diep(char *s)
{
    perror(s);
    exit(1);
}
 
int main(void)
{
    struct sockaddr_in si_me, si_other;
    int s, i, j, slen=sizeof(si_other);
    char buf[BUFLEN];
    struct client clients[10]; // 10 clients. Notice that we're not doing any bound checking.
    int n = 0;
 
    // Create a UDP socket
    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
        diep("socket");
 
    // si_me stores our local endpoint. Remember that this program
    // has to be run in a network with UDP endpoint previously known
    // and directly accessible by all clients. In simpler terms, the
    // server cannot be behind a NAT.
    memset((char *) &si_me, 0, sizeof(si_me));
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr*)(&si_me), sizeof(si_me))==-1)
        diep("bind");
 
    while (1)
    {
        // When a new client sends a datagram...
        if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr*)(&si_other), &slen)==-1)
            diep("recvfrom");
        // The client's public UDP endpoint data is now in si_other.
        // Notice that we're completely ignoring the datagram payload.
        // If we want to support multiple clients inside the same NAT,
        // we'd have clients send their own private UDP endpoints
        // encoded in some way inside the payload, and store those as
        // well.
        printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
        // Now we add the client's UDP endpoint in our list.
        clients[n].host = si_other.sin_addr.s_addr;
        clients[n].port = si_other.sin_port;
        n++;
        // And then tell everybody about everybody's public UDP endpoints
        for (i = 0; i < n; i++)
        {
            si_other.sin_addr.s_addr = clients[i].host;
            si_other.sin_port = clients[i].port;
            // We send a datagram for each client in our list. Of course,
            // we could also assemble a single datagram and send that.
            for (j = 0; j < n; j++)
            {
                // The payload is the client's public UDP endpoint, clients[j]
                printf("Sending to %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
                // We're sending binary data here, using the server's byte order.
                // In your code, you should make sure every client agrees on the endianness.
                if (sendto(s, &clients[j], 6, 0, (struct sockaddr*)(&si_other), slen)==-1)
                    diep("sendto");
            }
        }
        printf("Now we have %d clients\n", n);
        // And we go back to listening. Notice that since UDP has no notion
        // of connections, we can use the same socket to listen for data
        // from different clients.
    }
 
    // Actually, we never reach this point...
    close(s);
    return 0;
}