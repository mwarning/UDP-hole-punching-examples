// UDP hole punching example, client code
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
 
// This is our server's IP address. In case you're wondering, this one is an RFC 5737 address.
#define SRV_IP "203.0.113.61"
 
// A small struct to hold a UDP endpoint. We'll use this to hold each peer's endpoint.
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
 
int main(int argc, char* argv[])
{
    struct sockaddr_in si_me, si_other;
    int s, i, f, j, k, slen=sizeof(si_other);
    struct client buf;
    struct client server;
    struct client peers[10]; // 10 peers. Notice that we're not doing any bound checking.
    int n = 0;
 
    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
        diep("socket");
 
    // Our own endpoint data
    memset((char *) &si_me, 0, sizeof(si_me));
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(PORT); // This is not really necessary, we can also use 0 (any port)
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
 
    // The server's endpoint data
    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(PORT);
    if (inet_aton(SRV_IP, &si_other.sin_addr)==0)
        diep("aton");
 
    // Store the server's endpoint data so we can easily discriminate between server and peer datagrams.
    server.host = si_other.sin_addr.s_addr;
    server.port = si_other.sin_port;
 
    // Send a simple datagram to the server to let it know of our public UDP endpoint.
    // Not only the server, but other clients will send their data through this endpoint.
    // The datagram payload is irrelevant, but if we wanted to support multiple
    // clients behind the same NAT, we'd send our won private UDP endpoint information
    // as well.
    if (sendto(s, "hi", 2, 0, (struct sockaddr*)(&si_other), slen)==-1)
        diep("sendto");
 
    // Right here, our NAT should have a session entry between our host and the server.
    // We can only hope our NAT maps the same public endpoint (both host and port) when we
    // send datagrams to other clients using our same private endpoint.
    while (1)
    {
        // Receive data from the socket. Notice that we use the same socket for server and
        // peer communications. We discriminate by using the remote host endpoint data, but
        // remember that IP addresses are easily spoofed (actually, that's what the NAT is
        // doing), so remember to do some kind of validation in here.
        if (recvfrom(s, &buf, sizeof(buf), 0, (struct sockaddr*)(&si_other), &slen)==-1)
            diep("recvfrom");
        printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
        if (server.host == si_other.sin_addr.s_addr && server.port == (short)(si_other.sin_port))
        {
            // The datagram came from the server. The server code is set to send us a
            // datagram for each peer, in which the payload contains the peer's UDP
            // endpoint data. We're receiving binary data here, sent using the server's
            // byte ordering. We should make sure we agree on the endianness in any
            // serious code.
            f = 0;
            // Now we just have to add the reported peer into our peer list
            for (i = 0; i < n && f == 0; i++)
            {
                if (peers[i].host == buf.host && peers[i].port == buf.port)
                {
                    f = 1;
                }
            }
            // Only add it if we didn't have it before.
            if (f == 0)
            {
                peers[n].host = buf.host;
                peers[n].port = buf.port;
                n++;
            }
            si_other.sin_addr.s_addr = buf.host;
            si_other.sin_port = buf.port;
            printf("Added peer %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
            printf("Now we have %d peers\n", n);
            // And here is where the actual hole punching happens. We are going to send
            // a bunch of datagrams to each peer. Since we're using the same socket we
            // previously used to send data to the server, our local endpoint is the same
            // as before.
            // If the NAT maps our local endpoint to the same public endpoint
            // regardless of the remote endpoint, after the first datagram we send, we
            // have an open session (the hole punch) between our local endpoint and the
            // peer's public endpoint. The first datagram will probably not go through
            // the peer's NAT, but since UDP is stateless, there is no way for our NAT
            // to know that the datagram we sent got dropped by the peer's NAT (well,
            // our NAT may get an ICMP Destination Unreachable, but most NATs are
            // configured to simply discard them) but when the peer sends us a datagram,
            // it will pass through the hole punch into our local endpoint.
            for (k = 0; k < 10; k++)
            {
                // Send 10 datagrams.
                for (i = 0; i < n; i++)
                {
                    si_other.sin_addr.s_addr = peers[i].host;
                    si_other.sin_port = peers[i].port;
                    // Once again, the payload is irrelevant. Feel free to send your VoIP
                    // data in here.
                    if (sendto(s, "hi", 2, 0, (struct sockaddr*)(&si_other), slen)==-1)
                        diep("sendto()");
                }
            }
        }
        else
        {
            // The datagram came from a peer
            for (i = 0; i < n; i++)
            {
                // Identify which peer it came from
                if (peers[i].host == buf.host && peers[i].port == (short)(buf.port))
                {
                    // And do something useful with the received payload
                    printf("Received from peer %d!\n", i);
                    break;
                }
            }
 
            // It is possible to get data from an unregistered peer. These are some reasons
            // I quickly came up with, in which this can happen:
            // 1. The server's datagram notifying us with the peer's address got lost,
            //    or it hasn't arrived yet (likely)
            // 2. A malicious (or clueless) user is sending you data on this endpoint (maybe
            //    unlikely)
            // 3. The peer's public endpoint changed either because the session timed out,
            //    or because its NAT did not assign the same public endpoint when sending
            //    datagrams to different remote endpoints. If this happens, and we're able
            //    to detect this situation, we could change our peer's endpoint data to
            //    the correct one. If we manage to pull this off correctly, even if at most
            //    one client has a NAT that doesn't support hole punching, we can communicate
            //    directly between both peers.
        }
    }
 
    // Actually, we never reach this point...
    close(s);
    return 0;
}