#include "udp_bridge.h"

#include <ISmmPlugin.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>

extern ISmmAPI *g_SMAPI;

static int s_sockfd = -1;
static struct sockaddr_in s_destAddr;

bool UdpBridge_Init(const char *destHost, int destPort)
{
    if (s_sockfd >= 0)
    {
        META_CONPRINTF("[SmartBots] UDP bridge already initialized\n");
        return true;
    }

    s_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (s_sockfd < 0)
    {
        META_CONPRINTF("[SmartBots] ERROR: socket() failed: %s\n", strerror(errno));
        return false;
    }

    // Set non-blocking
    int flags = fcntl(s_sockfd, F_GETFL, 0);
    if (flags < 0 || fcntl(s_sockfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        META_CONPRINTF("[SmartBots] ERROR: fcntl(O_NONBLOCK) failed: %s\n", strerror(errno));
        close(s_sockfd);
        s_sockfd = -1;
        return false;
    }

    // Set destination address (Python brain)
    memset(&s_destAddr, 0, sizeof(s_destAddr));
    s_destAddr.sin_family = AF_INET;
    s_destAddr.sin_port = htons(destPort);
    if (inet_pton(AF_INET, destHost, &s_destAddr.sin_addr) != 1)
    {
        META_CONPRINTF("[SmartBots] ERROR: invalid host address: %s\n", destHost);
        close(s_sockfd);
        s_sockfd = -1;
        return false;
    }

    META_CONPRINTF("[SmartBots] UDP bridge initialized (%s:%d)\n", destHost, destPort);
    return true;
}

void UdpBridge_Close()
{
    if (s_sockfd >= 0)
    {
        close(s_sockfd);
        s_sockfd = -1;
        META_CONPRINTF("[SmartBots] UDP bridge closed\n");
    }
}

bool UdpBridge_Send(const char *data, int len)
{
    if (s_sockfd < 0)
        return false;

    ssize_t sent = sendto(s_sockfd, data, len, 0,
                          (struct sockaddr *)&s_destAddr, sizeof(s_destAddr));
    if (sent < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            META_CONPRINTF("[SmartBots] UDP send error: %s\n", strerror(errno));
        }
        return false;
    }
    return true;
}

int UdpBridge_Recv(char *buf, int bufSize)
{
    if (s_sockfd < 0)
        return -1;

    ssize_t received = recvfrom(s_sockfd, buf, bufSize, 0, nullptr, nullptr);
    if (received < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;  // No data available
        return -1;     // Real error
    }
    return (int)received;
}
