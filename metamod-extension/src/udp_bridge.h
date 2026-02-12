#ifndef _SMARTBOTS_UDP_BRIDGE_H_
#define _SMARTBOTS_UDP_BRIDGE_H_

// Non-blocking UDP socket wrapper for C++ <-> Python communication.
// All I/O happens on the main thread from GameFrame — no threads needed.

// Initialize the UDP socket. Returns true on success.
// destHost/destPort specify the Python brain's listen address.
bool UdpBridge_Init(const char *destHost, int destPort);

// Close the socket and release resources.
void UdpBridge_Close();

// Send data to the Python brain. Returns true on success.
bool UdpBridge_Send(const char *data, int len);

// Non-blocking receive. Returns bytes read, 0 if nothing available, -1 on error.
int UdpBridge_Recv(char *buf, int bufSize);

#endif // _SMARTBOTS_UDP_BRIDGE_H_
