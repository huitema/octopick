
#include <WinSock2.h>
#include <iphlpapi.h>
#include <Ws2ipdef.h>
#include <ws2tcpip.h>
#include "../OctoPair/LocalAddress.h"

static struct in6_addr mdns_mcast6 = {
	{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB }
};

int LocalAddressDoTest()
{
	// Init WSA.
	WSADATA wsaData;
	int ret = 0;
	struct in6_addr addr6;
	// char address[256];
	int sock, usock, tsock;
	int port, uport, tport;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		// fprintf(stderr, "Cannot init WSA\n");
		return -1;
	}

	ret = GetLocalAddress(&addr6);

	//printf("GetLocalAddress: ret=%d (%s), %s\n", ret, WsaErrorText(ret), inet_ntop(AF_INET6, &addr6, address, sizeof(address)));

	if (ret == 0)
	{
		ret = OpenMulticastSocket(NULL, 5353, &mdns_mcast6, 255, &sock);

		// printf("OpenMulticastSocket: ret=%d (%s), sock=%d\n", ret, WsaErrorText(ret), sock);
	}

	if (ret == 0)
	{
		ret = GetSocketPortNumber(sock, &port);
		// printf("GetSocketPortNumber (mcast): ret=%d (%s), port=%d\n", ret, WsaErrorText(ret), port);
	}

	if (ret == 0)
	{
		ret = OpenUdpSocket(&addr6, 0, &usock);
		// printf("OpenUDPSocket: ret=%d (%s), sock=%d\n", ret, WsaErrorText(ret), usock);
	}

	if (ret == 0)
	{
		ret = GetSocketPortNumber(usock, &uport);
		// printf("GetSocketPortNumber (udp): ret=%d (%s), port=%d\n", ret, WsaErrorText(ret), uport);
	}

	if (ret == 0)
	{
		ret = OpenTcpSocket(&addr6, 0, 16, &tsock);
		// printf("OpenTCPSocket: ret=%d (%s), sock=%d\n", ret, WsaErrorText(ret), tsock);
	}

	if (ret == 0)
	{
		ret = GetSocketPortNumber(tsock, &tport);
		// printf("GetSocketPortNumber (tcp): ret=%d (%s), port=%d\n", ret, WsaErrorText(ret), tport);
	}

	closesocket(sock);
	closesocket(usock);
	closesocket(tsock);

	return ret;
}