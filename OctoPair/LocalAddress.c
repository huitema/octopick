#ifndef USE_WINSOCK
#define USE_WINSOCK

#include <WinSock2.h>
#include <iphlpapi.h>
#include <Ws2ipdef.h>
#include <ws2tcpip.h>
#endif

#include "LocalAddress.h"

int GetLocalAddress(struct in6_addr * addr6)
{
	char name[256];
	struct addrinfo hints, *ai, *p, *selected = NULL;
	struct in6_addr * a6;
	struct sockaddr_in6 *sa6;

	int ret = gethostname(name, sizeof(name));

	if (ret == 0)
	{

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_STREAM;
		ret = getaddrinfo(name, NULL, &hints, &ai);

		if (ret == 0)
		{
			p = ai;

			while (p != NULL)
			{
				if (p->ai_family == AF_INET6)
				{
					if (selected == NULL)
					{
						selected = ai;
					}


					sa6 = (struct sockaddr_in6 *)  p->ai_addr;

					a6 = &sa6->sin6_addr;

					if (a6->u.Byte[0] == 0xFE &&
						a6->u.Byte[1] == 0x80)
					{
						selected = p;
						break;
					}

				}
				p = p->ai_next;
			}

			if (selected == NULL)
			{
				ret = -1;
			}
			else
			{
				memcpy(addr6, &((struct sockaddr_in6 *)selected->ai_addr)->sin6_addr, sizeof(struct in6_addr));
			}
		}
	}

	return ret;
}


static int OpenSocket(int sock_type, int proto, struct in6_addr * addr6, int port, int * sock)
{
	struct sockaddr_in6 ipv6_port;
	int ret = 0;
	int fd6;

	memset(&ipv6_port, 0, sizeof(ipv6_port));
	ipv6_port.sin6_family = AF_INET6;
	ipv6_port.sin6_port = htons(port);
	if (addr6 != NULL)
	{
		memcpy(&ipv6_port.sin6_addr, addr6, sizeof(struct in6_addr));
	}

	fd6 = socket(AF_INET6, sock_type, proto);

	if (fd6 == -1)
	{
		ret = GetLastError();
	}
	else if (port != 0 || addr6 != NULL)
	{
		if (bind(fd6, (SOCKADDR*)&ipv6_port, sizeof(ipv6_port)) == SOCKET_ERROR)
		{
			ret = WSAGetLastError();
		}
	}

	if (ret == 0)
	{
		*sock = fd6;
	}
	else
	{
		if (fd6 != -1)
		{
			closesocket(fd6);
		}

		*sock = -1;
	}

	return ret;
}

int OpenUdpSocket(struct in6_addr * addr6, int port, int * sock)
{
	return OpenSocket(SOCK_DGRAM, IPPROTO_UDP, addr6, port, sock);
}

int OpenTcpSocket(struct in6_addr * addr6, int port, int listen_backlog, int * sock)
{
	int ret = OpenSocket(SOCK_STREAM, IPPROTO_TCP, addr6, port, sock);

	if (ret == 0 && listen_backlog > 0)
	{
		if (listen(*sock, listen_backlog) != 0)
		{
			ret = WSAGetLastError();
		}
	}
	return ret;
}

int GetSocketPortNumber(int sock, int * port)
{
	struct sockaddr_storage sa_store;
	int sa_length = sizeof(sa_store);
	
	int ret = getsockname(sock, (struct sockaddr *)&sa_store, &sa_length);

	if (ret == 0)
	{
		switch (sa_store.ss_family)
		{
		case AF_INET:
			*port = ntohs(((struct sockaddr_in *)&sa_store)->sin_port);
			break;
		case AF_INET6:
			*port = ntohs(((struct sockaddr_in6 *)&sa_store)->sin6_port);
			break;
		default:
			ret = WSAEINVAL;
			*port = 0;
			break;
		}
	}
	else
	{
		ret = WSAGetLastError();
		*port = 0;
	}

	return ret;
}

int OpenMulticastSocket(struct in6_addr * addr6, int port, 
	struct in6_addr * mdns_mcast_ipv6, unsigned char ttl, int * msock)
{
	struct sockaddr_in6 ipv6_dest;
	struct sockaddr_in6 ipv6_port;
	int so_reuse_bool = TRUE;
	struct ipv6_mreq mreq6;
	int fd6 = -1;
	int ret = 0;

	memset(&ipv6_dest, 0, sizeof(ipv6_dest));
	memset(&ipv6_port, 0, sizeof(ipv6_port));
	ipv6_dest.sin6_family = AF_INET6;
	ipv6_dest.sin6_port = htons(port);
	ipv6_port.sin6_family = AF_INET6;
	ipv6_port.sin6_port = htons(port);
	memcpy(&ipv6_dest.sin6_addr
		, mdns_mcast_ipv6, sizeof(struct in6_addr));

	if (addr6 != NULL)
	{
		memcpy(&ipv6_port.sin6_addr, addr6, sizeof(struct in6_addr));
	}

	fd6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	if (fd6 == INVALID_SOCKET)
	{
		ret = GetLastError();
	}
	else
	{
		ret = setsockopt(fd6, SOL_SOCKET, SO_REUSEADDR, (const char*)&so_reuse_bool, (int) sizeof(int));

		if (bind(fd6, (SOCKADDR*)&ipv6_port, sizeof(ipv6_port)) == SOCKET_ERROR)
		{
			ret = WSAGetLastError();
		}

		if (ret == 0)
		{
			memcpy(&mreq6.ipv6mr_multiaddr
				, &ipv6_dest.sin6_addr, sizeof(mreq6.ipv6mr_multiaddr));
			memcpy(&mreq6.ipv6mr_interface
				, &ipv6_port.sin6_addr, sizeof(mreq6.ipv6mr_interface));

			if (setsockopt(fd6, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP
				, (const char*)&mreq6, (int) sizeof(mreq6)) == 0)
			{
				if (ttl != 0)
				{
					if (setsockopt(fd6, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) != 0)
					{
						ret = WSAGetLastError();
					}
				}
			}
			else
			{
				ret = WSAGetLastError();
			}
		}
	}

	if (ret == 0)
	{
		*msock = fd6;
	}
	else
	{
		if (fd6 != -1)
		{
			closesocket(fd6);
		}

		*msock = -1;
	}

	return ret;
}
