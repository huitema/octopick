#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	/*
	 * Find the local address for the default interface.
	 * TODO: manage additional interfaces.
	 */
	int GetLocalAddress(struct in6_addr * addr6);

	/*
	 * Open an UDP socket, bind it to the specified address and port.
     * @param addr6: IPv6 address, optional. If not null, the socket 
	 *    will be bound to that address.
     * @param port: port number. The socket will be bound to that port.
     * @param sock: if the call succeeds, will contain the socket number.
	 *    If the call fail, the function will not leave an open socket,
	 *    and this parameter will be set to -1.
     * @return: 0 if success, an error code if failure.
	 */
	int OpenUdpSocket(struct in6_addr * addr6, int port, int * sock);

	/*
	 * Open a TCP socket, bind it to the specified address and port.
	 * @param addr6: IPv6 address, optional. If not null, the socket
	 *    will be bound to that address.
	 * @param port: port number. The socket will be bound to that port.
	 * @listen_backlog: backlog size for the listen call. If set to zero,
	 *    the TCP socket will be a client socket, no listen call issued.
	 * @param sock: if the call succeeds, will contain the socket number.
	 *    If the call fail, the function will not leave an open socket,
	 *    and this parameter will be set to -1.
	 * @return: 0 if success, an error code if failure.
	 */
	int OpenTcpSocket(struct in6_addr * addr6, int port, int listen_backlog, int * sock);

	/*
	 * Open an UDP socket, bind it to the specified address and port,
	 * subscribe to the specified multicast group,
	 * and set the default multicast TTL to 255.
     * @param addr6: IPv6 address, optional. If not null, the socket 
	 *    will be bound to that address. 
     * @param port: port number. The socket will be bound to that port.
	 *    SO_REUSEADDR will be used to allow multiple sockets to
	 *    listen to the same multicast port.
     * @param mcast_ipv6: IPv6 multicast address. The IPV6_ADD_MEMBERSHIP
	 *    option will be called to join the socket to that group.
	 * @param ttl: TTL option, optional. If not null, the IPV6_MULTICAST_HOPS
	 *    option will be used to request that TTL for multicast traffic.
     * @param msock: if the call succeeds, will contain the socket number.
	 *    If the call fail, the function will not leave an open socket,
	 *    and this parameter will be set to -1.
     * @return: 0 if success, an error code if failure.
	 *
	 * NOTE: when binding to MDNS, setting the addr6 parameter to a non NULL
	 * value causes the call to fail with error WSAEADDRNOTAVAIL because the system
	 * is already listening to the MDNS multicast group.
	 */
	int OpenMulticastSocket(struct in6_addr * addr6, int port, 
		struct in6_addr * mcast_ipv6, unsigned char ttl, int * msock);

	/*
	 * Return the port number associated with a socket.
	 * @param sock: the socket.
	 * @param port: if the call succeeds, will contain the port number.
	 *    set to zero if the call fails.
	 * @return: 0 if success, an error code if failure.
	 */
	int GetSocketPortNumber(int sock, int * port);



#ifdef __cplusplus
}
#endif