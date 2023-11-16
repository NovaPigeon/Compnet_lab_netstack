
/**
 * @file socket.h
 * @brief POSIX-compatible socket library supporting TCP protocol on IPv4.
 */

#ifndef NETSTACK_SOCKET_H
#define NETSTACK_SOCKET_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/**
 * @see [POSIX.1-2017:socket](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/socket.html)
 */

int __wrap_socket(int domain, int type, int protocol);

/**
 * @see [POSIX.1-2017:bind](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/bind.html)
 */
int __wrap_bind(int socket, const struct sockaddr *address,
                socklen_t address_len);

/**
 * @see [POSIX.1-2017:listen](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/listen.html)
 */
int __wrap_listen(int socket, int backlog);

/**
 * @see [POSIX.1-2017:connect](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/connect.html)
 */
int __wrap_connect(int socket, const struct sockaddr *address,
                   socklen_t address_len);

/**
 * @see [POSIX.1-2017:accept](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/accept.html)
 */
int __wrap_accept(int socket, struct sockaddr *address,
                  socklen_t *address_len);

/**
 * @see [POSIX.1-2017:read](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/read.html)
 */
ssize_t __wrap_read(int fildes, void *buf, size_t nbyte);

/**
 * @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/write.html)
 */
ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte);

/**
 * @see [POSIX.1-2017:close](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/close.html)
 */
ssize_t __wrap_close(int fildes);

/**
 * @see [POSIX.1-2017:getaddrinfo](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/getaddrinfo.html)
 */
int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);

/**
 * @see [POSIX.1-2017:freeaddrinfo](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/freeaddrinfo.html)
 */
void __wrap_freeaddrinfo(struct addrinfo *ai);

/**
 * @see [POSIX.1-2017:setsockopt](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/setsockopt.html)
 */
int __wrap_setsockopt(int socket, int level, int option_name,
                      const void *option_value, socklen_t option_len);

#ifdef __cplusplus
}
#endif

#endif