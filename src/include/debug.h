#ifndef NETSTACK_DEBUG_H
#define NETSTACK_DEBUG_H

#ifdef IP_ETHER_DEBUG
#define dbg_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg_printf(...)
#endif

#ifdef TCP_DEBUG
#define dbg_tcp_printf(...) fprintf(stderr,__VA_ARGS__)
#else
#define dbg_tcp_printf(...)
#endif

/* #define dbg_tcp_printf(...)       \
    fprintf(stdout, __VA_ARGS__); \
    fflush(stdout);               \
    fprintf(stderr, __VA_ARGS__) */
#endif