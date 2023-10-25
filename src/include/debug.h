#ifndef NETSTACK_DEBUG_H
#define NETSTACK_DEBUG_H


#define DEBUG_ETHERNET

#ifdef DEBUG_ETHERNET
#define dbg_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg_printf(...)
#endif

//#define PRINT_TABLE_VERBOSE

#endif