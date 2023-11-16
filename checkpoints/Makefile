
all: echo_client echo_server perf_client perf_server client server
#LIBRARY:=../src/lib/socket.cpp ../src/lib/ARP.cpp ../src/lib/callback.cpp ../src/lib/route.cpp ../src/lib/IP.cpp ../src/lib/device.cpp ../src/lib/TCP.cpp ../src/lib/utils.cpp
#LIBRARY:= ../build/lib/liblab-netstack-socket.a ../build/lib/liblab-netstack.a 
LIBRARY:=-L ../build/lib -llab-netstack-socket -lstdc++ -llab-netstack -lpcap -lpthread

%: %.c
	g++ -g -o $@ $^  unp.c $(LIBRARY) \
	-Wl,--wrap=socket,--wrap=setsockopt,--wrap=bind,\
	--wrap=listen,--wrap=connect,--wrap=accept,--wrap=read,\
	--wrap=write,--wrap=close,--wrap=getaddrinfo,--wrap=freeaddrinfo

clean: 
	rm -r echo_client echo_server perf_client perf_server

