Compile:

mkdir build
cd build
cmake ..

(To compile the GUI, run XCode & open gui/osx/pppd-VPN.xcodeproj)

Run:
-Options: {-l 0-3(log level)} {-x config_file} [-s/c (aka. server/client, use only for testing between 2 clients!)] [-p password]
e.g.
$ bin/OSX_SSL_VPN_Client -l 3 -x path_to.csslv


Run modes:

1. As a VPN client (default)
Client -> SSL VPN Gateway

2. As a SSL server, tunnel ppp with client using pppd
SSL server <- SSL client

3. As a SSL client, tunnel ppp with server using pppd
SSL client -> SSL server



( CLIENT - SERVER setup)
The idea of using server-client setup is to test the limit of pppd (and the client implementation)
by not involving a VPN gateway server.
In this way, a tunnel is setup between the client and server with ip pairs 5.5.5.5 <-> 6.6.6.6

Easiest way to do this is to make 2 .csslv files, one for server & one for client, with contents:
-server:
*Choose a listening port (the other options, such as user, ip & fingerprint should be included but values are discarded)
-client
*Choose a ip & port (the other options, such as user & fingerprint should be included but values are discarded)

Then run:
-server:
$ bin/OSX_SSL_VPN_Client -l 3 -x server.csslv -s
-client:
$ bin/OSX_SSL_VPN_Client -l 3 -x client.csslv -c

In order to run an instance of this program as a "server" (i.e. mode 2), you must first
generate cert.pem & key.pem, e.g.

$ openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days XXX



Useful commands:

tail -f /var/log/system.log | grep --line-buffered ppp
//In combination with pppd-input argument "kdebug >= 1", see ppp.c (ppp_init-function)

route get google.se
//See whether ip of google is fetched through ppp0 interface

netstat -nrf inet
//Show ip routing table

sudo killall configd
//Seems to keep ppp0-state in between executions sometimes... ??








