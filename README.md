Fast Root
=========

This package is a DNS server that serves the root zone (".")
and _nothing else_.  It only runs on Linux systems.

In its current incarnation it is not suitable for running public
facing root service, but it works well as a local instance of the
root zone that recursive resolvers can be configured to talk to in
preference to sending queries off-net to the real root server system.

NB: this is an ISC Research Project and is not covered by our support
team.  It appears stable, and useful, but is offered without warranty
of any kind.  Please send feedback to ray@isc.org.  Bug reports
(unless security related) should be filed on Github.

Features
--------

- Written in multi-threaded C++14 this code runs on everything from
a Raspberry Pi to the largest multi-core server.

    - on higher-end servers it can saturate a 10 Gbps network
      port (~2M responses per second) using only 3 to 4 CPU cores.

    - on a RPi3 B+ it has been benchmarked to run at 15,000
      queries per second.   A single RPi should be able to
      service dozens of recursive servers.

- achieves high performance by using Linux raw sockets in `AF_PACKET`
mode to reduce the number of context switches and data copying operations.

- supports IPv4, IPv6 link local, UDP and "Stateless TCP"

- recognises the EDNS buffer size option and the DNSSEC "DO" bit

Building
--------

The only third party library dependency is `ldns`, from NL.net Labs.
The `Makefile` will attempt to find this via `pkg-config` using the
package name `ldns` or `libldns`.

Running `make` followed by `make install` (the latter as `root`)
will install the binary in `$(PREFIX)/sbin`, where PREFIX defaults
to `/usr/local`.

Operation
---------

The server needs a regularly updated copy of the root zone to function.

There is a script in `./scripts/get-root.sh` that uses a zone transfer
message ("AXFR") from `f.root-servers.net` if the current root zone
serial number is different to that of the file currently saved (or
indeed if there is no file currently saved).

Rather than listening on the server's own IP address, the fast root
server needs to be assigned an otherwise unused IPv4 address on the
local network which must be specified on the command line on start
up with the "-s" option.

The server will automatically assign itself a link-local IPv6 address
from the range fe80::/10 using SLACC with EUI-64  but there's no
support (yet) for adding a standard unicast address.

As far as the operating system kernel is concerned these IP addresses
are (intentionally) invisible.  This prevents the kernel from sending
spurious ICMP or TCP RST messages relating to inbound packets sent to
network ports that it doesn't know about.  The server itself supports
all of the required ARP and IPv6 Neighbor Discovery protocols necessary
to announce its IP address(es) on the local network.  It will also
respond to ICMP and ICMPv6 "ping" packets sent to its addresses.

To simplify implementation, all responses are sent to the exact same
MAC address from which the request originated.  The O/S routing table
is not consulted.  This also helps prevents the server from being used 
in spoofing attacks.

Startup
-------

For `systemd` based Linux distributions there is a service definition
file in `./scripts/froot.service`.

The service should not be run as root - the `systemd` script is
configured to run with the `CAP_NET_RAW` capability to permit access
to raw sockets without requiring any further privileges.

If you are running outside of `systemd`, use the `setcap` application to
add this capability to the application, e.g:

    # setcap cap_net_raw+ep /usr/local/sbin/froot

Recursive Configuration
-----------------------

To make a BIND recursor use this server for root zone queries in
preference to the public root server system, configure the root zone
in your `named.conf` file as follows:

    zone "." {
        type static-stub;
        server-addresses { x.x.x.x; 192.5.5.241; ... };
    };

where `x.x.x.x` is the IP address assigned to this server.  With this
in place the root hints are not used, so you should add some of the
current root server addresses to the list to act as a fallback in
case this server is not responding.

A small subset of queries will still go to the real root system as
BIND probes their round-trip times to find out which ones are most
responsive, but the vast majority will go to the local server.

Future Developments?
--------------------

To act as a fully functional public facing root server the following
additional functionality would be required:

- full TCP support, optionally with AXFR service
- support for the `.arpa` and `root-servers.net` zones
- DDoS mitigation features (e.g. RRL)

