""" A multicast interface to the socket library 

    Ignacio Martinez (igmartin@movistar.es)
    January 2023

    - Support for IPv4 and IPV6 multicasting by means of AF_INET and AF_INET6
      address families.
    - Use the standard socket interface with additions that ease
      socket configuration options, including methods for joining
      and leaving groups.
    - Support for unicast datagram delivery in addition to multicasting
    - Use getifaddrs module to obtain interface and address information
    - Support multiple concurrent joins on a socket, up to IP_MAX_MEMBERSHIPS
    - Support Source Specific Multicast (SSM) for IPv4 and IPv6
    - Support concurrent IPv4 and IPv6 operation on the same socket
    - Support join and leaves for IPv4 and IPv6 on same socket (Linux only)
    - Scoped multicast with interface based scope zone selectioni
      for link local IPv6 addresses
    - Work on Linux and MacOS

    class McastSocket(socket)
        ''' a subclass of 'socket' to simplify UDP multicasting
            and datagram delivery '''

        initialize with 'msock = McastSocket(ipmode)'
        where 'ipmode' is the working mode for the socket,
        which can be IPv4 only, IPv6 only or mixed IPv6/IPv4
        Select with one out of IPM_IPV4, IPM_IPV6, IPM_BOTH

    overloaded methods:

        res = bind(iface, service)
        res = connect(mgroup, service)       
        buffer, address, port = recvfrom()
        res = sendto(buffer, mgroup, service)
        close()

    other class methods:

        res = join(mgroup, iface=None, source=None)
        res = leave(mgroup, iface=None, source=None)
        res = set_recvoptions(reuseaddress=-1, reuseport=-1)
        res = set_sendoptions(iface=None, loop=-1, ttl=-1, prec=-1):

    meaning of arguments and return parameters:

        ifaddr:  unicast address of an interface in the system
                 (str) textual IPv4 or IPv6 address
                 Addresses may not be unique (e.g. 'fe80::1' assigned to
                 two or more interfaces)
                 to disambiguate, add scope zone (e.g. "fe80::1%eth0")
                 to link-local addresses
        iface:   the address, name or index of an existing interface
                 in the system
                 (str) IPv4 or IPv6 address. The latter must be correctly scoped
                 (str) An interface name on the system
                 (int) The index of an interface
                 Examples: "eth0", 3, "192.168.1.4", "fe80::2345%eth1", "::1"
        service: a port name or number, or 0 for internal selection
                 (str) a port name describing the service and resolved
                 by getservbyname()
                 (int) a port number (a positive integer < 65536)
                 use port 0 to let the system select a local port for you
                 when binding. Example: "echo", 7777
        mgroup:  a multicast group address
                 (str) a valid multicast group address
                 Examples: "234.2.3.4", "ff12::3456%eth0"
                 Note: as a generalization, unicast UDP datagram delivery
                 is supoorted as well, so 'mgroup' can also be filled with
                 a unicast address
        source:  a unicast source address for group source selection
                 (str) a valid unicast address
                 used for joins and leaves when data is restricted to
                 a particular source
        buffer:  the data to be sent or the data actually received,
                 as a bytes object
                 (bytes) the default buffer size for reads is 8192
                 Note: conversion from str to bytes is achieved specifying
                 an encoding
                 A usual encoding for text is Unicode 'utf-8'
                 For byte-to-byte text encoding use "iso-8859-15" or similar.
                 Example: "give me €".encode('utf-8'),
                               b'give me \xe2\x82\xac'.decode() 
        res:     the result of a method
                 (int) 0 means success, 1 means failure

    set_recvoptions and sendoptions arguments:

        reuseaddress: permit two or more sockets binding to the same address
                 (int) set to 1 to allow, 0 to disallow the feature
        reuseport:    permit two or more sockets binding to the same port
                 (int) set to 1 to allow, 0 to disallow the feature
        fwdif:   set the forwarding interface for packets
                 for IPv4 addresses, it must be the interface address as
                 a string (str)
                 for IPv6 addresses, it must be the interface name (str) or
                 index (int)
        loop:    permit/block receiving multicast messages in the same host
                 where they are sent
                 (int) set to 1 to allow, 0 to disallow the feature
        ttl:     time to live of a packet. Decremented by routers
                 as packets traverse them
                 (int) a positive integer < 256
                 use ttl=1 for local link transmission, ttl > 1 to reach
                 other networks 
        prec:    set the IP precedence bits in the IP header to indicate
                 Quality of Service (qos)
                 (int) a positive integer < 8
"""

# system imports
import sys
from socket import (socket, inet_pton, htons,
                getnameinfo, getservbyname, gaierror,
                AF_UNSPEC, AF_INET, AF_INET6,
                SOCK_DGRAM, IPPROTO_IP, IPPROTO_IPV6,
                NI_NUMERICHOST, NI_NUMERICSERV,
                IP_MAX_MEMBERSHIPS,
                IP_MULTICAST_LOOP, IP_MULTICAST_TTL, IP_MULTICAST_IF, IP_TOS,
                IPV6_MULTICAST_LOOP, IPV6_MULTICAST_HOPS,
                IPV6_MULTICAST_IF, IPV6_TCLASS,
                SOL_SOCKET, SO_REUSEADDR, SO_REUSEPORT,)
from select import select
from ctypes import (Structure, pointer, POINTER, cast, sizeof,
                    c_byte, c_ushort, c_uint8, c_uint16, c_uint32)

# local imports
from util.custlogging import get_logger, ERROR, WARNING
from util.address import (SCP_INTLOCAL, SCP_LINKLOCAL, SCP_REALMLOCAL, 
                          SCP_ADMINLOCAL, SCP_SITELOCAL, SCP_ORGANIZATION,
                          SCP_GLOBAL,
                          struct_sockaddr,
                          struct_sockaddr_in, struct_sockaddr_in6,
                          IPv4Address, IPv6Address, LinkLayerAddress,
                          get_address,)
from util.getifaddrs import get_interface, get_interface_index

#################
# Constants
#

# IP operation mode
#
IPM_IP   = 4
IPM_IPV6 = 6
IPM_BOTH = 46

# socket state
#
ST_CLOSED    = 0
ST_OPEN      = 1
ST_BOUND     = 3
ST_CONNECTED = 5

# check address type
#
CHK_NONE      = 0
CHK_UNICAST   = 1
CHK_MULTICAST = 2

# Buffer size for read operations on sockets
#
BUFFSIZE = 8192

# log object for this module
#
logger = get_logger(__name__, WARNING)
#
#     Platform dependencies
#     from netinet/in.h
#
PLATFORM = sys.platform
if PLATFORM == 'darwin':
    SIN_LEN                   = True
    IPV6_V6ONLY               = 27
    MCAST_JOIN_GROUP          = 80
    MCAST_LEAVE_GROUP         = 81
    MCAST_JOIN_SOURCE_GROUP   = 82
    MCAST_LEAVE_SOURCE_GROUP  = 83
elif PLATFORM.startswith('linux'):
    SIN_LEN                   = False
    IPV6_V6ONLY               = 26
    MCAST_JOIN_GROUP          = 42 
    MCAST_LEAVE_GROUP         = 45 
    MCAST_JOIN_SOURCE_GROUP   = 46 
    MCAST_LEAVE_SOURCE_GROUP  = 47 
else:
    logger.error("Non supported or non tested OS: %s. Exiting", PLATFORM)
    sys.exit(1)

###################################################
#
#            C data structures
#
# from netinet/in.h
#
class struct_sockaddr_storage(Structure):
    if PLATFORM == 'darwin':
        _fields_ = [
            ('ss_len',    c_uint8), 
            ('ss_family', c_uint8),
            ('ss_pad',    c_uint8 * 126),]
    elif PLATFORM.startswith('linux'):
        _fields_ = [
            ('ss_family', c_uint16),
            ('ss_pad',    c_uint8 * 126),]

class struct_group_req(Structure):
    if PLATFORM == 'darwin':
        _fields_ = [
            ('gr_interface',     c_uint32),
            ('gr_group',         struct_sockaddr_storage),]
    elif PLATFORM.startswith('linux'):
        _fields_ = [
            ('gr_interface',     c_uint32),
            ('gr_pad',           c_uint32),
            ('gr_group',         struct_sockaddr_storage),]

class struct_group_source_req(Structure):
    if PLATFORM == 'darwin':
        _fields_ = [
            ('gsr_interface',    c_uint32),
            ('gsr_group',        struct_sockaddr_storage),
            ('gsr_source',       struct_sockaddr_storage),]
    elif PLATFORM.startswith('linux'):
        _fields_ = [
            ('gsr_interface',    c_uint32),
            ('gsr_pad',          c_uint32),
            ('gsr_group',        struct_sockaddr_storage),
            ('gsr_source',       struct_sockaddr_storage),]

# utility functions
#
def get_service_port(service):
    """ obtain the service port, which can be encoded as a decimal number
        or as a string """

    try:
        port = int(service)
    except ValueError:
        port = None
    else:
        return port

    try:
        port = getservbyname(service)
    except OSError as ose:
        logger.error("invalid service: %s, %s", service, ose.strerror)

    return port

class McastSocket(socket):
    """ a subclass of 'socket' that simplifies applications doing multicast
        and generic datagram exchange"""

    def __init__(self, ipmode=IPM_BOTH, fileno=None):

        if ipmode == IPM_IP:
            family = AF_INET
        elif ipmode in (IPM_IPV6, IPM_BOTH):
            family = AF_INET6
        else:
            logger.error("Invalid socket mode option: %d", ipmode)
            self.state = ST_CLOSED
            # throw something here like 'raise ValueError("....")'
            raise ValueError("Invalid socket mode option")
            #return

        # this is the actual socket creation
        #
        super().__init__(family, SOCK_DGRAM, 0, fileno)

        self.v6only = True
        if ipmode == IPM_BOTH:
            self.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
            self.v6only = False

        self.aux      = None
        self.joined   = 0
        self.sent     = 0
        self.received = 0

        self.state = ST_OPEN

    def _get_multicast_sockaddr(self, mgroup, service, mcastonly=False):
        """ obtain the sockaddr structure parameter for a multicast group
            sockaddr format is Python's' address tuple (host, port) or
            (host, port, flowinfo, scope_id) for the AF_INET6 family
            used in connect() and sendto() """

        try:
            maddr = get_address(mgroup, service, self.family, SOCK_DGRAM)
        except (ValueError, TypeError) as excp:
            logger.error("getaddrinfo error: '%s', mgroup: %s, service: %s",
                          str(excp), mgroup, service)
            return None
        except gaierror:
            logger.error(
                 "getaddrinfo error: no results for mgroup: %s, service: %s",
                  mgroup, service)
            return None

        if mcastonly and not maddr.is_multicast():
            # disallow unicast datagram transmission
            logger.error("invalid multicast group: %s", mgroup)
            return None
        
        if maddr.family == AF_INET6 and self.family == AF_INET:
            logger.error("Cannot transport IPv6 datagrams on IPv4 socket")
            return None
        elif maddr.family == AF_INET and self.family == AF_INET6:
            if self.v6only:
                logger.error("Socket solely configured for IPv6 operation")
                return None

        return maddr.sockaddr

    def _get_interface_sockaddr(self, ifaddr, service):
        """ obtain the sockaddr structure parameter for an interface address
            used in bind() """

        # interface address family should match socket's
        addrobj = get_address(ifaddr, service, self.family, SOCK_DGRAM)
        if not addrobj:
            logger.error("Interface sockaddr error. iface: %s, service: %s",
                          ifaddr, service)
            return None

        return addrobj.sockaddr

    def _build_sockaddr(self, ipaddr, check=CHK_NONE):
        """ build a sockaddr_storage structure and cast it to
            the appropiate sockaddr according to address family
            used in join() and leave() """

        addrobj = get_address(ipaddr)
        if not addrobj:
            return None

        if ((check == CHK_MULTICAST and not addrobj.is_multicast()) or
            (check == CHK_UNICAST   and addrobj.is_multicast())):
            return None

        ss = struct_sockaddr_storage()

        if addrobj.family == AF_INET:
            if SIN_LEN:
                ss.ss_len = sizeof(struct_sockaddr_in)
            ss.ss_family = AF_INET
            sin = cast(pointer(ss), POINTER(struct_sockaddr_in)).contents
            sin.sin_port    = htons(0)
            sin.sin_addr[:] = addrobj.in_addr
        
        elif addrobj.family == AF_INET6:
            if SIN_LEN:
                ss.ss_len = sizeof(struct_sockaddr_in6)
            ss.ss_family = AF_INET6
            sin6 = cast(pointer(ss), POINTER(struct_sockaddr_in6)).contents
            sin6.sin6_port     = htons(0)
            sin6.sin6_flowinfo = 0
            sin6.sin6_addr[:]  = addrobj.in_addr
            sin6.sin6_scope_id = 0

        return ss

    def _get_optvalue(self, mgroup, iface, source):
        """ build an structure group_req or group_source_req
            if source address is present """

        ifindex = get_interface_index(iface)

        # iface = None, "" or 0 are an indication to the kernel
        # to select an interface using routing information
        if iface and (ifindex == 0):
            logger.error("Invalid interface name or address: %s", iface)
            return None

        groupaddr = self._build_sockaddr(mgroup, check=CHK_MULTICAST)
        if not groupaddr:
            logger.error("Invalid multicast group address: %s", mgroup)
            return None

        if source:
            sourceaddr = self._build_sockaddr(source, check=CHK_UNICAST)
            if not sourceaddr:
                logger.error("Invalid unicast source addres: %s", source)
                return None
            grp = struct_group_source_req()
            grp.gsr_interface = ifindex
            grp.gsr_group     = groupaddr
            grp.gsr_source    = sourceaddr
        else:
            grp = struct_group_req()
            grp.gr_interface = ifindex
            grp.gr_group     = groupaddr

        return grp

    def _join_leave(self, mgroup, iface, source, isjoin=True):

        tag = "join" if isjoin else "leave"

        if self.state == ST_CLOSED:
            logger.error("cannot %s group. Socket is closed", tag)
            return 1

        if isjoin and self.joined >= IP_MAX_MEMBERSHIPS:
            logger.error("exceeded max number of multicast groups %s", tag)
            return 1

        if PLATFORM == 'darwin':
            # MacOS requires 'proto' to be aligned with the socket family
            if self.family == AF_INET:
                proto = IPPROTO_IP
            elif self.family == AF_INET6:
                proto = IPPROTO_IPV6
        else:
            # Linux ipv6 sockets allow for joins on either family addresses
            maddrobj = get_address(mgroup, type=SOCK_DGRAM)
            if not maddrobj:
                logger.error("Invalid multicast group address: %s", mgroup)
                return 1
            proto = 0
            if maddrobj.family == AF_INET:
                proto = IPPROTO_IP
            elif maddrobj.family == AF_INET6:
                proto = IPPROTO_IPV6

        if isjoin:
            option = MCAST_JOIN_GROUP
            if source:
                option = MCAST_JOIN_SOURCE_GROUP    
        else:
            option = MCAST_LEAVE_GROUP
            if source:
                option = MCAST_LEAVE_SOURCE_GROUP

        value = self._get_optvalue(mgroup, iface, source)
        if not value:
            return 1

        try:
            # this is the actual IGMP join/leave
            #
            self.setsockopt(proto, option, bytes(value))
        except OSError as ose:
            logger.error("Multicast %s group error (%d): %s",
                          tag, ose.errno, ose.strerror)
            return 1

        return 0

#############
# public
#
    def bind(self, ifaddr, service, reuseport=0):
        """ local interface to bind() """

        if self.state == ST_CLOSED:
            logger.error("cannot bind socket to address. Socket is closed")
            return 1

        address = self._get_interface_sockaddr(ifaddr, service)

        if not address:
            logger.error("Invalid interface name or address: %s", ifaddr)
            return 1

        # if binding to a non zero port set to reuse address and, optionally,
        # to reuse port so other sockets can bind to the same address and port
        #
        if address[1] > 0:
            reuseaddress = 1
            self.set_recvoptions(reuseaddress, reuseport)

        try:
            super().bind(address)
        except OSError as ose:
            logger.error("Error binding mcast service to socket: %s",
                          ose.strerror)
            return 1

        self.state = ST_BOUND

        return 0

    def connect(self, mgroup, service):
        """ connect this socket to a remote socket with address 'mgroup'
            and port 'service'. Datagrams can be sent with 'send()'
            without specifying group and service """    

        if self.state == ST_CLOSED:
            logger.error("cannot connect socket to remote address. "
                         "Socket is closed")
            return 1
    
        address = self._get_multicast_sockaddr(mgroup, service)

        if not address:
            logger.error("Invalid multicast group address: %s", mgroup)
            return 1

        try:
            super().connect(address) 
        except OSError as ose:
            logger.error("cannot connect to remote address (%d), %s",
                          ose.errno, ose.strerror)
            return 1

        self.state = ST_CONNECTED

        return 0

    def recvfrom(self):
        """ receive datagrams from socket """

        if self.state == ST_CLOSED:
            logger.error("cannot receive datagrams on socket. Socket is closed")
            return None, "", 0

        buff, address = super().recvfrom(BUFFSIZE)

        host, service = getnameinfo(address, NI_NUMERICHOST|NI_NUMERICSERV)

        if len(address) == 4:            # family is AF_INET6
            addrobj = get_address(host)
            if addrobj.map4:             # is a mapped IPv4 address
                host = addrobj.map4      # return plain IPv4 address instead

        return buff, host, service

    def sendto(self, buffer, mgroup, service):
        """ send datagram to a remote mgroup/service combination """

        if self.state == ST_CLOSED:
            logger.error("cannot send datagrams on socket. Socket is closed")
            return 0
    
        address = self._get_multicast_sockaddr(mgroup, service)

        if not address:
            logger.error("Invalid multicast group address: %s", mgroup)
            return 0

        try:
            sent = super().sendto(buffer, address)
        except OSError as ose:
            logger.error("error sending datagram to dest %s: %s",
                          address, ose.strerror)
            sent = 0

        return sent

    def close(self):

        super().close()

        self.state = ST_CLOSED

    def join(self, mgroup, iface=None, source=None):
        """ join multicast group 'mgroup' at interface address 'iface'
            with optional SSM source 'source' """

        res = self._join_leave(mgroup, iface, source, isjoin=True)
        if res == 0:
            self.joined += 1

        return res

    def leave(self, mgroup, iface=None, source=None):
        """ Leave multicast group 'mgroup' at interface 'ifaddr'
            with optional SSM source 'source' """

        res = self._join_leave(mgroup, iface, source, isjoin=False)
        if res == 0:
            self.joined -= 1

        return res

    def set_recvoptions(self, reuseaddress=-1, reuseport=-1):
        """ set the socket receiving options """

        if self.state == ST_CLOSED:
            logger.error("cannot set options on socket. Socket is closed")
            return 1

        try:
            if (reuseaddress in (0,1) and
                reuseaddress != self.getsockopt(SOL_SOCKET, SO_REUSEADDR)):
                self.setsockopt(SOL_SOCKET, SO_REUSEADDR, reuseaddress)
            if (reuseport in (0, 1) and
                reuseport != self.getsockopt(SOL_SOCKET, SO_REUSEPORT)):
                self.setsockopt(SOL_SOCKET, SO_REUSEPORT, reuseport)
        except OSError as ose:
            logger.error("Error trying to set socket receiving options: %s",
                          ose.strerror)
            return 1

        return 0

    def set_sendoptions(self, fwdif=None, loop=-1, ttl=-1, prec=-1):
        """ set various options for sending multicast datagrams
            options include output interface, ttl, loopback reception
            and IP precedence """

        if self.state == ST_CLOSED:
            logger.error("cannot set options on socket. Socket is closed")
            return 1

        if self.family == AF_INET:
            proto    = IPPROTO_IP
            opt_loop = IP_MULTICAST_LOOP
            opt_ttl  = IP_MULTICAST_TTL
            opt_mif  = IP_MULTICAST_IF
            opt_tos  = IP_TOS
            # if fwdif is an interface address it must match the socket family
            addrobj  = get_address(fwdif, family=AF_INET)
            if fwdif and not addrobj:
                logger.error("Invalid forwarding interface address: %s", fwdif)
                return None
            forwint  = None
            if addrobj:
                forwint = addrobj.in_addr
        elif self.family == AF_INET6:
            proto    = IPPROTO_IPV6
            opt_loop = IPV6_MULTICAST_LOOP
            opt_ttl  = IPV6_MULTICAST_HOPS
            opt_mif  = IPV6_MULTICAST_IF
            opt_tos  = IPV6_TCLASS
            forwint  = get_interface_index(fwdif, AF_INET6)
            if fwdif and forwint == 0:
                logger.error("Invalid forwarding interface: %s", fwdif)
                return None

        try:
            if loop in (0, 1) and loop != self.getsockopt(proto, opt_loop):
                self.setsockopt(proto, opt_loop, loop)
            if 0 < ttl < 256 and ttl != self.getsockopt(proto, opt_ttl):
                self.setsockopt(proto, opt_ttl,  ttl)
            if forwint and forwint != self.getsockopt(proto, opt_mif):
                self.setsockopt(proto, opt_mif,  forwint)
            if prec > 0 and prec != self.getsockopt(proto, opt_tos):
                self.setsockopt(proto, opt_tos,  (prec & 0x07) << 5)
        except OSError as ose:
            logger.error("Error trying to set mcast send socket options: %s",
                          ose.strerror)
            return 1

        return 0

##########
# utility functions
#
socketlist = []
v4groups   = []
v6groups   = []

# These globals are defined here and set by 'mcast_read_init()'
#
mcastread       = None
mcast_read_stop = None

def mcast_read_generator():
    """ a generator function to iteratively read from sockets """

    while True:
        try:
            ready, _, _ = select(socketlist, [], [])
        except KeyboardInterrupt:
            break
        for sock in ready:
            yield sock.recvfrom()

def mcast_read_init():
    """ initialization of the mcastread iterable """

    global mcastread, mcast_read_stop

    mcastread = mcast_read_generator()
    mcast_read_stop = mcastread.close

def mcast_read():
    """ perform one read """

    try:
        return next(mcastread)
    except StopIteration:
        return None, None, None

def mcast_server(grouplist, port, interface):
    """ initialize multicast server. Do parameter checking,
        create sockets and join groups
        arguments
        grouplist: tuple (group [, join-interface [, source]])
        port: the server port
        interface: the default interface for joins (can be overriden in tuple)
    """

    # check port
    #
    service = None
    if isinstance(port, int):
        service = port
    elif isinstance(port, str):
        service = getservbyname(port)

    if not service:
        logger.error("error: Invalid port: %s", port)
        return 1
    
    # check joining interface (if null, it must be explicitly set in grouplist)
    #
    ifindex = 0
    if interface:
        ifindex = get_interface_index(interface)

    # build the per-family lists of multicast groups
    #
    for tupl in grouplist:
        if not isinstance(tupl, tuple or list):
            logger.error("Invalid type for parameter 'grouplist'. "
                         "Must be 'tuple' or 'list'")
            return 1

        group  = None
        ifaddr = ifindex
        source = None

        if len(tupl) > 2:
            source = tupl[2]
        if len(tupl) > 1:
            ifaddr = tupl[1]
        if len(tupl) > 0:
            group = tupl[0]
        else:
            logger.error("Empty entry in group list")
            continue

        maddr = get_address(group, type=SOCK_DGRAM)
        if maddr and maddr.family == AF_INET:
            v4groups.append((group, ifaddr, source))
        elif maddr and maddr.family == AF_INET6:
            v6groups.append((group, ifaddr, source))
        else:
            logger.error("Invalid multicast group: %s", group)
            return 1

    # check that at least one list is not empty
    #
    want4 = len(v4groups) > 0
    want6 = len(v6groups) > 0
    if not want4 and not want6:
        logger.error("error: No multicast group addresses available")
        return 1

    # socket creation and binding
    #
    if want4 and want6:
        msock = McastSocket(IPM_BOTH)
        socketlist.append(msock)
        if PLATFORM == 'darwin':
            msock4 = McastSocket(IPM_IP)
            socketlist.append(msock4)
            msock.bind("::", service, reuseport=1)
            msock4.bind("",  service, reuseport=1)
        else:
            msock.bind("::", service)
    elif want6:
        msock = McastSocket(IPM_IPV6)
        socketlist.append(msock)
        msock.bind("::", service)
    elif want4:
        msock = McastSocket(IPM_IP)
        socketlist.append(msock)
        msock.bind("", service)

    # group joining
    #
    if want6 and want4 and PLATFORM == 'darwin':
        for group, intf, source in v4groups[:]:
            if msock4.join(group, intf, source) != 0:
                v4groups.remove((group, intf, source))
    elif want6:
        for group, intf, source in v6groups[:]:
            if msock.join(group, intf, source) != 0:
                v6groups.remove((group, intf, source))
    elif want4:
        for group, intf, source in v4groups[:]:
            if msock.join(group, intf, source) != 0:
                v4groups.remove((group, intf, source))

    # init read generator
    #
    mcast_read_init()

    return 0

def mcast_server_stop():
    """ leave multicast groups and close sockets """

    want4 = len(v4groups) > 0
    want6 = len(v6groups) > 0

    sock6 = None
    sock4 = None
    for sock in socketlist:
        if sock.family == AF_INET6:
            sock6 = sock
        elif sock.family == AF_INET:
            sock4 = sock
    if want4 and not sock4:
        sock4 = sock6

    # leave groups
    #
    if want6:
        for group, intf, source in v6groups:
            sock6.leave(group, intf, source)
        if want4 and PLATFORM == 'darwin':
            for group, intf, source in v4groups: 
                sock4.leave(group, intf, source)
    elif want4:
        for group, intf, source in v4groups:
            sock4.leave(group, intf, source)

    # close sockets
    #
    for sock in socketlist:
        sock.close()

    return 0
