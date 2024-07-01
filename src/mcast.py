""" A multicast interface to the socket library 

    Ignacio Martinez (igmartin@movistar.es)
    January 2023

    - Support for IPv4 and IPV6 multicasting by means of AF_INET and AF_INET6 address families.
    - Use the standard socket interface with additions that ease the configuration of socket
      options, including methods for joining and leaving groups.
    - Support for unicast datagram delivery in addition to multicasting
    - Use getifaddrs module to obtain interface and address information
    - Support multiple concurrent joins on a socket, up to IP_MAX_MEMBERSHIPS
    - Support Source Specific Multicast (SSM) for IPv4 and IPv6
    - Support concurrent IPv4 and IPv6 operation on the same socket
    - Support join and leaves for IPv4 and IPv6 on same socket (Linux only)
    - Scoped multicast with interface based scope zone selection for link local IPv6 addresses
    - Work on Linux and MacOS

    class McastSocket(socket)
        ''' a child class of 'socket' to simplify UDP multicasting and datagram delivery '''

        initialize with 'msock = McastSocket(ipmode)'
        where 'ipmode' is the working mode for the socket, which can be IPv4 only, IPv6 only or
        mixed IPv6/IPv4. Select with one out of IPM_IPV4, IPM_IPV6, IPM_BOTH

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

        ifaddr:  address of an interface in the system
                 (str) IPv4 or IPv6 address. The latter must be unique in the system so 
                 add scope zone when neccessary, e.g. "ff12:4567%eth0"
        iface:   the address, name or index of an existing interface in the system
                 (str) IPv4 or IPv6 address. The latter must be correctly scoped
                 (str) An interface name on the system
                 (int) The index of an interface
                 Examples: "eth0", 3, "192.168.1.4", "fe80::2345%eth1", "::1"
        service: a port name or number, or 0 for internal selection
                 (str) a port name describing the service and resolved by getservbyname()
                 (int) a port number (a positive integer < 65536)
                 use port 0 to let the system select a local port for you when binding
                 Examples: "echo", 7777
        mgroup:  a multicast group address
                 (str) a valid multicast group address
                 Examples: "234.2.3.4", "ff12::3456%eth0"
                 Note: as a generalization, unicast UDP datagram delivery is supoorted
                 as well, so 'mgroup' can also be filled with a unicast address
        source:  a unicast source address for group source selection
                 (str) a valid unicast address
                 used for joins and leaves when data is restricted to a particular source
        buffer:  the data to be sent or the data actually received, as a bytes object
                 (bytes) the default buffer size for reads is 8192
                 Note: conversion from str to bytes is achieved specifying an encoding
                 A usual encoding for text is Unicode 'utf-8'. For byte-to-byte text
                 encoding use "iso-8859-15" or similar.
                 Example: "give me €".encode('utf-8'), b'give me \xe2\x82\xac'.decode() 
        res:     the result of a method
                 (int) 0 means success, 1 means failure

    set_recvoptions and sendoptions arguments:

        reuseaddress: permit two or more sockets binding to the same address
                 (int) set to 1 to allow, 0 to disallow the feature
        reuseport:    permit two or more sockets binding to the same port
                 (int) set to 1 to allow, 0 to disallow the feature
        fwdif:   set the forwarding interface for packets
                 for IPv4 addresses, it must be the interface address as a string (str)
                 for IPv6 addresses, it must be the interface name (str) or index (int)
        loop:    permit/block receiving multicast messages in the same host where they are sent
                 (int) set to 1 to allow, 0 to disallow the feature
        ttl:     time to live of a packet. Decremented by routers as packets traverse them
                 (int) a positive integer < 256
                 use ttl=1 for local link transmission, ttl > 1 to reach other networks 
        prec:    set the IP precedence bits in the IP header to indicate Quality of Service (qos)
                 (int) a positive integer < 8

"""

# system imports
import sys
from socket import (socket, inet_pton, getservbyname, htons,
                    AF_UNSPEC, AF_INET, AF_INET6, SOCK_DGRAM, IPPROTO_IP, IPPROTO_IPV6,
                    IP_MAX_MEMBERSHIPS,
                    IP_MULTICAST_LOOP, IP_MULTICAST_TTL, IP_MULTICAST_IF, IP_TOS,
                    IPV6_MULTICAST_LOOP, IPV6_MULTICAST_HOPS, IPV6_MULTICAST_IF, IPV6_TCLASS,
                    SOL_SOCKET, SO_REUSEADDR, SO_REUSEPORT,)
from select import select
from ctypes import (Structure, pointer, POINTER, cast, sizeof,
                    c_byte, c_ushort, c_uint8, c_uint16, c_uint32)

# local imports
from util.custlogging import get_logger, ERROR, WARNING
from util.getifaddrs  import get_interface, get_interface_address, find_interface_address

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

# Text representation of INADDR_ANY and UNSPECIFIED addresses
#
T_INADDR_ANY  = "0.0.0.0"
T_INADDR6_ANY = "::"

# Buffer size for read operations on sockets
#
BUFFSIZE = 8192

# Scope of IPv6 multicast addresses
#
SCP_INTLOCAL     = 0x01
SCP_LINKLOCAL    = 0x02
SCP_REALMLOCAL   = 0x03
SCP_ADMINLOCAL   = 0x04
SCP_SITELOCAL    = 0x05
SCP_ORGANIZATION = 0x08
SCP_GLOBAL       = 0x0e

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
# generic sockaddr structure
#
class struct_sockaddr(Structure):
    if PLATFORM == 'darwin':
        _fields_ = [
            ('sa_len',    c_uint8),
            ('sa_family', c_uint8),
            ('sa_data',   c_byte * 14),]
    elif PLATFORM.startswith('linux'):
        _fields_ = [
            ('sa_family', c_ushort),
            ('sa_data',   c_byte * 14),]

# sockaddr structures for IPv4 and IPv6 addresses
#
class struct_sockaddr_in(Structure):
    if PLATFORM == 'darwin':
        _fields_ = [
            ('sin_len',    c_uint8),
            ('sin_family', c_uint8),
            ('sin_port',   c_uint16),
            ('sin_addr',   c_byte * 4),
            ('sin_zero',   c_byte * 8)]
    elif PLATFORM.startswith('linux'):
        _fields_ = [
            ('sin_family', c_ushort),
            ('sin_port',   c_uint16),
            ('sin_addr',   c_byte * 4)]

class struct_sockaddr_in6(Structure):
    if PLATFORM == 'darwin':
        _fields_ = [
            ('sin6_len',      c_uint8),
            ('sin6_family',   c_uint8),
            ('sin6_port',     c_uint16),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr',     c_byte * 16),
            ('sin6_scope_id', c_uint32)]
    elif PLATFORM.startswith('linux'):
        _fields_ = [
            ('sin6_family',   c_ushort),
            ('sin6_port',     c_uint16),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr',     c_byte * 16),
            ('sin6_scope_id', c_uint32)]
#
# C style structures
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

####################################

class Address(object):
    """ An object descibing an IP address with some of its characterstics """

    def __init__(self, addr, sockfam=AF_UNSPEC):

        self.address    = None
        self.in_addr    = None
        self.family     = AF_UNSPEC
        self.base       = self.address
        self.zone       = ""
        self.scope      = 0
        self.map4       = ""
        self.ipv4mapped = ""
        self.valid      = False

        # addr = None is not valid
        # addr = "" is a synonym of INADDR_ANY
        if isinstance(addr, str):
            self.address = addr.strip().lower()
            if self.get_addrfamily(sockfam) == 0:
                self.get_scope()
                self.valid = True

    def get_addrfamily(self, sockfam):
        """ obtain the internal representation and family of the address """

        # Null address. Map it to INADDR_ANY or ANADDR6_ANY depending on socket family
        if not self.address:
            if sockfam == AF_INET:
                self.address = T_INADDR_ANY
            elif sockfam == AF_INET6:
                self.address = T_INADDR6_ANY
            else:
                return 1

        base, _, zone = self.address.partition('%')

        try:
            in_addr = inet_pton(AF_INET6, base)
        except OSError:
            pass
        else:
            self.in_addr = in_addr
            self.family  = AF_INET6
            self.base    = base
            self.zone    = zone
            _, _, self.map4 = self.address.partition('::ffff:')
            return 0

        try:
            in_addr = inet_pton(AF_INET, self.address)
        except OSError:
            return 1

        self.in_addr    = in_addr
        self.family     = AF_INET
        self.ipv4mapped = '::ffff:' + self.address

        return 0

    def get_zone(self):
        """ obtain the zone id in IPv6 scoped addresses """

        if self.family != AF_INET6:
            return ""

        base, _, zone = self.address.partition('%')
        if zone:
            self.base = base
            self.zone = zone

        return 0

    def get_scope(self):
        """ obtain the embedded scope of an address """

        scope = 0

        if self.family != AF_INET6 or not self.in_addr:
            return scope

        if self.in_addr == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01':
            scope = SCP_INTLOCAL                              # interface local (loopback)
        elif self.in_addr[0] == 0xfe and ((self.in_addr[1] & 0xc0) == 0x80):
            scope = SCP_LINKLOCAL                             # link local
        elif self.in_addr[0] == 0xfe and ((self.in_addr[1] & 0xc0) == 0xc0):
            scope = SCP_SITELOCAL                             # site local (deprecated)
        elif self.in_addr[0] == 0xfd:
            scope = SCP_GLOBAL                                # unique local addresses -> global
        elif self.in_addr[0] == 0xff:
            scope = self.in_addr[1] & 0x0f                    # multicast addresses
        else:
            scope = SCP_GLOBAL                                # global unicast addresses

        self.scope = scope

        return scope

    def is_multicast(self):
        """ check whether an address is multicast or not """

        if self.in_addr:
            if self.family == AF_INET:
                return (self.in_addr[0] & 0xf0) == 0xe0
            if self.family == AF_INET6 and self.map4:
                return (self.in_addr[12] & 0xf0) == 0xe0
            if self.family == AF_INET6:
                return self.in_addr[0] == 0xff

        return False

def get_service_port(service):
    """ obtain the service port, which can be encoded as a decimal number or as a string """

    if isinstance(service, int):
        return service

    try:
        port = getservbyname(service)
    except OSError as ose:
        logger.error("invalid service: %s, %s", service, ose.strerror)
        port = None

    return port

def get_address(addr, family=AF_UNSPEC):
    """ return an Address object for 'addr', None if the address is not valid
        'addr' can be empty, in which case 'family' specifies the corresponding address family """

    if addr is None:
        return None

    addrobj = Address(addr, family)

    if not addrobj.valid:
        del addrobj
        return None

    return addrobj

def get_interface_index(iface):
    """ obtain the index of the interface 'iface'. If iface is an address, try to resolve
        the interface in which the address is configured """

    ifindex = 0

    ifc = get_interface(iface)
    if ifc:
        ifindex = ifc.index
    else:
        addrobj = get_address(iface)
        if addrobj and addrobj.zone:
            ifindex = get_interface_index(addrobj.zone)
        elif addrobj:
            ifa = find_interface_address(addrobj.address, addrobj.family)
            if ifa:
                ifindex = ifa.interface.index

    return ifindex

class McastSocket(socket):
    """ a subclass of 'socket' that simplifies applications doing multicast
        and generic datagram exchange"""

    def __init__(self, ipmode=IPM_BOTH, fileno=None):

        if ipmode == IPM_IP:
            family = AF_INET
        elif ipmode in (IPM_IPV6, IPM_BOTH):
            family = AF_INET6
        else:
            logger.error("Invalid address type option. socket not initialized")
            self.state = ST_CLOSED
            return

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

    def _get_multicast_sockaddr(self, mgroup, service):
        """ obtain the sockaddr structure parameter for a multicast group """

        address = None

        port = get_service_port(service)
        if port is None:
            return address

        maddrobj = get_address(mgroup)
        if not maddrobj:
            return address

        # # allow for unicast datagram transmission
        # if not maddrobj.is_multicast():
        #     logger.error("invalid multicast group: %s", mgroup)
        #     return address
        
        if self.family == AF_INET:
            address = maddrobj.address, port
            if maddrobj.family == AF_INET6:
                logger.error("cannot reach ipv6 destination %s over ipv4 socket: %s",
                        maddrobj.address)

        elif self.family == AF_INET6:
            if maddrobj.family == AF_INET:
                address = maddrobj.ipv4mapped, port, 0, 0
            elif maddrobj.family == AF_INET6:
                scopeid = 0
                ifindex = get_interface_index(maddrobj.zone)
                if SCP_INTLOCAL < maddrobj.scope < SCP_GLOBAL:
                    scopeid = ifindex
                #ifc = get_interface(maddrobj.zone)
                #if ifc and SCP_INTLOCAL < maddrobj.scope < SCP_GLOBAL:
                #    scopeid = ifc.index
                address = maddrobj.base, port, 0, scopeid

        return address

    def _get_interface_sockaddr(self, ifaddr, service):
        """ obtain the sockaddr structure parameter for an interface address """

        address = None

        port = get_service_port(service)
        if port is None:
            return address

        addrobj = get_address(ifaddr, self.family)
        if not addrobj:
            return address

        if addrobj.family == AF_INET:
            address = addrobj.address, port
        elif addrobj.family == AF_INET6:
            scopeid = 0
            ifindex = get_interface_index(ifaddr)
            if addrobj.scope == SCP_LINKLOCAL:
                scopeid = ifindex
            address = addrobj.base, port, 0, scopeid

        return address

    def _build_sockaddr(self, ipaddr, check=CHK_NONE):
        """ build a sockaddr_storage structure and cast it to the appropiate sockaddr
            according to address family """

        addrobj = get_address(ipaddr)
        if not addrobj or ((check == CHK_MULTICAST and addrobj.is_multicast() is False) or
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
        """ build an structure group_req or group_source_req if source is present """

        ifindex = get_interface_index(iface)

        # iface = None, "" or 0 are an indication to the kernel to select an interface
        # using routing information
        if iface and ifindex == 0:
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
            logger.error("exceeded max number of multicast group %ss", tag)
            return 1

        if PLATFORM == 'darwin':
            # MacOS requires 'proto' to be aligned with the socket family
            if self.family == AF_INET:
                proto = IPPROTO_IP
            elif self.family == AF_INET6:
                proto = IPPROTO_IPV6
        else:
            # Linux ipv6 sockets allow for joins on either family addresses
            maddrobj = get_address(mgroup)
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
            logger.error("Multicast %s group error (%d): %s", tag, ose.errno, ose.strerror)
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
            logger.error("Error binding mcast service to socket: %s", ose.strerror)
            return 1

        self.state = ST_BOUND

        return 0

    def connect(self, mgroup, service):
        """ connect this socket to a remote socket with address 'mgroup' and port 'service'
            datagrams can be sent with 'send()' without specifying group and service """    

        if self.state == ST_CLOSED:
            logger.error("cannot connect socket to remote address. Socket is closed")
            return 1
    
        address = self._get_multicast_sockaddr(mgroup, service)

        if not address:
            logger.error("Invalid multicast group address: %s", mgroup)
            return 1

        try:
            super().connect(address) 
        except OSError as ose:
            logger.error("cannot connect to remote address (%d), %s", ose.errno, ose.strerror)
            return 1

        self.state = ST_CONNECTED

        return 0

    def recvfrom(self):
        """ receive datagrams from socket """

        if self.state == ST_CLOSED:
            logger.error("cannot receive datagrams on socket. Socket is closed")
            return 1

        buff, address = super().recvfrom(BUFFSIZE)

        paddr, port = address[:2]
        addrobj = get_address(paddr)
        if addrobj and addrobj.family == AF_INET6:
            scopeid = address[3]
            if addrobj.map4:
                paddr = addrobj.map4
            elif scopeid > 0 and not addrobj.zone:
                # some versions of Python may return both a zoned address and a scope id
                ifc = get_interface(scopeid)
                if ifc:
                    paddr += '%' + ifc.name

        return buff, paddr, port

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
            logger.error("error sending datagram to dest %s: %s", address, ose.strerror)
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
            if reuseaddress in (0,1) and reuseaddress != self.getsockopt(SOL_SOCKET, SO_REUSEADDR):
                self.setsockopt(SOL_SOCKET, SO_REUSEADDR, reuseaddress)
            if reuseport in (0, 1) and reuseport != self.getsockopt(SOL_SOCKET, SO_REUSEPORT):
                self.setsockopt(SOL_SOCKET, SO_REUSEPORT, reuseport)
        except OSError as ose:
            logger.error("Error trying to set socket receiving options: %s", ose.strerror)
            return 1

        return 0

    def set_sendoptions(self, fwdif=None, loop=-1, ttl=-1, prec=-1):
        """ set various options for sending multicast datagrams
            options include output interface, ttl, loopback reception and IP precedence """

        if self.state == ST_CLOSED:
            logger.error("cannot set options on socket. Socket is closed")
            return 1

        if self.family == AF_INET:
            proto    = IPPROTO_IP
            opt_loop = IP_MULTICAST_LOOP
            opt_ttl  = IP_MULTICAST_TTL
            opt_mif  = IP_MULTICAST_IF
            opt_tos  = IP_TOS
            addrobj  = get_address(fwdif)
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
            forwint  = get_interface_index(fwdif)
            if fwdif and forwint == 0:
                logger.error("Invalid forwarding interface name: %s", forwint)
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
            logger.error("Error trying to set mcast send socket options: %s", ose.strerror)
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
    """ initialize multicast server. Do parameter checking, create sockets and join groups """

    # check port
    #
    port = get_service_port(port)
    if port is None:
        logger.error("error: Invalid port: %s", str(port))
        return 1
    
    # check joining interface
    #
    ifindex = get_interface_index(interface)
    if ifindex == 0:
        logger.error("error: Invalid interface: %s", interface)
        return 1

    # build the per-family lists of multicast groups
    #
    for tupl in grouplist:
        group  = None
        ifaddr = ifindex
        source = None
        if isinstance (tupl, str):
            group = tupl
        elif isinstance (tupl, tuple):
            tulen = len(tupl)
            if tulen > 0:
                group = tupl[0]
            if tulen > 1 and tupl[1]:
                ifaddr = tupl[1]
            if tulen > 2:
                source = tupl[2]
        else:
            logger.error("Invalid entry in group list: %s", str(tupl))
            continue

        maddr = get_address(group)
        if maddr and maddr.family == AF_INET:
            v4groups.append((group, ifaddr, source))
        elif maddr and maddr.family == AF_INET6:
            v6groups.append((group, ifaddr, source))
        else:
            logger.error("Invalid multicast group: %s", group)

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
            msock.bind("::", port, reuseport=1)
            msock4.bind("",  port, reuseport=1)
        else:
            msock.bind("::", port)
    elif want6:
        msock = McastSocket(IPM_IPV6)
        socketlist.append(msock)
        msock.bind("::", port)
    elif want4:
        msock = McastSocket(IPM_IP)
        socketlist.append(msock)
        msock.bind("", port)

    # group joining
    #
    if want6:
        # Linux permits grouping all v4 and v6 operation on a single v6 socket
        #
        for group, intf, source in v6groups[:]:
            if msock.join(group, intf, source) != 0:
                v6groups.remove((group, intf, source))
        # MacOS does not allow v4 joins on v6 sockets
        #
        if want4 and PLATFORM == 'darwin':
            for group, intf, source in v4groups[:]:
                if msock4.join(group, intf, source) != 0:
                    v4groups.remove((group, intf, source))
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
