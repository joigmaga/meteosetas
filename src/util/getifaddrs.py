#! /usr/bin/env python3

"""  getifaddrs - Read and print interface and address information

     Based on https://gist.github.com/provegard/1536682, which was
     based on getifaddrs.py from pydlnadms [http://code.google.com/p/pydlnadms/].
     Tested on Linux and OS X only!

     Ignacio Martinez igmartin@movistar.es
     Jan 2023
"""

########################################
#
# Imports and basic symbol definitions
#
########################################
# Only being tested MacOS and linux
#
import sys
from os import strerror
from socket import AF_UNIX, AF_INET, AF_INET6, SOCK_DGRAM, inet_ntop, inet_pton
from util.custlogging import get_logger, ERROR, WARNING
logger = get_logger(__name__, WARNING)

ALLOWED_OSES = ('darwin', 'linux', 'linux2', 'linux3')
if sys.platform not in ALLOWED_OSES:
    logger.error("platform %s is not supported. Exiting", sys.platform)
    sys.exit(1)

IS_DARWIN = sys.platform == 'darwin'
IS_LINUX  = sys.platform.startswith('linux')

# common symbol for L2 address family
if IS_DARWIN:
    from socket import AF_LINK
    LOCAL_AF_L2 = AF_LINK
else:
    from socket import AF_PACKET
    LOCAL_AF_L2 = AF_PACKET

# from sys/socket.h
AF_LOCAL = AF_UNIX
AF_MAX   = 42

# all families match
LOCAL_AF_ALL = AF_MAX

from ctypes import (
    CDLL,
    Structure, Union, POINTER,
    pointer, get_errno, cast,
    c_char,
    c_byte, c_short, c_ushort, c_int, c_uint,
    c_void_p, c_char_p,
    c_uint8, c_uint16, c_uint32
)
from ctypes.util import find_library

libc = CDLL(find_library('c'), use_errno=True)

######################################################################
#
# Symbols and mappings
#
######################
# Some ioctl codes
#
if IS_DARWIN:
    SIOCGIFMETRIC = 0xC0206917
    SIOCGIFMTU    = 0xC0206933
    SIOCGIFCAP    = 0xC020695B
    SIOCGIFPHYS   = 0xC0206935
    SIOCGIFSTATUS = 0xC331693D
else:
    SIOCGIFMETRIC = 0x0000891D
    SIOCGIFMTU    = 0x00008921
    SIOCGIFTXQLEN = 0x00008942

# Ethernet hardware types (MacOS)
#
IFT_ETHER  = 0x06
IFT_LOOP   = 0x18
IFT_L2VLAN = 0x87
IFT_BRIDGE = 0xd1
#
# (linux)
#
ARPHRD_ETHER    = 1
ARPHRD_LOOPBACK = 772

# interface flags
#
IFF_UP          = 0x0001
IFF_BROADCAST   = 0x0002
IFF_LOOPBACK    = 0x0008
IFF_POINTOPOINT = 0x0010
if IS_DARWIN:
    IFF_MULTICAST   = 0x8000
elif IS_LINUX:
    IFF_MULTICAST   = 0x1000

# IPv6 scope
#
SCP_MIN          = 0x00
SCP_INTLOCAL     = 0x01
SCP_LINKLOCAL    = 0x02
SCP_REALMLOCAL   = 0x03
SCP_ADMINLOCAL   = 0x04
SCP_SITELOCAL    = 0x05
SCP_ORGANIZATION = 0x08
SCP_GLOBAL       = 0x0e
SCP_ALL          = 0x10

# IPv6 address scope mappings
#
scopemap = {  SCP_ALL:          "all",
              SCP_INTLOCAL:     "host",
              SCP_LINKLOCAL:    "link",
              SCP_SITELOCAL:    "site",
              SCP_GLOBAL:       "global",
           }

# address family mappings
#
familymap = { LOCAL_AF_ALL:   "all",
              LOCAL_AF_L2:    "link",
              AF_INET:        "inet",
              AF_INET6:       "inet6",
            }

##################################
# macro-style short functions
#
def family_match(fam, reqfam):
    """ return True if 'fam' matches the expected family or the latter is 'all families' """

    return reqfam in (fam, LOCAL_AF_ALL)

def scope_match(scp, reqscp):
    """ return True if 'scp' matches the expected scope or the latter is 'all scopes' """

    return reqscp in (scp, SCP_ALL)

def islayer2(fam):
    """ return True if address family is link layer """

    return fam == LOCAL_AF_L2

def isether(hwt):
    """ return True if the link is Ethernet """

    return ((IS_DARWIN and hwt in (IFT_ETHER, IFT_L2VLAN, IFT_BRIDGE)) or
            (IS_LINUX  and hwt == ARPHRD_ETHER))

def isloop(hwt):
    """ return True is the link is loopback """

    return ((IS_DARWIN and hwt == IFT_LOOP) or
            (IS_LINUX  and hwt == ARPHRD_LOOPBACK))

def revmap(dmap, val):
    """ return the key for value 'val' in dictionary 'dmap'. None if no value found """

    return list(dmap)[list(dmap.values()).index(val)] if val in dmap.values() else None

#
# Assume 'one-byte char per byte' encoding for interface names
#
GETIFADDRS_ENCODING = 'ISO-8859-15'

# interface name max size for structure ifreq and sizeof(struct ifreq)
#
IFNAMSIZ     = 16
SIZEOF_IFREQ = 32

#####################################################
#
# C data structures
#
#   generic sockaddr structure
#
class struct_sockaddr(Structure):
    if IS_DARWIN:
        _fields_ = [
            ('sa_len',    c_uint8), 
            ('sa_family', c_uint8),
            ('sa_data',   c_byte * 14),]
    else:
        _fields_ = [
            ('sa_family', c_ushort),
            ('sa_data',   c_byte * 14),]

# sockaddr structures for IPv4 and IPv6 addresses
#
class struct_sockaddr_in(Structure):
    if IS_DARWIN:
        _fields_ = [
            ('sin_len',    c_uint8), 
            ('sin_family', c_uint8),
            ('sin_port',   c_uint16),
            ('sin_addr',   c_byte * 4), 
            ('sin_zero',   c_byte * 8)]
    else:
        _fields_ = [
            ('sin_family', c_ushort),
            ('sin_port',   c_uint16),
            ('sin_addr',   c_byte * 4)]

class struct_sockaddr_in6(Structure):
    if IS_DARWIN:
        _fields_ = [
            ('sin6_len',      c_uint8), 
            ('sin6_family',   c_uint8),
            ('sin6_port',     c_uint16),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr',     c_byte * 16),
            ('sin6_scope_id', c_uint32)]
    else:
        _fields_ = [
            ('sin6_family',   c_ushort),
            ('sin6_port',     c_uint16),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr',     c_byte * 16),
            ('sin6_scope_id', c_uint32)]

# sockaddr structures for hardware addresses
# MacOS uses "struct sdl" whereas "struct ll" describes linux hw addresses
#
if IS_DARWIN:
    class struct_sockaddr_dl(Structure):
        _fields_ = [
            ('sdl_len',     c_uint8),
            ('sdl_family',  c_uint8),
            ('sdl_index',   c_uint16),
            ('sdl_type',    c_uint8),
            ('sdl_nlen',    c_uint8),
            ('sdl_alen',    c_uint8),
            ('sdl_slen',    c_uint8),
            ('sdl_data',    c_uint8 * 256),]

if IS_LINUX:
    class struct_sockaddr_ll(Structure):
        _fields_ = [
            ('sll_family',   c_uint16),
            ('sll_protocol', c_uint16),
            ('sll_ifindex',  c_int),
            ('sll_hatype',   c_uint16),
            ('sll_pkttype',  c_uint8),
            ('sll_halen',    c_uint8),
            ('sll_data',     c_uint8 * 8),]

# Simplified version of "struct ifaddr"
# Use in linux the same semantics for the field 'ifa_dstaddr' as in MacOS
#   if interface is broadcast capable, field contains the broadcast address
#   otherwise, if interface is point-to-point, field contains the destination address of the link
#
class struct_ifaddrs(Structure):
    pass

struct_ifaddrs._fields_ = [
    ('ifa_next',    POINTER(struct_ifaddrs)),
    ('ifa_name',    c_char_p),
    ('ifa_flags',   c_uint),
    ('ifa_addr',    POINTER(struct_sockaddr)),
    ('ifa_netmask', POINTER(struct_sockaddr)),
    ('ifa_dstaddr', POINTER(struct_sockaddr)),
    ('ifa_data',    c_void_p),]

# Structure ifreq for getting interface information with ioctl
# Simplified to include relevant fields only. Added padding up to the original union size
#
class union_ifr_ifru(Union):
    _fields_ = [
        ('ifru_addr',      struct_sockaddr),
        ('ifru_dstaddr',   struct_sockaddr),
        ('ifru_broadaddr', struct_sockaddr),
        ('ifru_flags',     c_short),
        ('ifru_metric',    c_int),
        ('ifru_mtu',       c_int),
        ('ifru_phys',      c_int),
        ('ifru_media',     c_int),
        ('ifru_intval',    c_int),
        ('ifru_cap',       c_int * 2),
        ('ifru_pad',       c_char * (SIZEOF_IFREQ-IFNAMSIZ)),]

class struct_ifreq(Structure):
    _fields_ = [
        ('ifr_name',    c_char * IFNAMSIZ),
        ('ifr_ifru',    union_ifr_ifru),]

#############################################################################
#
# module defined classes for abstracting network interfaces and its addresses
#
class NetworkInterface(object):
    """ A placeholder for interface related information including addresses """

    def __init__(self, name):

        self.name    = name
        self.flags   = 0
        self.eflags  = 0
        self.metric  = 0
        self.mtu     = 0
        self.options = 0
        self.index   = 0
        self.phys    = 0
        self.hwtype  = None

        self.txqlen  = 0            # linux only

        self.addresses = []

    def is_broadcast(self):

        return self.flags & IFF_BROADCAST

    def is_pointopoint(self):

        return self.flags & IFF_POINTOPOINT

    def getaddress(self, ifa, psa):
        """ read and save an address according to its family """

        if not ifa or not psa:
            return None, None

        encname      = ifa.ifa_name
        sockaddr     = ifa.ifa_addr
        flags        = ifa.ifa_flags

        name = encname.decode(GETIFADDRS_ENCODING)
        fam  = sockaddr.contents.sa_family

        # in MacOS, avoid spurious destination addresses for point-to-point interfaces 
        # inactive utunx interfaces point to an empty sockaddr for destination addresses
        if psa.contents.sa_family != fam:
            return None, None

        addr  = None
        if fam == AF_INET:
            sin  = cast(psa, POINTER(struct_sockaddr_in)).contents
            addr = IPv4Address(bytes(sin.sin_addr))

        elif fam == AF_INET6:
            sin6 = cast(psa, POINTER(struct_sockaddr_in6)).contents
            addr = IPv6Address(bytes(sin6.sin6_addr))
            addr.scope_id = sin6.sin6_scope_id
            # need to wait for prefixlen to get the address scope

        elif fam == LOCAL_AF_L2:
            self.flags  = flags & 0x0000FFFF
            self.eflags = flags & 0xFFFF0000
            # get interface metric, mtu, ...
            self.getoptions(encname)
            #
            if IS_DARWIN:
                sdl  = cast(psa, POINTER(struct_sockaddr_dl)).contents
                addr = LinkLayerAddress(bytes(sdl.sdl_data[sdl.sdl_nlen:sdl.sdl_nlen+sdl.sdl_alen]))
                self.hwtype = sdl.sdl_type 
                self.index  = sdl.sdl_index
            if IS_LINUX:
                sll  = cast(psa, POINTER(struct_sockaddr_ll)).contents
                addr = LinkLayerAddress(bytes(sll.sll_data[:sll.sll_halen]))
                self.hwtype = sll.sll_hatype
                self.index  = sll.sll_ifindex

        # add your favourite family here
        #
           
        if addr:
            addr.interface = self

        return addr, fam

    def getoptions(self, name):
        """ libc based ioctl calls to obtain some additional interface attributes
            note that requests with highest bit set must be cast to avoid
            being interpreted as signed """ 

        s = libc.socket(AF_LOCAL, SOCK_DGRAM, 0)
        if s < 0:
            err = get_errno()
            logger.error("socket error (%d): %s", err, strerror(err))
            return err

        ifr  = struct_ifreq()
        ifrp = pointer(ifr)

        ifr.ifr_name = name

        if libc.ioctl(s, c_uint(SIOCGIFMETRIC), ifrp) == 0:
            self.metric = ifr.ifr_ifru.ifru_metric

        if libc.ioctl(s, c_uint(SIOCGIFMTU), ifrp) == 0:
            self.mtu = ifr.ifr_ifru.ifru_mtu

        if IS_DARWIN:
            if libc.ioctl(s, c_uint(SIOCGIFCAP), ifrp) == 0:
                self.options = ifr.ifr_ifru.ifru_cap[1]

            if libc.ioctl(s, c_uint(SIOCGIFPHYS), ifrp) == 0:
                self.phys = ifr.ifr_ifru.ifru_phys

        if IS_LINUX:
            if libc.ioctl(s, c_uint(SIOCGIFTXQLEN), ifrp) == 0:
                self.txqlen = ifr.ifr_ifru.ifru_intval

        libc.close(s)

        return 0

    def print_family_addresses(self, fam) -> str:
        """ select and print addresses from the interface address based on address family """

        addrlist = []

        for addr in self.addresses:
            if addr.family != fam:
                continue
            addrlist.append(addr)

        if len(addrlist) == 0:
            return ""

        if len(addrlist) == 1:
            return addrlist[0].printfulladdress()
 
        return str(tuple(addr.printfulladdress() for addr in addrlist))

    def __str__(self):
        """ interface printout """

        fmt = "%s: flags=%x, eflags=%x, metric=%d, mtu=%d, options=%x, index=%d, hwtype=%d" % (
              self.name, self.flags, self.eflags, self.metric, self.mtu, self.options,
              self.index, self.hwtype)

        if IS_LINUX:
            fmt += ", txqlen=%d" % self.txqlen

        addrout = self.print_family_addresses(AF_INET)
        if addrout:
            fmt += ", IPv4=%s" % addrout
        addrout = self.print_family_addresses(AF_INET6)
        if addrout:
            fmt += ", IPv6=%s" % addrout
        addrout = self.print_family_addresses(LOCAL_AF_L2)
        if addrout:
            fmt += ", MAC=%s" % addrout
                
        return fmt

class InterfaceAddress(object):
    """ Base class for all addresses """

    def __init__(self, addr, fam):
        self.address   = addr
        self.family    = fam

        self.interface = None

    def getprefix(self, netmask):
        """ get the prefix length of an address by examining its netmask """

        prefixlen = 0

        if not netmask:
            return prefixlen

        done = False
        for i in range(len(netmask.address)):
            # netmask is encoded as 4 or 16 bytes in network (big-endian) byte code
            # count set bits until first clear bit or mask is exhausted
            byte = netmask.address[i]
            for j in range(7,-1,-1):
                if byte & (1 << j):
                    prefixlen += 1
                else:
                    done = True
                    break
            if done:
                break
 
        return prefixlen

class IPv4Address(InterfaceAddress):
    """ IP address family subclass """

    def __init__(self, addr, fam=AF_INET):
        super().__init__(addr, fam)

        self.netmask     = None
        self.broadcast   = None
        self.destination = None
        self.prefixlen   = None     # CIDR mask
        
    def getmaskdest(self, maddr, daddr, interface):
        """ get the netmask address as well as the broadcast/destination depending on media """

        # network mask
        if maddr:
            self.netmask   = maddr
            self.prefixlen = self.getprefix(self.netmask)

        # broadcast or destination address
        if daddr:
            if interface.is_broadcast():
                self.broadcast = daddr
            elif interface.is_pointopoint():
                self.destination = daddr

        return 0

    def printaddress(self, *args):
        """ obtain a printable version of an IPv4 address """

        return inet_ntop(self.family, self.address)
        
    def printfulladdress(self, *args):

        addrout = self.printaddress()
        if self.netmask:
            addrout += " netmask %s" % self.netmask.printaddress()
        if self.broadcast:
            addrout += " broadcast %s" % self.broadcast.printaddress()
        elif self.destination:
            addrout += " destination %s" % self.destination.printaddress()

        return addrout

    def __str__(self):

        return self.printaddress()

class IPv6Address(InterfaceAddress):
    """ IP version 6 address family subclass """

    def __init__(self, addr, fam=AF_INET6):
        super().__init__(addr, fam)

        self.netmask     = None
        self.destination = None
        self.prefixlen   = None
        self.scope       = None      # address scope
        self.scope_id    = 0         # scope zone (interface index)
        self.zone_id     = None      # scope zone (interface name)

    def getmaskdest(self, maddr, daddr, interface):
        """ get the netmask address as well as the broadcast/destination depending on media """

        # network mask
        if maddr:
            self.netmask   = maddr
            self.prefixlen = self.getprefix(self.netmask)

        # destination address
        if daddr and interface.is_pointopoint():
            self.destination = daddr

        return 0

    def getzone(self):
        """ obtain the zone id for an IPv6 link-local address
            Note: this method returns a string, which can be appended to the address """

        if self.scope == SCP_GLOBAL or self.scope == SCP_INTLOCAL:
            return None
        
        # default scope zone. Don't add zone to printable address (as of RFC 4007)
        if self.scope_id == 0:
            return None

        # if the address is scoped, the scope_id attribute represents the interface in scope
        if self.scope_id != self.interface.index:
            logger.warning("scope_id mismatch. scope_id: %d, interface index: %d",
                           self.scope_id, self.interface.index)

        return self.interface.name

    def getscope(self):
        """ get the scope of an unicast IPv6 address
            here the term 'scope' is generic and refers to the IPv6 address type
            There are actually two scopes only (link-local and global) for unicast addresses """

        check = self.address
        if check[0] == 0xFE and ((check[1] & 0xC0) == 0x80): 
            scp = SCP_LINKLOCAL       # link-local address (scope is associated with a link)
        elif check[0] == 0xFE and ((check[1] & 0xC0) == 0xC0): 
            scp = SCP_SITELOCAL       # site-local address (deprecated)
        elif check[0] == 0xFD:
            scp = SCP_GLOBAL          # unique local address (locally assigned)
        elif check[0] == 0xFC:
            scp = SCP_GLOBAL          # unique local address, router assigned (not implemented)
        elif self.prefixlen == 128 and check[15] == 1:
            scp = SCP_INTLOCAL        # loopback address
        else:
            scp = SCP_GLOBAL          # global address

        return scp
         
    def printaddress(self, printzone=True):
        """ obtain a printable version of a unicast IPv6 address with or without the 'zone id' """

        printable = inet_ntop(self.family, self.address)
        
        if printzone:
            # should only print 'zone_id' for LINKLOCAL addresses (SITELOCALs are deprecated)
            if self.scope not in (SCP_GLOBAL, SCP_INTLOCAL) and self.zone_id:
                printable += "%%%s" % self.zone_id

        return printable

    def printfulladdress(self, printzone=True):

        addrout = self.printaddress(printzone)
        addrout += " prefixlen %d" % self.prefixlen
        if self.destination and self.interface.is_pointopoint():
            addrout += " destination %s" % self.destination.printaddress()
        if self.scope_id and self.scope not in (SCP_GLOBAL, SCP_INTLOCAL):
            addrout += " scopeid 0x%x" % self.scope_id
        return addrout

    def __str__(self):

        return self.printaddress()

class LinkLayerAddress(InterfaceAddress):
    """ Link Layer address family class """

    def __init__(self, addr, fam=LOCAL_AF_L2):
        super().__init__(addr, fam)

    def print_macaddress(self):
        """ Format as a colon separated MAC address
            Skip all-zero addresses """

        addr    = self.address
        addrlen = len(addr)
        iszero  = True

        buff = ""
        for i in range(addrlen):
            if addr[i] != 0:
                iszero = False
            buff += "%02x" % addr[i]
            if i < addrlen-1:
                buff += ":"

        return "" if iszero else buff

    def printaddress(self, *args):
        """ obtain a printable version of the link layer address """

        return self.print_macaddress()
        
    def printfulladdress(self, *args):

        return self.printaddress()

    def __str__(self):

        return self.printaddress()

#######################################################
#

def ifap_iter(ifap):
    """ generator to iterate over interfaces """

    ifa = ifap.contents
    while True:
        yield ifa
        if not ifa.ifa_next:
            break
        ifa = ifa.ifa_next.contents

def get_network_interfaces(ifname=None, reqfamily=LOCAL_AF_ALL, reqscope=SCP_ALL):
    """ walk through all network interfaces
        obtain relevant information about selected interface names, address families and scope """

    ifap = POINTER(struct_ifaddrs)()
    if libc.getifaddrs(pointer(ifap)) != 0:
        err = get_errno()
        msg = strerror(err)
        logger.error("getifaddrs() error: [%d] %s", err, msg)
        sys.exit(err)

    try:
        interfaces = {}
        for ifa in ifap_iter(ifap):

            # get interface name creating a new interface instance if neccessary
            #
            name = ifa.ifa_name.decode(GETIFADDRS_ENCODING)
            if ifname and (name != ifname):
                continue

            if name not in interfaces:
                interfaces[name] = NetworkInterface(name)
            interface = interfaces[name]

            sockaddr     = ifa.ifa_addr
            masksockaddr = ifa.ifa_netmask
            destsockaddr = ifa.ifa_dstaddr
            flags        = ifa.ifa_flags

            # hw address contains important interface information
            # need to get the info before checking address family
            #
            addr, fam = interface.getaddress(ifa, sockaddr)

            if not family_match(fam, reqfamily):
                del addr
                continue

            # done with link layer. Now get netmask and broadcast/destination addresses
            # destination addresses are non-null but meaningless for loopback and tunnel interfaces
            # in linux, we must use the parent address family
            #
            if fam in (AF_INET, AF_INET6):
                maskaddr, _ = interface.getaddress(ifa, masksockaddr)
                destaddr, _ = interface.getaddress(ifa, destsockaddr)

                addr.getmaskdest(maskaddr, destaddr, interface)

            # and the address scope (IPv6)
            #
            if fam == AF_INET6:
                addr.scope   = addr.getscope()   # address scope (e.g. global or link-local)
                addr.zone_id = addr.getzone()    # zone scope (link id) for link-local addr)
                if addr.destination:
                    addr.destination.scope   = addr.destination.getscope()
                    addr.destination.zone_id = addr.destination.getzone()
                # check the address scope against the current reqscope selection
                if not scope_match(addr.scope, reqscope):
                    del addr
                    continue

            interface.addresses.append(addr)

        return interfaces.values()
    finally:
        libc.freeifaddrs(ifap)

######################################################################
#
# public constants and methods
#

GIA_AF_ALL     = LOCAL_AF_ALL
GIA_AF_LINK    = LOCAL_AF_L2
GIA_AF_INET    = AF_INET
GIA_AF_INET6   = AF_INET6

GIA_SCP_MIN    = SCP_MIN
GIA_SCP_ALL    = SCP_ALL
GIA_SCP_HOST   = SCP_INTLOCAL       # node-local (loopback)
GIA_SCP_LINK   = SCP_LINKLOCAL      # link-local
GIA_SCP_SITE   = SCP_SITELOCAL      # site-local
GIA_SCP_GLOBAL = SCP_GLOBAL         # global

def get_interface_names() -> tuple:
    """ return a tuple of all the interface names available """

    return tuple([iface.name for iface in get_network_interfaces()])

def get_interface(ifname: str|int) -> NetworkInterface:
    """ get the interface object for the interface name selected """

    is_string = isinstance(ifname, str)
    is_int    = isinstance(ifname, int)

    for iface in get_network_interfaces():
        if is_int and ifname == iface.index:
            return iface
        elif is_string:
            if ifname == iface.name:
                return iface
            if ifname.isdecimal() and int(ifname) == iface.index:
                return iface

    return None

def get_interface_addresses(ifname: str|int,
                            fam:    int=GIA_AF_ALL,
                            scope:  int=GIA_SCP_ALL) -> list[InterfaceAddress]:
    """ return a list of the addresses for the families and scopes selected
        return None if there is no interface with such a name
        return a (possibly empty) list of addresses otherwise """

    iface = get_interface(ifname)
    if not iface:
        return None

    addrlist = []
    for addr in iface.addresses:
        if not family_match(addr.family, fam):
            continue
        if addr.family == GIA_AF_INET6 and not scope_match(addr.scope, scope):
            continue
        addrlist.append(addr)
               
    return addrlist

def get_interface_address(ifname: str|int,
                          fam: int=GIA_AF_ALL,
                          scope: int=GIA_SCP_ALL) -> InterfaceAddress:
    """ return a single address for the interface name and family selected
        if all families are selected, return the hardware address if any
        if family is inet6, an address, if any, with the required scope is returned
        otherwise (all scopes selected), the address with the highest scope is returned """

    # Same systems have subinterfaces, which look like normal interfaces to this method
    # Other systems have the primary/secondary ... address concept. We assume here that the
    # primary address for an interface (or for a scope in IPv6) is the one that comes first
    #
    if fam == GIA_AF_ALL:
        return get_interface_address(ifname, GIA_AF_LINK, scope)

    addrlist = get_interface_addresses(ifname, fam, scope)

    if not addrlist:
        return None

    if fam == GIA_AF_INET6:
        curscope = GIA_SCP_MIN
        for addr in addrlist[:]:
            if addr.scope == scope:
                return addr
            if addr.scope > curscope:
                curscope = addr.scope
                addrlist[0] = addr
        if not scope_match(addrlist[0], scope):
            return None

    return addrlist[0]

def _check_address(addr: str, fam: int) -> (bytes, int):
    """ check that the input string is a valid representation of an interface address for
        the specified address family """

    check = None
    scope_id = 0

    if fam == GIA_AF_LINK:
        mac = addr
        mac = mac.replace("-", "")
        mac = mac.replace(":", "")
        try:
            check = int(mac, 16).to_bytes(6, 'big') 
        except ValueError:
            logger.error("Invalid MAC address encoding: %s", addr)
            return None, 0
    elif fam in (GIA_AF_INET, GIA_AF_INET6):
        try:
            check = inet_pton(fam, addr)
        except OSError:
            logger.error("Invalid address: %s", addr)
            return None, 0
        if fam == GIA_AF_INET6:
            addr, _, zone = addr.partition('%')
            if zone:
                ifc = get_interface(zone)
                if ifc:
                    scope_id = ifc.index
                else:
                    logger.error("zone id mismatch: %s is not a valid interface", zone)
                    check = None

    return check, scope_id

def find_interface_address(addr: str, fam: int=GIA_AF_INET, ifname: str=None) -> InterfaceAddress:
    """ search for a given address. Lookup can be restricted to an interface and/or a family
        important: address scope is encoded in the address itself """

    check, scope_id = _check_address(addr, fam)

    if not check:
        return None

    match_ifaddr = None
    for ifc in get_network_interfaces():
        if ifname is not None and ifname != ifc.name:
            continue
        for ifaddr in ifc.addresses:
            if not family_match(ifaddr.family, fam):
                continue
            if check != ifaddr:
                continue
            # match
            if fam == GIA_AF_INET6:
                if scope_id > 0:
                    # keep on looping until a match with the right interface is found
                    if ifaddr.interface.index == scope_id:
                        return ifaddr
                elif match_ifaddr:
                    # second match. Same address in two interfaces and no scope zone specified
                    # Reject address and reqest with scope zone (e.g. 'fe::1%eth0')
                    logger.error("Ambiguous IPv6 link-local address. Must specify interface")
                    return None
                else:
                    # first match with default scope zone (0)
                    # we do not give any particular meaning to the 'default zone'
                    match_ifaddr = ifaddr
            elif fam in (GIA_AF_INET, GIA_AF_LINK):
                return ifaddr

    if fam == GIA_AF_INET6 and match_ifaddr:
        # single match. return interface
        return match_ifaddr

    return None

def print_interface_addresses(ifname:  str,
                              fam:     int=GIA_AF_ALL,
                              scope:   int=GIA_SCP_ALL,
                              fullfmt: bool=True) -> tuple[str]:
    """ print the list of addresses configured in the interface for the address familiy
        and the address scope selected
    """

    addrlist = get_interface_addresses(ifname, fam, scope)
    if addrlist is None:
        return ()

    if fullfmt:
        return tuple([addr.printfulladdress() for addr in addrlist])

    return tuple([addr.printaddress() for addr in addrlist])

def print_interface_address(ifname:  str,
                            fam:     int=GIA_AF_LINK,
                            scope:   int=GIA_SCP_ALL,
                            fullfmt: bool=True,
                            zone:    bool=True) -> str:
    """ return a single address for the interface and family selected
        if no address family is selected, the link layer address is returned
        if the interface has multiple IPv6 addresses and no scope is selected,
        the address with the highest scope is returned
        if zone is False, this prevents adding '%zone_id' to IPV6 local-link addresses
    """

    addr = get_interface_address(ifname, fam, scope)
    if not addr:
        return ""

    if fullfmt:
        return addr.printfulladdress(zone)

    return addr.printaddress(zone)

__all__ = ["GIA_AF_ALL", "GIA_AF_LINK", "GIA_AF_INET", "GIA_AF_INET6",
           "GIA_SCP_ALL", "GIA_SCP_HOST", "GIA_SCP_LINK", "GIA_SCP_GLOBAL",
           "get_network_interfaces",
           "get_interface", "get_interface_names",
           "find_interface_address",
           "get_interface_address", "get_interface_addresses",
           "print_interface_address", "print_interface_addresses"]

if __name__ == "__main__":
    [print(str(ni)) for ni in get_network_interfaces()]

