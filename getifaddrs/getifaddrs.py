#! /usr/bin/env python3

# Based on https://gist.github.com/provegard/1536682, which was
# Based on getifaddrs.py from pydlnadms [http://code.google.com/p/pydlnadms/].
# Only tested on Linux and OS X!

# Ignacio Martinez igmartin@movistar.es
# Jan 2023

#################################################################
#
# This only works for MacOS and linux
#
ALLOWED_OSES = ('darwin', 'linux')
#
import sys
if sys.platform not in ALLOWED_OSES:
    print("platform %s is not supported. Exiting" % sys.platform, file=sys.stderr)
    sys.exit(1)

is_darwin = sys.platform == 'darwin'
is_linux  = sys.platform == 'linux'

from os import strerror
import fcntl
from socket import (AF_UNIX, AF_INET, AF_INET6, SOCK_DGRAM,
                    socket, inet_ntop, ntohl, if_indextoname,
)

# common symbol for L2 address family
if is_darwin:
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

def family_match(family, famreq):
    return family == famreq or famreq == LOCAL_AF_ALL

def islayer2(family):
    return family == LOCAL_AF_L2

from ctypes import (
    Structure, Union, POINTER,
    pointer, get_errno, cast, sizeof, create_string_buffer,
    c_char,
    c_byte, c_short, c_int,
    c_ubyte, c_ushort, c_uint,
    c_void_p, c_char_p,
    c_uint8, c_uint16, c_uint32
)
import ctypes.util
import ctypes

#######################################################################################
#
# Some ioctl codes
#
if is_darwin:
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

def isether(hwtype):
    return ((is_darwin and hwtype in (IFT_ETHER, IFT_L2VLAN, IFT_BRIDGE)) or
            (is_linux  and hwtype == ARPHRD_ETHER))

def isloop(hwtype):
    return ((is_darwin and hwtype == IFT_LOOP) or
            (is_linux  and hwtype == ARPHRD_LOOPBACK))

FLG_FLAGS   = 1
FLG_EFLAGS  = 2
FLG_OPTIONS = 3

# interface flags
#
IFF_UP          = 0x0001
IFF_BROADCAST   = 0x0002
IFF_DEBUG       = 0x0004
IFF_LOOPBACK    = 0x0008
IFF_POINTOPOINT = 0x0010
IFF_NOTRAILERS  = 0x0020
IFF_RUNNING     = 0x0040
IFF_NOARP       = 0x0080
IFF_PROMISC     = 0x0100
IFF_ALLMULTI    = 0x0200

IFF_OACTIVE     = 0x0400
IFF_SIMPLEX     = 0x0800
IFF_LINK0       = 0x1000
IFF_LINK1       = 0x2000
IFF_LINK2       = 0x4000

IFF_MASTER      = 0x0400
IFF_SLAVE       = 0x0800
IFF_PORTSEL     = 0x2000
IFF_AUTOMEDIA   = 0x4000
IFF_DYNAMIC     = 0x8000

# extended interface flags (high order bits)
#
IFF_LOWER_UP    = 0x010000
IFF_DORMANT     = 0x020000
IFF_ECHO        = 0x040000

if is_darwin:
    IFF_MULTICAST   = 0x8000
if is_linux:
    IFF_MULTICAST   = 0x1000

iffmap = { IFF_UP:          "UP",
           IFF_BROADCAST:   "BROADCAST",
           IFF_DEBUG:       "DEBUG",
           IFF_LOOPBACK:    "LOOPBACK",
           IFF_POINTOPOINT: "POINTOPOINT",
           IFF_NOTRAILERS:  "SMART",
           IFF_RUNNING:     "RUNNING",
           IFF_NOARP:       "NOARP",
           IFF_PROMISC:     "PROMISC",
           IFF_ALLMULTI:    "ALLMULTI",
           IFF_OACTIVE:     "OACTIVE",
           IFF_SIMPLEX:     "SIMPLEX",
           IFF_LINK0:       "LINK0",
           IFF_LINK1:       "LINK1",
           IFF_LINK2:       "LINK2",
           IFF_MULTICAST:   "MULTICAST",
         }

if is_linux:
    iffmap.update( {
           IFF_NOTRAILERS:  "NOTRAILERS",
           IFF_MASTER:      "MASTER",
           IFF_SLAVE:       "SLAVE",
           IFF_PORTSEL:     "PORTSEL",
           IFF_AUTOMEDIA:   "AUTOMEDIA",
           IFF_DYNAMIC:     "DYNAMIC",
           IFF_LOWER_UP:    "LOWER_UP",
           IFF_DORMANT:     "DORMANT",
           IFF_ECHO:        "ECHO",
         })

# interface capabilities (displayed as 'options' in MacOS)
#
IFCAP_RXCSUM           = 0x00001
IFCAP_TXCSUM           = 0x00002
IFCAP_VLAN_MTU         = 0x00004
IFCAP_VLAN_HWTAGGING   = 0x00008
IFCAP_JUMBO_MTU        = 0x00010
IFCAP_TSO4             = 0x00020
IFCAP_TSO6             = 0x00040
IFCAP_LRO              = 0x00080
IFCAP_AV               = 0x00100
IFCAP_TXSTATUS         = 0x00200
IFCAP_SKYWALK          = 0x00400
IFCAP_HW_TIMESTAMP     = 0x00800
IFCAP_SW_TIMESTAMP     = 0x01000
IFCAP_CSUM_PARTIAL     = 0x02000
IFCAP_CSUM_ZERO_INVERT = 0x04000

optmap = { IFCAP_RXCSUM:           "RXCSUM",
           IFCAP_TXCSUM:           "TXCSUM", 
           IFCAP_VLAN_MTU:         "VLAN_MTU",
           IFCAP_VLAN_HWTAGGING:   "VLAN_HWTAGGING",
           IFCAP_JUMBO_MTU:        "JUMBO_MTU",
           IFCAP_TSO4:             "TSO4",
           IFCAP_TSO6:             "TSO6",
           IFCAP_LRO:              "LRO",
           IFCAP_AV:               "AV",
           IFCAP_TXSTATUS:         "TXSTATUS",
           IFCAP_SKYWALK:          "CHANNEL_IO",
           IFCAP_HW_TIMESTAMP:     "HW_TIMESTAMP",
           IFCAP_SW_TIMESTAMP:     "SW_TIMESTAMP",
           IFCAP_CSUM_PARTIAL:     "CSUM_PARTIAL",
           IFCAP_CSUM_ZERO_INVERT: "CSUM_ZERO_INVERT", }

# IPv6 scope
#
SCP_MIN    = 0
SCP_HOST   = 1
SCP_LOCAL  = 2
SCP_LINK   = 3
SCP_SITE   = 4
SCP_GLOBAL = 5
SCP_ALL    = 6

scopemap = {  SCP_ALL:      "all",
              SCP_HOST:     "host",
              SCP_LOCAL:    "local",
              SCP_LINK:     "link",
              SCP_SITE:     "site",
              SCP_GLOBAL:   "global",
           }

familymap = { LOCAL_AF_ALL:   "all",
              LOCAL_AF_L2:    "link",
              AF_INET:        "inet",
              AF_INET6:       "inet6",
            }

def revmap(map, item):
    """ reverse mapping """

    for key in map.keys():
        if map[key] == item:
            return key

    return None

def scope_match(scope, scopereq):
    return (scope == scopereq) or (scopereq == SCP_ALL)

#
# Assume one-byte per char encoding for interface names
# Haven't seen interface names with unicode multi-byte chars yet
#
GETIFADDRS_ENCODING = 'ISO-8859-1'

# interface name max size for structure ifreq and sizeof(struct ifreq)
#
IFNAMSIZ     = 16
SIZEOF_IFREQ = 32

# Address listing format
# Two options: ifconfig-like output or packed style address dump (default)
#
IFCONFIG_FORMAT = 1
DUMP_FORMAT     = 2
DEFAULT_FORMAT  = DUMP_FORMAT

BYTE_SCALE = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB")

#####################################################
#
# generic sockaddr structure
#
class struct_sockaddr(Structure):
    if is_darwin:
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
    if is_darwin:
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
    if is_darwin:
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
if is_darwin:
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

if is_linux:
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

if is_darwin:
    class struct_ifstat(Structure):
        _fields_ = [
            ('ifs_name',      c_char * IFNAMSIZ),
            ('ascii',         c_char * 801),]

if is_darwin:
    class struct_if_data(Structure):
        _fields_ = [
            ('ifi_type',            c_uint8),
            ('ifi_typelen',         c_uint8),
            ('ifi_physical',        c_uint8),
            ('ifi_addrlen',         c_uint8),
            ('ifi_hdrlen',          c_uint8),
            ('ifi_recvquota',       c_uint8),
            ('ifi_xmitquota',       c_uint8),
            ('ifi_unused1',         c_uint8),
            ('ifi_mtu',             c_uint32),
            ('ifi_metric',          c_uint32),
            ('ifi_baudrate',        c_uint32),
            ('ifi_ipackets',        c_uint32),
            ('ifi_ierrors',         c_uint32),
            ('ifi_opackets',        c_uint32),
            ('ifi_oerrors',         c_uint32),
            ('ifi_collisions',      c_uint32),
            ('ifi_ibytes',          c_uint32),
            ('ifi_obytes',          c_uint32),
            ('ifi_imcasts',         c_uint32),
            ('ifi_omcasts',         c_uint32),
            ('ifi_iqdrops',         c_uint32),
            ('ifi_noproto',         c_uint32),
            ('ifi_recvtiming',      c_uint32),
            ('ifi_xmittiming',      c_uint32),
            ('ifi_lastchange',      c_uint32 * 2),
            ('ifi_unused2',         c_uint32),
            ('ifi_hwassist',        c_uint32),
            ('ifi_reserved1',       c_uint32),
            ('ifi_reserved2',       c_uint32),]

if is_linux:
    class struct_rtnl_link_stats(Structure):
        _fields_ = [
            ('rx_packets',          c_uint32),
            ('tx_packets',          c_uint32),
            ('rx_bytes',            c_uint32),
            ('tx_bytes',            c_uint32),
            ('rx_errors',           c_uint32),
            ('tx_errors',           c_uint32),
            ('rx_dropped',          c_uint32),
            ('tx_dropped',          c_uint32),
            ('multicast',           c_uint32),
            ('collisions',          c_uint32),
            ('rx_length_errors',    c_uint32),
            ('rx_over_errors',      c_uint32),
            ('rx_crc_errors',       c_uint32),
            ('rx_frame_errors',     c_uint32),
            ('rx_fifo_errors',      c_uint32),
            ('rx_missed_errors',    c_uint32),
            ('tx_aborted_errors',   c_uint32),
            ('tx_carrier_errors',   c_uint32),
            ('tx_fifo_errors',      c_uint32),
            ('tx_heartbeat_errors', c_uint32),
            ('tx_window_errors',    c_uint32),
            ('rx_compressed',       c_uint32),
            ('tx_compressed',       c_uint32),]

#############################################################################
#
# module defined classes for abstracting network interfaces and its addresses
#
class NetworkInterface(object):
    """ A placeholder for interface related information including addresses """

    def __init__(self, name, output_format=IFCONFIG_FORMAT):

        self.name    = name
        self.flags   = 0
        self.eflags  = 0
        self.metric  = 0
        self.mtu     = 0
        self.options = 0
        self.index   = 0
        self.phys    = 0
        self.hwtype  = None

        self.in_packets  = 0
        self.in_bytes    = 0
        self.in_errors   = 0
        self.in_dropped  = 0
        self.in_mcasts   = 0
        self.out_packets = 0
        self.out_bytes   = 0
        self.out_errors  = 0
        self.collisions  = 0

        self.txqlen      = 0        # linux
        self.baudrate    = 0        # darwin

        if is_darwin:
            self.out_mcasts  = 0

        if is_linux:
            self.in_overrun_errors   = 0
            self.in_frame_errors     = 0
            self.in_fifo_errors      = 0
            self.in_missed_errors    = 0
            self.out_dropped         = 0
            self.out_overrun_errors  = 0
            self.out_carrier_errors  = 0
            self.out_fifo_errors     = 0
            self.out_aborted_errors  = 0

        self.format = output_format

        self.addresses = []

    def getaddress(self, psa, encname=None, flags=0, data=None):
        """ read and save an address depending on the family it belongs to """

        family = psa.contents.sa_family

        addr  = None
        if family == AF_INET:
            sin  = cast(psa, POINTER(struct_sockaddr_in)).contents
            addr = IPv4Address(bytes(sin.sin_addr))

        elif family == AF_INET6:
            sin6 = cast(psa, POINTER(struct_sockaddr_in6)).contents
            addr = IPv6Address(bytes(sin6.sin6_addr))
            addr.scope_id = sin6.sin6_scope_id        # scope id, a numeric id for each interface
            # need to wait for prefixlen to get the address scope

        elif family == LOCAL_AF_L2:
            self.flags  = flags & 0x0000FFFF
            self.eflags = flags & 0xFFFF0000
            # get interface metric, mtu, ...
            self.getoptions(encname)
            # interface statistics
            self.getstats(data)
            #
            if is_darwin:
                sdl  = cast(psa, POINTER(struct_sockaddr_dl)).contents
                addr = LinkLayerAddress(bytes(sdl.sdl_data[sdl.sdl_nlen:sdl.sdl_nlen+sdl.sdl_alen]))
                self.hwtype = sdl.sdl_type 
                self.index  = sdl.sdl_index
            if is_linux:
                sll  = cast(psa, POINTER(struct_sockaddr_ll)).contents
                addr = LinkLayerAddress(bytes(sll.sll_data[:sll.sll_halen]))
                self.hwtype = sll.sll_hatype
                self.index  = sll.sll_ifindex

        # your favourite family here
        #

        return addr, family

    def getoptions(self, name):
        """ libc based ioctl calls to obtain some additional interface attributes
            note that requests with highest bit set must be cast to avoid being interpreted as signed
        """ 

        s = libc.socket(AF_LOCAL, SOCK_DGRAM, 0)
        if s < 0:
            err = get_errno()
            print("socket error (%d): %s" % (err, strerror(err)), file=sys.stderr)
            return 1

        ifr  = struct_ifreq()
        ifrp = pointer(ifr)

        ifr.ifr_name = name

        if libc.ioctl(s, c_uint(SIOCGIFMETRIC), ifrp) == 0:
            self.metric = ifr.ifr_ifru.ifru_metric

        if libc.ioctl(s, c_uint(SIOCGIFMTU), ifrp) == 0:
            self.mtu = ifr.ifr_ifru.ifru_mtu

        if is_darwin:
            if libc.ioctl(s, c_uint(SIOCGIFCAP), ifrp) == 0:
                self.options = ifr.ifr_ifru.ifru_cap[1]

            if libc.ioctl(s, c_uint(SIOCGIFPHYS), ifrp) == 0:
                self.phys = ifr.ifr_ifru.ifru_phys

        if is_linux:
            if libc.ioctl(s, c_uint(SIOCGIFTXQLEN), ifrp) == 0:
                self.txqlen = ifr.ifr_ifru.ifru_intval

        libc.close(s)

        return 0

    def getstats(self, data):

        if not data:
            return -1

        if is_darwin:
            stats = cast(data, POINTER(struct_if_data)).contents

            # common
            self.in_packets  = stats.ifi_ipackets
            self.in_bytes    = stats.ifi_ibytes
            self.in_errors   = stats.ifi_ierrors
            self.in_dropped  = stats.ifi_iqdrops
            self.in_mcasts   = stats.ifi_imcasts
            self.out_packets = stats.ifi_opackets
            self.out_errors  = stats.ifi_oerrors
            self.out_bytes   = stats.ifi_obytes
            self.collisions  = stats.ifi_collisions

            # darwin specific
            self.out_mcasts  = stats.ifi_omcasts
            self.baudrate    = stats.ifi_baudrate

        if is_linux:
            stats = cast(data, POINTER(struct_rtnl_link_stats)).contents

            # common
            self.in_packets  = stats.rx_packets
            self.in_bytes    = stats.rx_bytes
            self.in_errors   = stats.rx_errors
            self.in_dropped  = stats.rx_dropped
            self.in_mcasts   = stats.multicast
            self.out_packets = stats.tx_packets
            self.out_bytes   = stats.tx_bytes
            self.out_errors  = stats.tx_errors
            self.collisions  = stats.collisions

            # linux specific
            self.in_overrun_errors   = stats.rx_over_errors
            self.in_frame_errors     = stats.rx_frame_errors
            self.in_fifo_errors      = stats.rx_fifo_errors
            self.in_missed_errors    = stats.rx_missed_errors
            self.out_dropped         = stats.tx_dropped
            self.out_overrun_errors  = stats.tx_fifo_errors
            self.out_carrier_errors  = stats.tx_carrier_errors 
            self.out_fifo_errors     = stats.tx_fifo_errors
            self.out_aborted_errors  = stats.tx_aborted_errors

        return 0

#    def getoptions(self, name):
#        """ A pythonic alternative to get interface options, mtu, etc 
#            as we are reading integers, platform byte order must be respected """
#
#        def getintval(buffer, offset):
#
#            return ntohl(int(buffer[offset:offset+4].hex(), 16))
#
#        try:
#            s = socket(AF_LOCAL, SOCK_DGRAM, 0)
#        except OSError as ose:
#            print("socket error: (%d) %s" % (ose.errno, ose.strerror), file=sys.stderr)
#            return -1
#
#        buff = create_string_buffer(name, sizeof(struct_ifreq))
#
#        fcntl.ioctl(s, SIOCGIFMETRIC, buff)
#        self.metric = getintval(buff, IFNAMSIZ)
#
#        fcntl.ioctl(s, SIOCGIFMTU, buff)
#        self.mtu = getintval(buff, IFNAMSIZ)
#
#        if is_darwin':
#            fcntl.ioctl(s, SIOCGIFCAP, buff)
#            self.options = getintval(buff, IFNAMSIZ+4)
#
#            fcntl.ioctl(s, SIOCGIFPHYS, buff)
#            self.phys = getintval(buff, IFNAMSIZ)
#
#        if is_linux:
#            fcntl.ioctl(s, SIOCGIFTXQLEN, buff)
#            self.txqlen = getintval(buff, IFNAMSIZ)
#
#        s.close()
#
#        return 0

    def print_flags(self, flagtype):
        """ Print flags and options using the corresponding map """

        map = {}
        fmt = ""

        if flagtype == FLG_FLAGS:
            map   = iffmap
            flags = self.flags
        elif flagtype == FLG_EFLAGS:
            map   = iffmap
            flags = self.eflags
        elif flagtype == FLG_OPTIONS:
            map   = optmap
            flags = self.options
        
        first = True
        for f in map.keys():
            if f & flags:
                fmt += "%s%s" % ("" if first else ",", map[f])
                first = False

        return fmt

    def print_family_addresses(self, family):
        """ print addresses from the interface address lists for each family """

        addrlist = []

        for addr in self.addresses:
            if addr.family == family:
                addrlist.append(addr)

        if len(addrlist) == 0:
            return ""

        if len(addrlist) == 1:
            return str(addrlist[0])
 
        return str(tuple([str(_) for _ in addrlist]))

    def print_stats(self):

        def bytescale(num):

            for fact in range(0,len(BYTE_SCALE)):
                if num < 2**(10*(fact+1)):
                    break

            return float(num/(2**(10*fact))), BYTE_SCALE[fact]

        fmt   = ""

        brate, scale = bytescale(self.in_bytes)
        if is_darwin:
            fmt += "\n\tRX packets %d bytes %d (%.1f %s)" % (
                                   self.in_packets, self.in_bytes, brate, scale) 
            fmt += "\n\tRX multicast %d errors %d dropped %d" % (
                                   self.in_mcasts, self.in_errors, self.in_dropped)
        else:        
            fmt += "\n\tTX packets %d  bytes %d (%.1f %s)" % (
                                   self.in_packets, self.in_bytes, brate, scale) 
            fmt += "\n\tTX errors %d  dropped %d  overruns %d  frame %d" % (
                                   self.in_errors, self.in_dropped,
                                   self.in_overrun_errors, self.in_frame_errors)

        brate, scale = bytescale(self.out_bytes)
        if is_darwin:
            fmt += "\n\tTX packets %d bytes %d (%.1f %s)" % (
                                   self.out_packets, self.out_bytes, brate, scale)
            fmt += "\n\tTX multicast %d errors %d collisions %d" % (
                                   self.out_mcasts, self.out_errors, self.collisions)
        else:
            fmt += "\n\tTX packets %d  bytes %d (%.1f %s)" % (
                                   self.out_packets, self.out_bytes, brate, scale)
            fmt += "\n\tTX errors %d  dropped %d  overruns %d  carrier %d  collisions %d" % (
                                   self.out_errors, self.out_dropped, self.out_overrun_errors,
                                   self.out_carrier_errors, self.collisions)
   
        return fmt

    def __str__(self):
        """ interface printout """

        # platform dependencies: flags display in hex in darwin, decimal in linux
        #
        if is_darwin:
            flagsnum  = "%x"
            com       = ""
        else:
            flagsnum  = "%d"
            com       = " "

        sep = "="
        if self.format == IFCONFIG_FORMAT:
            sep = " "
            flagsfmt = (flagsnum + "<%s>") % (self.flags, self.print_flags(FLG_FLAGS))
            if self.eflags:
                flagsfmt += (" %seflags=" + flagsnum + "<%s>") % (com, self.eflags,
                                                                  self.print_flags(FLG_EFLAGS))
        else:
            sep = "="
            com = ","
            flagsfmt = flagsnum % self.flags

        fmt = "%s:" % self.name
        fmt += " flags=%s" % flagsfmt
        if self.metric:
            fmt += "%s metric%s%d" % (com, sep, self.metric)
        if self.mtu:
            fmt += "%s mtu%s%d" % (com, sep, self.mtu)

        if self.format == IFCONFIG_FORMAT:
            if self.options:
                fmt += "\n\toptions=%x<%s>" % (self.options, self.print_flags(FLG_OPTIONS))
            for addr in self.addresses:            
                if addr and addr.family == LOCAL_AF_L2:
                    praddr = str(addr)
                    if isether(self.hwtype):
                        fmt += "\n\tether"
                    elif isloop(self.hwtype) and (praddr or self.txqlen):
                        fmt += "\n\tloop"
                    elif praddr:
                        fmt += "\n\taddr %s" % praddr
                    if praddr:
                       fmt += " %s" % praddr
                    if self.txqlen:
                        fmt += " %stxqlen %s" % (com, self.txqlen)
                elif addr and addr.family == AF_INET:
                    fmt += "\n\tinet %s %snetmask %s" % (str(addr), com, str(addr.netmask))
                    if addr.broadcast:
                        fmt += " %sbroadcast %s" % (com, str(addr.broadcast))
                    if addr.destination:
                        fmt += " %sdestination %s" % (com, str(addr.destination))
                elif addr and addr.family == AF_INET6:
                    fmt += "\n\tinet6 %s" % str(addr)
                    if addr.destination:
                        fmt += " %sdestination %s" % str(com, addr.destination)
                    fmt += " %sprefixlen %s" % (com, addr.prefixlen)
                    fmt += " %sscopeid 0x%x<%s>" % (com, addr.scope_id, scopemap[addr.scope])
            if self.in_bytes + self.out_bytes > 0:
                fmt += self.print_stats()
        else:
            fmt += ", index=%d" % self.index
            if self.txqlen:
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
                
        fmt += "\n"

        return fmt

class InterfaceAddress(object):
    """ Base class for all addresses """

    def __init__(self, address, family):
        self.address   = address
        self.family    = family

    def getprefix(self, netmask):
        """ get the prefix length of an address by looking at its netmask """

        prefixlen = 0
        done = False
        for i in range(len(netmask.address)):
            b = netmask.address[i]
            for j in range(7,-1,-1):
                if b & (1 << j):
                    prefixlen += 1
                else:
                    done = True
                    break
            if done:
                break
 
        return prefixlen

    def print_family_address(self):
        """ obtain a printable representation of an address according to its family """

        if self.family == LOCAL_AF_L2:
            printable = self.print_macaddress()

        elif self.family in (AF_INET, AF_INET6):
            printable = inet_ntop(self.family, self.address)

        if self.family == AF_INET6 and self.scope == SCP_LINK:
            if self.zone_id:
                printable += "%%%s" % self.zone_id

        return printable

    def __str__(self):

        return self.print_family_address()

class IPv4Address(InterfaceAddress):

    def __init__(self, address, family=AF_INET):
        super().__init__(address, family)

        self.netmask     = None
        self.broadcast   = None
        self.destination = None
        self.prefixlen   = None     # CIDR mask
        
class IPv6Address(InterfaceAddress):

    def __init__(self, address, family=AF_INET6):
        super().__init__(address, family)

        self.netmask     = None
        self.destination = None
        self.prefixlen   = None
        self.scope       = None
        self.scope_id    = 0
        self.zone_id     = None

    def getzone(self):
        """ obtain the zone id for an IPv6 link-local address
            Note: this method returns a string, which can be appended to the address """

        zone_id = None

        if self.scope != SCP_LINK:
            return zone_id
        
        # default scope zone. Don't add to printable address (as of RFC 4007)
        if self.scope_id == 0:
            return zone_id

        try:
            # check whether an interface with such index exists
            zone_id = if_indextoname(self.scope_id)
        except OSError:
            # No known interface with that index. Return the index as a string
            return str(self.scope_id)

        # Valid interface. Note that multiple interfaces sharing one link have the same scope
        return zone_id

    def getscope(self):
        """ get the scope of an IPv6 address
            here the term 'scope' is generic and refers to the type of the IPv6 address
            There are actually two scopes only (link-local and global) """

        check = self.address
        if check[0] == 0xFE and ((check[1] & 0x80) == 0x80): 
            scope = SCP_LINK            # link-local address (scope is associated with a link)
        elif check[0] == 0xFE and ((check[1] & 0xC0) == 0xC0): 
            scope = SCP_SITE            # site-local address (deprecated)
        elif check[0] == 0xFC:
            scope = SCP_LOCAL           # unique local address (locally assigned)
        elif check[0] == 0xFD:
            scope = SCP_LOCAL           # unique local address, router assigned (not yet implemented)
        elif self.prefixlen == 128 and check[15] == 1:
            scope = SCP_HOST            # loopback address
        else:
            scope = SCP_GLOBAL          # global address

        # Looks like BSD specific. Scope zone id encapsulated into the IPV6 address
        #if scope == SCP_LINK and check[2] != 0:
        #    self.scope_id = check[2]

        return scope
         
class LinkLayerAddress(InterfaceAddress):

    def __init__(self, address, family=LOCAL_AF_L2):
        super().__init__(address, family)

    def print_macaddress(self):
        """ Format as a colon separated MAC address
            Skip all-zero addresses """

        addr    = self.address
        addrlen = len(addr)
        iszero  = True

        buff = ""
        for i in range(addrlen):
            if addr[i] != '\0':
                iszero = False
            buff += "%02x" % addr[i]
            if (i < addrlen-1):
                buff += ":"

        return "" if iszero else buff

#######################################################
#

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

def ifap_iter(ifap):
    """ generator to iterate over interfaces """

    ifa = ifap.contents
    while True:
        yield ifa
        if not ifa.ifa_next:
            break
        ifa = ifa.ifa_next.contents

def get_network_interfaces(ifname=None,
                           reqfamily=LOCAL_AF_ALL,
                           reqscope=SCP_ALL,
                           output_format=DEFAULT_FORMAT):
    """ walk through all network interfaces
        obtain relevant information about selected interface names, address families and scope """

    ifap = POINTER(struct_ifaddrs)()
    if (libc.getifaddrs(pointer(ifap)) != 0):
        err = get_errno()
        raise OSError(err, strerror(err))
    try:
        interfaces = {}
        for ifa in ifap_iter(ifap):

            # get interface name creating a new interface instance if neccessary
            #
            name = ifa.ifa_name.decode(GETIFADDRS_ENCODING)
            if ifname and (name != ifname):
                continue

            if name not in interfaces:
                interfaces[name] = NetworkInterface(name, output_format)
            interface = interfaces[name]

            if not ifa.ifa_addr:
                continue

            addr    = ifa.ifa_addr
            encname = ifa.ifa_name
            flags   = ifa.ifa_flags
            stats   = ifa.ifa_data
            address, family = interface.getaddress(addr, encname, flags, stats)

            # hw address contains important interface information
            # need to get the info before checking address family
            #

            if not family_match(family, reqfamily):
                del address
                continue

            # done with link layer. Now get netmask and broadcast/destination addresses
            # destination addresses are non-null but meaningless for loopback and tunnel interfaces
            # in linux, we must use the parent address family
            #
            if family in (AF_INET, AF_INET6):
                maskaddr = ifa.ifa_netmask
                if maskaddr:
                    address.netmask, fam = interface.getaddress(maskaddr)
                    if address.netmask:
                        address.prefixlen = address.getprefix(address.netmask)

                # broadcast or destination address
                destaddr = ifa.ifa_dstaddr
                if destaddr:
                    dest, fam = interface.getaddress(destaddr)
                    if dest:
                        if family == AF_INET and (flags & IFF_BROADCAST):
                            address.broadcast = dest
                        if flags & IFF_POINTOPOINT:
                            address.destination = dest
                            # prefixlen of destination address 
                            if netmask and destaddr:
                                address.destination.prefixlen = (
                                                      address.destination.getprefix(address.netmask))

            # and the address scope (IPv6)
            #
            if family == AF_INET6:
                address.scope   = address.getscope()   # address scope (e.g. global or link-local)
                address.zone_id = address.getzone()    # zone scope (link related) for link-local addresses
                if address.destination:
                     address.destination.scope   = address.destination.getscope()
                     address.destination.zone_id = address.destination.getzone()
                # check the address scope against the current reqscope selection
                if not scope_match(address.scope, reqscope):
                    del address
                    continue

            interface.addresses.append(address)

        return interfaces.values()
    finally:
        libc.freeifaddrs(ifap)

######################################################################
#
# public constants and methods
#

GIA_AF_ALL     = LOCAL_AF_ALL
GIA_AF_LINK    = LOCAL_AF_L2
GIA_AF_IP      = AF_INET
GIA_AF_IPV6    = AF_INET6

GIA_SCP_MIN    = SCP_MIN
GIA_SCP_ALL    = SCP_ALL
GIA_SCP_HOST   = SCP_HOST
GIA_SCP_LOCAL  = SCP_LOCAL
GIA_SCP_LINK   = SCP_LINK      # link-local
GIA_SCP_SITE   = SCP_SITE      # site-local
GIA_SCP_GLOBAL = SCP_GLOBAL    # global

GIA_FMT_DUMP   = DUMP_FORMAT
GIA_FMT_IFCONF = IFCONFIG_FORMAT

get_interfaces = get_network_interfaces

def get_interface_names():
    """ get a list of all the interface names available """

    return [iface.name for iface in get_interfaces()]

def get_interface(ifname):
    """ get the interface object for the interface name selected """

    for iface in get_interfaces():
        if iface.name == ifname:
           return iface

    return None

def get_addresses(ifname, family=GIA_AF_ALL):
    """ get a list, possibly empty, of all the addresses for the families selected
        return None if there is no interface with such name """

    iface = get_interface(ifname)
    if not iface:
        return None

    addrlist = []
    for addr in iface.addresses:
        if family == GIA_AF_ALL:
            addrlist.append(addr)
        elif family == addr.family:
            addrlist.append(addr)

    return addrlist

def get_address(ifname, family=GIA_AF_ALL):
    """ return a single address for the interface name and family selected
        if all families are selected, return the hardware address if any """

    if family == GIA_AF_ALL:
        return get_address(ifname, GIA_AF_LINK)

    addrlist = get_addresses(ifname, family)

    if not addrlist:
        return None

    if family == GIA_AF_IPV6 and len(addrlist) > 1:
        curscope = GIA_SCP_MIN
        for addr in addrlist[:]:
            if addr.scope > curscope:
                curscope = addr.scope
                addrlist[0] = addr

    return addrlist[0]     

def print_addresses(ifname, family=GIA_AF_ALL):

    addrlist = get_addresses(ifname, family)
    if addrlist is None:
        return ""

    return [str(addr) for addr in addrlist]

def print_address(ifname, family=GIA_AF_LINK):

    return str(get_address(ifname, family))

__all__ = ["GIA_AF_ALL", "GIA_AF_LINK", "GIA_AF_IP", "GIA_AF_IPV6",
           "GIA_SCP_MIN", "GIA_SCP_ALL", "GIA_SCP_HOST", "GIA_SCP_LOCAL", "GIA_SCP_LINK", "GIA_SCP_GLOBAL",
           "get_interface_names", "get_interface", "get_interfaces", "get_address", "get_addresses",
           "print_address", "print_addresses"]

if __name__ == '__main__':

    import argparse

    ######################################
    #
    # Command line option and argument parsing
    #
    argp = argparse.ArgumentParser(description='get interface addresses and related information')
    argp.add_argument('-v', '--version',  action='version', version='getifaddrs version 1.0')
    argp.add_argument('-i', '--ifconfig', action='store_const', const=IFCONFIG_FORMAT, 
                help='ifconfig style output format')
    argp.add_argument('-f', '--family',   choices=familymap.values(), default='all',
                help='address family')
    argp.add_argument('-s', '--scope',    choices=scopemap.values(),  default='all',
                help='IPv6 address scope')
    argp.add_argument('interface',        nargs='?', help='interface name')
    opts = argp.parse_args()

    output_format = DEFAULT_FORMAT
    if opts.ifconfig:
        output_format = IFCONFIG_FORMAT 
    family = revmap(familymap, opts.family)
    scope  = revmap(scopemap,  opts.scope)

    for ni in get_interfaces(opts.interface, family, scope, output_format): print(str(ni), end='') 