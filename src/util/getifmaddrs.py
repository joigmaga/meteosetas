""" This module provides tools for handling multicast group addresses
    associated to network interfaces """

import sys
import os
from socket import AF_UNSPEC, AF_INET, AF_INET6, inet_ntop

from util.address import (IPv4Address, IPv6Address, LinkLayerAddress,
                     struct_sockaddr, struct_sockaddr_in, struct_sockaddr_in6,
                     get_address,)
from util.getifaddrs import (GETIFADDRS_ENCODING,
                     get_network_interfaces, get_interface,
                     struct_sockaddr_dl,)
from util.custlogging import get_logger, ERROR, WARNING
logger = get_logger(__name__, WARNING)

##############################3#######
# supported on MacOS and Linux
#
IS_DARWIN = sys.platform == 'darwin'
IS_LINUX  = sys.platform.startswith('linux')

# common symbol for L2 address family
if IS_DARWIN:
    from socket import AF_LINK
    AF_LOCAL_L2 = AF_LINK
elif IS_LINUX:
    from socket import AF_PACKET
    AF_LOCAL_L2 = AF_PACKET

##############################3#######
#
IGMP_UNKNOWN   = 0
IGMP_VERSION_1 = 1
IGMP_VERSION_2 = 2
IGMP_VERSION_3 = 3

MLD_UNKNOwN    = 0
MLD_VERSION_1  = 1
MLD_VERSION_2  = 2

MODE_UNKNOWN   = 0
MODE_EXCLUDE   = 1
MODE_INCLUDE   = 2

class GroupIPv4Address(IPv4Address):

    def __init__(self, address):

        super().__init__(address)

        self.fmode   = MODE_UNKNOWN
        self.version = IGMP_UNKNOWN
        self.transla = None
        self.sources = []

class GroupIPv6Address(IPv6Address):

    def __init__(self, address, host="", scope_id=0):

        super().__init__(address, host, scope_id)

        self.fmode   = MODE_UNKNOWN
        self.version = MLD_VERSION_2
        self.transla = None
        self.sources = []

class GroupLinkLayerAddress(LinkLayerAddress):

    def __init__(self, address):

        super().__init__(address)

        self.fmode   = MODE_UNKNOWN
        self.transla = None

#######
#
if IS_DARWIN:
    from ctypes import (
        CDLL,
        Structure, POINTER,
        pointer, get_errno, cast, sizeof,
        c_int, c_size_t, c_void_p, c_byte,
        c_uint, c_uint32,
    )
    from ctypes.util import find_library

    libc = CDLL(find_library('c'), use_errno=True)

    NULL = POINTER(c_void_p)()

    class struct_ifmaddrs(Structure):
        pass        

    struct_ifmaddrs._fields_ = [
        ('ifma_next',    POINTER(struct_ifmaddrs)),
        ('ifma_name',    POINTER(struct_sockaddr)),
        ('ifma_addr',    POINTER(struct_sockaddr)),
        ('ifma_lladdr',  POINTER(struct_sockaddr)),]

    # per interface flags
    IGIF_SILENT   = 0x00000001	  # Do not use IGMP on this ifp
    IGIF_LOOPBACK = 0x00000002    # Send IGMP reports to loopback

    class struct_igmp_ifinfo(Structure):
        _fields_ = [
            ('igi_ifindex',  c_uint32),
            ('igi_version',  c_uint32),
            ('igi_v1_timer', c_uint32),
            ('igi_v2_timer', c_uint32),
            ('igi_v3_timer', c_uint32),
            ('igi_flags',    c_uint32),
            ('igi_rv',       c_uint32),
            ('igi_qi',       c_uint32),
            ('igi_qri',      c_uint32),
            ('igi_uri',      c_uint32),]

    MLIF_SILENT    = 0x00000001  # Do not use MLD on this ifp 
    MLIF_USEALLOW  = 0x00000002  # Use ALLOW/BLOCK for joins/leaves
    MLIF_PROCESSED = 0x00000004  # Entry has been processed and can be skipped

    class struct_mld_ifinfo(Structure):
        _fields_ = [
            ('mli_ifindex',  c_uint32),
            ('mli_version',  c_uint32),
            ('mli_v1_timer', c_uint32),
            ('mli_v2_timer', c_uint32),
            ('mli_flags',    c_uint32),
            ('mli_rv',       c_uint32),
            ('mli_qi',       c_uint32),
            ('mli_qri',      c_uint32),
            ('mli_uri',      c_uint32),
            ('_pad',         c_uint32),]

    #######################################################
    #
    def get_sockaddr_name(psa):
        """ get the interface name from the link layer sockaddr struct """

        sdl  = cast(psa, POINTER(struct_sockaddr_dl)).contents
        name = bytes(sdl.sdl_data[:sdl.sdl_nlen]).decode(GETIFADDRS_ENCODING)

        return name

    def get_sockaddr_address(psa, family):
        """ get the group address from ifma returned info """

        if family == AF_INET:
            sin  = cast(psa, POINTER(struct_sockaddr_in)).contents
            addr = GroupIPv4Address(bytes(sin.sin_addr))
        elif family == AF_INET6:
            sin6 = cast(psa, POINTER(struct_sockaddr_in6)).contents
            addr = GroupIPv6Address(bytes(sin6.sin6_addr),
                   scope_id=sin6.sin6_scope_id)
        elif family == AF_LOCAL_L2:
            addr = get_sockaddr_lladdress(psa)
        
        return addr 

    def get_sockaddr_lladdress(psa):
        """ get the translated link layer group address from LL sockaddr """

        sdl  = cast(psa, POINTER(struct_sockaddr_dl)).contents
        addr = GroupLinkLayerAddress(
                 bytes(sdl.sdl_data[sdl.sdl_nlen:sdl.sdl_nlen+sdl.sdl_alen]))

        return addr

    def ifmap_iter(ifmap):
        """ generator to iterate over multicast groups """

        ifma = ifmap.contents
        while True:
            yield ifma
            if not ifma.ifma_next:
                break
            ifma = ifma.ifma_next.contents

if IS_DARWIN:
    ### getifmaddrs is only supported on MacOS
    def get_multicast_addresses(ifname=None, family=AF_UNSPEC, ifiter=None):

        ifmap = POINTER(struct_ifmaddrs)()
        if libc.getifmaddrs(pointer(ifmap)) != 0:
            err = get_geterrno()
            logger.error("getifmaddrs: [%d] '%s'", err, os.strerror(err))
            return None

        ifaces = ifiter
        if not ifaces:
            ifaces = get_network_interfaces()

        for ifma in ifmap_iter(ifmap):
            if not ifma or not ifma.ifma_name:
                continue
            name = get_sockaddr_name(ifma.ifma_name)
            if ifname and ifname != name:
                continue
            if ifma.ifma_addr:
                fam = ifma.ifma_addr.contents.sa_family
                if family != AF_UNSPEC and fam != family:
                    continue
                group = get_sockaddr_address(ifma.ifma_addr, fam)
                if ifma.ifma_lladdr:
                    group.transla = get_sockaddr_lladdress(ifma.ifma_lladdr)
                ifc = get_interface(name, ifiter=ifaces)
                ifc.groups.append(group)

        for iface in ifaces:
            get_igmp(iface)
            get_mld(iface)
            for group in iface.groups:
                if group.family == AF_INET:
                    get_sources(iface, group)
                elif group.family == AF_INET6:
                    get_sources6(iface, group)

        return ifaces    

    def get_sources(iface, group):
        """ get the sources of a given group from kernel """

        mibsize = c_uint(7)
        mib = (c_int * mibsize.value)()
    
        if libc.sysctlnametomib(b'net.inet.ip.mcast.filters',
                                  mib, pointer(mibsize)) != 0:
            logger.error("sysctlnametomib v4 sources: [%d] '%s'",
                          get_errno(), os.strerror(get_errno()))
            return 1

        mibsize = c_uint(7)
        length  = c_size_t(0)
        mib[5]  = iface.index
        mib[6]  = int.from_bytes(group.in_addr, sys.byteorder)

        if libc.sysctl(mib, mibsize, NULL, pointer(length), NULL, 0) != 0:
            logger.error("sysctl v4 groups: [%d] '%s'", get_errno(),
                          os.strerror(get_errno()))
            return 1

        buf = (c_byte * length.value)()

        if libc.sysctl(mib, mibsize, buf, pointer(length), NULL, 0) != 0:
            logger.error("sysctl (2) v4 groups: [%d] '%s'", get_errno(),
                          os.strerror(get_errno()))
            return 1

        size   = sizeof(c_uint32)
        buffer = bytes(buf)
        fmode  = int.from_bytes(buffer[:size], sys.byteorder)

        start      = size
        addrsize   = 4
        while start < length.value:
            source = GroupIPv4Address(buffer[start:start+addrsize])
            group.sources.append(source)
            start += addrsize

        return 0

    def get_sources6(iface, group):

        mibsize = c_uint(10)
        mib = (c_int * mibsize.value)()
    
        if libc.sysctlnametomib(b'net.inet6.ip6.mcast.filters', mib,
                                  pointer(mibsize)) != 0:
            logger.error("sysctlnametomib v6 sources: [%d] '%s'",
                          get_errno(), os.strerror(get_errno()))
            return 1

        mibsize = c_uint(10)
        length  = c_size_t(0)
        mib[5]  = iface.index
        mib[6]  = int.from_bytes(group.in_addr[0:4],   sys.byteorder)
        mib[7]  = int.from_bytes(group.in_addr[4:8],   sys.byteorder)
        mib[8]  = int.from_bytes(group.in_addr[8:12],  sys.byteorder)
        mib[9]  = int.from_bytes(group.in_addr[12:16], sys.byteorder)

        if libc.sysctl(mib, mibsize, NULL, pointer(length), NULL, 0) != 0:
            logger.error("sysctl v6 groups: [%d] '%s'", get_errno(),
                          os.strerror(get_errno()))
            return 1

        buf = (c_byte * length.value)()

        if libc.sysctl(mib, mibsize, buf, pointer(length), NULL, 0) != 0:
            logger.error("sysctl (2) v6 groups: [%d] '%s'", get_errno(),
                          os.strerror(get_errno()))
            return 1

        size   = sizeof(c_uint32)
        buffer = bytes(buf)
        fmode  = int.from_bytes(buffer[:size], sys.byteorder)

        start      = size
        addrsize   = 16
        while start < length.value:
            source = GroupIPv6Address(buffer[start:start+addrsize],
                                      scope_id=iface.index)
            group.sources.append(source)
            start += addrsize

        return 0

    def get_igmp(iface):

        mibsize = c_uint(5)
        mib = (c_int * mibsize.value)()

        if libc.sysctlnametomib(b'net.inet.igmp.ifinfo', mib,
                                  pointer(mibsize)) != 0:
            logger.error("sysctlnametomib igmp: [%d] '%s'", get_errno(),
                          os.strerror(get_errno()))
            return 1

        mib[mibsize.value] = iface.index
        mibsize.value += 1

        ifinfo = struct_igmp_ifinfo()
        len = c_size_t(sizeof(ifinfo))

        if libc.sysctl(mib, mibsize,
                       pointer(ifinfo), pointer(len), NULL, 0) != 0:
            logger.error("sysctl igmp: [%d] '%s'", get_errno(),
                          os.strerror(get_errno()))
            return 1

        iface.querier = ifinfo.igi_version
        iface.mflags  = ifinfo.igi_flags

        return 0

    def get_mld(iface):

        mibsize = c_uint(5)
        mib = (c_int * mibsize.value)()

        if libc.sysctlnametomib(b'net.inet6.mld.ifinfo', mib,
                                  pointer(mibsize)) != 0:
            logger.error("sysctlnametomib mld: [%d] '%s'", get_errno(),
                          os.strerror(get_errno()))
            return 1

        mib[mibsize.value] = iface.index
        mibsize.value += 1

        ifinfo = struct_mld_ifinfo()
        len = c_size_t(sizeof(ifinfo))

        if libc.sysctl(mib, mibsize,
                       pointer(ifinfo), pointer(len), NULL, 0) != 0:
            logger.error("sysctl mld: [%d] '%s'", get_errno(),
                          os.strerror(get_errno()))
            return 1

        iface.querier = ifinfo.mli_version
        iface.mflags  = ifinfo.mli_flags

        return 0

    def print_multicast_groups_family(family, family_title):

        print("%s Multicast Group Memberships" % family_title)
        print("%-24s%-24s%-24s" % ("Group", family_title, "Netif"))

        m = get_multicast_addresses(family=family)
        for iface in m:
            for group in iface.groups:
                trans = "<none>"
                if group.transla:
                    trans = group.transla
                print("%-24s%-24s%-24s" % (group.printable, trans, iface.name))

    def print_multicast_groups():

        print_multicast_groups_family(AF_LOCAL_L2, "Link-layer")
        print()
        print_multicast_groups_family(AF_INET, "IPv4")
        print()
        print_multicast_groups_family(AF_INET6, "IPv6")

if IS_LINUX:
    # Linux stores igmp, group and source information in kernel files
    #
    IGMP_FILE    = "/proc/net/igmp"
    IGMP6_FILE   = "/proc/net/igmp6"
    SOURCE_FILE  = "/proc/net/mcfilter"
    SOURCE_FILE6 = "/proc/net/mcfilter6"

    QUERIER_VALUES = ("unknown", "V1", "V2", "V3")

    #define MAF_TIMER_RUNNING	0x01
    #define MAF_LAST_REPORTER	0x02
    #define MAF_LOADED		0x04
    #define MAF_NOREPORT	0x08
    #define MAF_GSQUERY		0x10

    def get_multicast_addresses(ifname=None, family=AF_UNSPEC, ifiter=None):

        if not ifiter:
            ifiter = get_network_interfaces()

        if parse_igmp_file(ifiter) != 0:
            return 1
        if parse_source_file(ifiter) != 0:
            return 1
        if parse_igmp6_file(ifiter) != 0:
            return 1
        return parse_source_file6(ifiter)

    def parse_igmp_file(ifiter):
        """ open and read file /proc/net/igmp (per interface groups) """

        with open(IGMP_FILE) as f:
            lines = f.readlines()

        iface = None

        for line in lines:

            if line.startswith('\t'):
                if not iface:
                    logger.error("Error parsing igmp kernel file")
                    return 1
                grp, nusr, timer, reporter = line.split()
                group = GroupIPv4Address(
                                 int(grp, 16).to_bytes(4, sys.byteorder))
                group.users = int(nusr)
                iface.groups.append(group)

            else:
                index = line.index(":")
                ifx, device = line[:index].split()
                if ifx == "Idx":
                    continue
                iface = get_interface(device, ifiter=ifiter)
                if not iface:
                    logger.error("Error parsing igmp kernel file. "
                                 "Invalid interface: %s", device)
                    return 1
                _, querier = line[index+1:].split()
                iface.querier = 0
                if querier in QUERIER_VALUES:
                    iface.querier = QUERIER_VALUES.index(querier)

        return 0

    def parse_igmp6_file(ifiter):
        """ open and read file /proc/net/igmp6 (per interface groups) """

        with open(IGMP6_FILE) as f:
            lines = f.readlines()

        for line in lines:

            index, device, grp, nusr, timer, reporter = line.split()
            iface = get_interface(device, ifiter=ifiter)
            if not iface:
                logger.error("Error parsing igmp kernel file. "
                             "Invalid interface: %s", device)
                return 1
            group = GroupIPv6Address(int(grp, 16).to_bytes(16, 'big'),
                                     scope_id=iface.index)
            iface.groups.append(group)
            group.users = int(nusr)

        return 0

    def parse_source_file(ifiter):

        with open(SOURCE_FILE) as f:
            lines = f.readlines()

        for line in lines:

            index, device, grp, src, incl, excl, *extra = line.split()
            if index == "Idx":
                continue
            iface = get_interface(device, ifiter=ifiter)
            if not iface:
                logger.error("Error parsing igmp kernel file. "
                             "Invalid interface: %s", device)
                return 1

            group = None
            grp = int(grp, 16).to_bytes(4, 'big')
            for g in iface.groups:
                if grp == g.in_addr:
                    group = g
            if group is None:
                logger.error("could not find group %s in interface %s",
                              grp, device)
                return 1

            source = IPv4Address(int(src, 16).to_bytes(4, 'big'))
            group.sources.append(source)
            group.fmode = MODE_UNKNOWN
            if int(incl) > 0:
                group.fmode = MODE_INCLUDE
            elif int(excl) > 0:
                group.fmode = MODE_EXCLUDE

    def parse_source6_file(ifiter):

        with open(SOURCE6_FILE) as f:
            lines = f.readlines()

        for line in lines:

            index, device, grp, src, incl, excl, *extra = line.split()
            if index == "Idx":
                continue
            iface = get_interface(device, ifiter=ifiter)
            if not iface:
                logger.error("Error parsing igmp kernel file. "
                             "Invalid interface: %s", device)
                return 1

            group = None
            grp = int(grp, 16).to_bytes(16, 'big')
            for g in iface.groups:
                if grp == g.in_addr:
                    group = g
            if group is None:
                logger.error("could not find group %s in interface %s",
                              grp, device)
                return 1

            source = IPv4Address(int(src, 16).to_bytes(4, 'big'))
            group.sources.append(source)
            group.fmode = MODE_UNKNOWN
            if int(incl) > 0:
                group.fmode = MODE_INCLUDE
            elif int(excl) > 0:
                group.fmode = MODE_EXCLUDE

    def print_multicast_groups():

        print("IPv6/IPv4 Group Memberships")
        print("Interface       RefCnt Group")
        print("--------------- ------ ---------------------")

        print_igmp_info()
        print("%-15s %-6d %-20s" % (device, users, group))
        print_igmp6_info()
        print("%-15s %-6d %-20s" % (device, users, group))

        print("")
        print("Sources")
        print("Interface       Group                  "
              "Source                 Incl  Excl")
        print("--------------- ---------------------- "
              "---------------------- ----- -----") 
        parse_source_file()
        print("%-15s %-22s %-22s %-5d %-5d" %
                   (device, group, source, include, exclude))
        parse_source6_file()
        print("%-15s %-22s %-22s %-5d %-5d" %
                   (device, group, source, include, exclude))

if __name__ == "__main__":
    print_multicast_groups()
