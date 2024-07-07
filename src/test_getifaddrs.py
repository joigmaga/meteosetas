#! /usr/bin/env python3

import sys
import util.getifaddrs

if sys.platform == 'darwin':
    int1 = "lo0"        # loopback
    int2 = "en0"        # ethernet
    int3 = "en2"        # wifi

gin = util.getifaddrs.get_interface_names()
assert isinstance(gin, list) and len(gin) > 0

ifcs = util.getifaddrs.get_interface(int1)
ifci = util.getifaddrs.get_interface(ifcs.index)
assert ifcs.name == ifci.name

ifcs = util.getifaddrs.get_interface(int2)
ifci = util.getifaddrs.get_interface(ifcs.index)
assert ifcs.name == ifci.name

ifcs = util.getifaddrs.get_interface(int3)
ifci = util.getifaddrs.get_interface(ifcs.index)
assert ifcs.name == ifci.name


ifaddrs1 = util.getifaddrs.get_interface_addresses(int1)
ifaddrs2 = util.getifaddrs.get_interface_addresses(int2)
ifaddrs3 = util.getifaddrs.get_interface_addresses(int3)

ifaddr1 = util.getifaddrs.get_interface_address(int1, util.getifaddrs.GIA_AF_INET)
ifaddr2 = util.getifaddrs.get_interface_address(int2, util.getifaddrs.GIA_AF_INET6)
ifaddr3 = util.getifaddrs.get_interface_address(int3, util.getifaddrs.GIA_AF_LINK)

assert ifaddr1 not in ifaddrs1
assert ifaddr2 not in ifaddrs2
assert ifaddr3 not in ifaddrs3

print("All tests successfully passed")
