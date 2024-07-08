#! /usr/bin/env python3

import sys
import util.getifaddrs

if sys.platform == 'darwin':
    int1 = "lo0"        # loopback
    int2 = "en0"        # ethernet
    int3 = "en2"        # wifi

# get_interface_names()
#
gin = util.getifaddrs.get_interface_names()
assert isinstance(gin, list) and len(gin) > 0

# get_interface()
#
ifcs = util.getifaddrs.get_interface(int1)
ifci = util.getifaddrs.get_interface(ifcs.index)
assert ifcs.name == ifci.name

ifcs = util.getifaddrs.get_interface(int2)
ifci = util.getifaddrs.get_interface(ifcs.index)
assert ifcs.name == ifci.name

ifcs = util.getifaddrs.get_interface(int3)
ifci = util.getifaddrs.get_interface(ifcs.index)
assert ifcs.name == ifci.name

# get_interface_addresses() and get_interface_address()
#
ifaddrs1 = util.getifaddrs.get_interface_addresses(int1)
ifaddrs2 = util.getifaddrs.get_interface_addresses(int2,
                       util.getifaddrs.GIA_AF_INET6, util.getifaddrs.GIA_SCP_LINK)
ifaddrs3 = util.getifaddrs.get_interface_addresses(int3)

ifaddr1 = util.getifaddrs.get_interface_address(int1, util.getifaddrs.GIA_AF_INET)
ifaddr2 = util.getifaddrs.get_interface_address(int2, util.getifaddrs.GIA_AF_INET6)
ifaddr3 = util.getifaddrs.get_interface_address(int3, util.getifaddrs.GIA_AF_LINK)

assert ifaddr1 not in ifaddrs1
assert ifaddr2 not in ifaddrs2
assert ifaddr3 not in ifaddrs3

# print_interface_addresses() and print_interface_address()
#
#util.getifaddrs.find_interface_addresses(int1, 
#util.getifaddrs.find_interface_address


print("Passed all tests passed successfully")
