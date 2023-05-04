# Copyright 2021-present Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Thrift SAI interface Neighbor tests
"""
from ptf.packet import *
from ptf.testutils import *
from ptf.thriftutils import *

from sai_base_test import *


@group("draft")
class NeighborAttrIpv6Test(SaiHelperSimplified):
    """
    Neighbor entry attributes IPv6 tests class
    Configuration
    +----------+-----------+
    | port0    | port0_rif |
    +----------+-----------+
    | port1    | port1_rif |
    +----------+-----------+
    """

    def setUp(self):
        super(NeighborAttrIpv6Test, self).setUp()

        self.create_routing_interfaces(ports=[0, 1])

        self.test_rif = self.port0_rif
        self.ipv6_addr = "2001:0db8::1:10"
        self.ll_ipv6_addr = "fe80::10"
        self.mac_addr = "00:10:10:10:10:10"

        self.pkt_v6 = simple_udpv6_packet(eth_dst=ROUTER_MAC,
                                          ipv6_dst=self.ipv6_addr,
                                          ipv6_hlim=64)
        self.exp_pkt_v6 = simple_udpv6_packet(eth_dst=self.mac_addr,
                                              eth_src=ROUTER_MAC,
                                              ipv6_dst=self.ipv6_addr,
                                              ipv6_hlim=63)

        self.ll_pkt_v6 = simple_udpv6_packet(eth_dst=ROUTER_MAC,
                                             ipv6_dst=self.ll_ipv6_addr,
                                             ipv6_hlim=64)

    def runTest(self):
        self.noHostRouteIpv6NeighborTest()
        self.noHostRouteIpv6LinkLocalNeighborTest()
        self.addHostRouteIpv6NeighborTest()

    def tearDown(self):
        self.destroy_routing_interfaces()

        super(NeighborAttrIpv6Test, self).tearDown()

    def noHostRouteIpv6NeighborTest(self):
        '''
        Verifies if IPv6 host route is not created according to
        SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE attribute value
        '''
        print("\nnoHostRouteIpv6NeighborTest()")

        try:
            nbr_entry_v6 = sai_thrift_neighbor_entry_t(
                rif_id=self.test_rif,
                ip_address=sai_ipaddress(self.ipv6_addr))
            status = sai_thrift_create_neighbor_entry(
                self.client,
                nbr_entry_v6,
                dst_mac_address=self.mac_addr,
                no_host_route=True)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            print("Sending IPv6 packet when host route not exists")
            send_packet(self, self.dev_port1, self.pkt_v6)
            verify_no_other_packets(self)
            print("Packet dropped")

        finally:
            sai_thrift_remove_neighbor_entry(self.client, nbr_entry_v6)

    def noHostRouteIpv6LinkLocalNeighborTest(self):
        '''
        Verifies if host route is not created for link local IPv6 address
        irrespective of SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE attribute
        value
        '''
        print("\nnoHostRouteIpv6LinkLocalNeighborTest()")

        try:
            ll_nbr_entry_1 = sai_thrift_neighbor_entry_t(
                rif_id=self.test_rif,
                ip_address=sai_ipaddress(self.ll_ipv6_addr))
            status = sai_thrift_create_neighbor_entry(
                self.client,
                ll_nbr_entry_1,
                dst_mac_address=self.mac_addr,
                no_host_route=True)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            print("Sending IPv6 packet - no_host_route was set to True")
            send_packet(self, self.dev_port1, self.ll_pkt_v6)
            verify_no_other_packets(self)
            print("Packet dropped")

            status = sai_thrift_remove_neighbor_entry(
                self.client, ll_nbr_entry_1)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            ll_nbr_entry_2 = sai_thrift_neighbor_entry_t(
                rif_id=self.test_rif,
                ip_address=sai_ipaddress(self.ll_ipv6_addr))
            status = sai_thrift_create_neighbor_entry(
                self.client,
                ll_nbr_entry_2,
                dst_mac_address=self.mac_addr,
                no_host_route=False)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            print("Sending IPv6 packet - no_host_route was set to False")
            send_packet(self, self.dev_port1, self.ll_pkt_v6)
            verify_no_other_packets(self)
            print("Packet dropped")

        finally:
            sai_thrift_remove_neighbor_entry(self.client, ll_nbr_entry_2)

    def addHostRouteIpv6NeighborTest(self):
        '''
        Verifies if IPv6 host route is created according to
        SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE attribute value
        '''
        print("\naddHostRouteIpv6NeighborTest()")

        try:
            nbr_entry_v6 = sai_thrift_neighbor_entry_t(
                rif_id=self.test_rif,
                ip_address=sai_ipaddress(self.ipv6_addr))
            status = sai_thrift_create_neighbor_entry(
                self.client,
                nbr_entry_v6,
                dst_mac_address=self.mac_addr,
                no_host_route=False)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            print("Sending IPv6 packet when host route exists")
            send_packet(self, self.dev_port1, self.pkt_v6)
            verify_packet(self, self.exp_pkt_v6, self.dev_port0)
            print("Packet forwarded")

        finally:
            sai_thrift_remove_neighbor_entry(self.client, nbr_entry_v6)


@group("draft")
class NeighborAttrIpv4Helper(SaiHelperSimplified):
    """
    Neighbor entry attributes IPv4 tests class
    Configuration
    +----------+-----------+
    | port0    | port0_rif |
    +----------+-----------+
    | port1    | port1_rif |
    +----------+-----------+
    """
    def setUp(self):
        super(NeighborAttrIpv4Helper, self).setUp()

        self.create_routing_interfaces(ports=[0, 1])

        self.test_rif = self.port0_rif
        self.ipv4_addr = "10.10.10.1"
        self.mac_addr = "00:10:10:10:10:10"
        self.mac_update_addr = "00:22:22:33:44:66"

        self.nhop = sai_thrift_create_next_hop(self.client,
                                               ip=sai_ipaddress(self.ipv4_addr),
                                               router_interface_id=self.port0_rif,
                                               type=SAI_NEXT_HOP_TYPE_IP)
        self.route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                    destination=sai_ipprefix('10.10.10.1/31'))
        sai_thrift_create_route_entry(self.client, self.route_entry0, next_hop_id=self.nhop)

        self.pkt_v4 = simple_udp_packet(eth_dst=ROUTER_MAC,
                                        ip_dst=self.ipv4_addr,
                                        ip_ttl=64)
        self.exp_pkt_v4 = simple_udp_packet(eth_dst=self.mac_addr,
                                            eth_src=ROUTER_MAC,
                                            ip_dst=self.ipv4_addr,
                                            ip_ttl=64)
        self.exp_updt_mac_pkt = simple_udp_packet(eth_dst=self.mac_update_addr,
                                                  eth_src=ROUTER_MAC,
                                                  ip_dst=self.ipv4_addr,
                                                  ip_ttl=64)

    def tearDown(self):
        self.destroy_routing_interfaces()
        
        sai_thrift_remove_route_entry(self.client, self.route_entry)
        sai_thrift_remove_next_hop(self.client, self.nhop)

        super(NeighborAttrIpv4Helper, self).tearDown()


@group("draft")
class NoHostRouteIpv4NeighborTest(NeighborAttrIpv4Helper):
    """
    Test run on two ports
    """
    def runTest(self):
        '''
        Verifies if IPv4 host route is not created according to
        SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE attribute value
        '''
        print("\nNoHostRouteIpv4NeighborTest()")

        try:
            nbr_entry_v4 = sai_thrift_neighbor_entry_t(
                rif_id=self.test_rif,
                ip_address=sai_ipaddress(self.ipv4_addr))
            status = sai_thrift_create_neighbor_entry(
                self.client,
                nbr_entry_v4,
                dst_mac_address=self.mac_addr,
                no_host_route=True)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            print("Sending IPv4 packet when host route not exists")
            send_packet(self, self.dev_port1, self.pkt_v4)
            verify_no_other_packets(self)
            print("Packet dropped")

        finally:
            sai_thrift_remove_neighbor_entry(self.client, nbr_entry_v4)


@group("draft")
class AddHostRouteIpv4NeighborTest(NeighborAttrIpv4Helper):
    """
    Test run on two ports
    """
    def runTest(self):
        '''
        Verifies if IPv4 host route is created according to
        SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE attribute value
        '''
        print("\nAddHostRouteIpv4NeighborTest()")

        try:
            nbr_entry_v4 = sai_thrift_neighbor_entry_t(
                rif_id=self.test_rif,
                ip_address=sai_ipaddress(self.ipv4_addr))
            status = sai_thrift_create_neighbor_entry(
                self.client,
                nbr_entry_v4,
                dst_mac_address=self.mac_addr,
                no_host_route=False)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            print("Sending IPv4 packet when host route exists")
            send_packet(self, self.dev_port1, self.pkt_v4)
            verify_packet(self, self.exp_pkt_v4, self.dev_port0)
            print("Packet forwarded")

        finally:
            sai_thrift_remove_neighbor_entry(self.client, nbr_entry_v4)


class UpdateNeighborEntryAttributeDstMacAddr(NeighborAttrIpv4Helper):
    '''
    Verifies if SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS is updated
    '''

    def setUp(self):
        super(UpdateNeighborEntryAttributeDstMacAddr, self).setUp()

    def runTest(self):
        print("\nUpdateNeighborEntryAttributeDstMacAddr()")

        nbr_entry_v4 = sai_thrift_neighbor_entry_t(
            rif_id=self.test_rif,
            ip_address=sai_ipaddress(self.ipv4_addr))
        status = sai_thrift_create_neighbor_entry(
            self.client,
            nbr_entry_v4,
            dst_mac_address=self.mac_addr)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        try:
            print("Sending IPv4 packet before updating the destination mac")
            send_packet(self, self.dev_port1, self.pkt_v4)
            verify_packet(self, self.exp_pkt_v4, self.dev_port0)
            print("Packet forwarded")
            
            print(f"Update neighbor to {self.mac_update_addr}")
            status = sai_thrift_set_neighbor_entry_attribute(
                self.client,
                nbr_entry_v4,
                dst_mac_address=self.mac_update_addr)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_neighbor_entry_attribute(
                self.client, nbr_entry_v4, dst_mac_address=True)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
            self.assertEqual(attr['dst_mac_address'], self.mac_update_addr)

            print("Sending IPv4 packet after updating the destination mac")
            send_packet(self, self.dev_port1, self.pkt_v4)
            verify_packet(self, self.exp_updt_mac_pkt, self.dev_port0)
            print("Packet forwarded")

        finally:
            sai_thrift_remove_neighbor_entry(self.client, nbr_entry_v4)

    def tearDown(self):
        super(UpdateNeighborEntryAttributeDstMacAddr, self).tearDown()
