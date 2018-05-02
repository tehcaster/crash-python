#!/usr/bin/env python
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

import gdb
from crash.infra import CrashBaseClass, export
from crash.util import container_of, find_member_variant, get_symbol_value
from crash.types.percpu import get_percpu_var
from bitmap import for_each_set_bit
import crash.types.zone

# TODO: un-hardcode this
VMEMMAP_START   = 0xffffea0000000000
DIRECTMAP_START = 0xffff880000000000
PAGE_SIZE       = 4096L

class TypesNodeUtilsClass(CrashBaseClass):
    __symbols__ = [ 'numa_node' ]

    @export
    def numa_node_id(self, cpu):
        return long(get_percpu_var(self.numa_node, cpu))

class Node(CrashBaseClass):
    __types__ = [ 'pg_data_t', 'struct zone' ]

    nids_online = None
    nids_possible = None

    @staticmethod
    def __get_nodes_state(state):
        n_state = get_symbol_value(state)
        node_states = get_symbol_value("node_states")
        bits = node_states[n_state]["bits"]
        return list(for_each_set_bit(bits))

    @staticmethod
    def for_each_online_nid():
        if Node.nids_online is None:
            Node.nids_online = Node.__get_nodes_state("N_ONLINE")
        for nid in Node.nids_online:
            yield nid

    @staticmethod
    def for_each_online_node():
        for nid in Node.for_each_online_nid():
            yield Node.from_nid(nid)

    @staticmethod
    def for_each_nid():
        if Node.nids_possible is None:
            Node.nids_possible = Node.__get_nodes_state("N_POSSIBLE")
        for nid in Node.nids_possible:
            yield nid

    @staticmethod
    def for_each_node():
        for nid in Node.for_each_nid():
            yield Node.from_nid(nid)

    @staticmethod
    def from_nid(nid):
        node_data = gdb.lookup_global_symbol("node_data").value()
        return Node(node_data[nid].dereference())

    def for_each_zone(self):
        node_zones = self.gdb_obj["node_zones"]

        ptr = long(node_zones[0].address)

        (first, last) = node_zones.type.range()
        for zid in range(first, last + 1):
            # FIXME: gdb seems to lose the alignment padding with plain
            # node_zones[zid], so we have to simulate it using zone_type.sizeof
            # which appears to be correct
            zone = gdb.Value(ptr).cast(self.zone_type.pointer()).dereference()
            yield crash.types.zone.Zone(zone, zid)
            ptr += self.zone_type.sizeof

    def __init__(self, obj):
        self.gdb_obj = obj

