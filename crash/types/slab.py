#!/usr/bin/env python
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

import gdb
from util import container_of

kmem_cache_type = gdb.lookup_type('struct kmem_cache')

AC_PERCPU = "percpu"
AC_SHARED = "shared"
AC_ALIEN  = "alien"

class KmemCache():
    gdb_obj = None

    num = 0
    buffer_size = 0
    name = ""

    def __get_nodelist(self, node):
        return self.gdb_obj["nodelists"][node]
        
    def __get_nodelists(self):
        # TODO use real number of nodes
        i = 0;
        while True:
            node = self.__get_nodelist(i)
            if long(node) == 0L:
                break
            yield (i, node.dereference())
            i += 1

    def __init__(self, name, gdb_obj):
        self.name = name
        self.gdb_obj = gdb_obj
        
        self.num = int(gdb_obj["num"])
        self.buffer_size = int(gdb_obj["buffer_size"])

    def __get_array_cache(self, acache, ac_type, nid_src, nid_tgt):
        res = dict()
        
        avail = int(acache["avail"])
        limit = int(acache["limit"])

        # TODO check avail > limit
        if avail == 0:
            return res

        for i in range(avail):
            ptr = long(acache["entry"][i])
            res[ptr] = {"ac_type" : ac_type, "nid_src" : nid_src,
                        "nid_tgt" : nid_tgt}

        return res

    def __get_array_caches(self, array, ac_type, nid_src, limit):
        res = dict()

        for i in range(limit):
            ptr = array[i]

            # TODO: limit should prevent this?
            if long(ptr) == 0L:
                break

            # A node cannot have alien cache on the same node, but some
            # kernels (xen) seem to have a non-null pointer there anyway
            if ac_type == AC_ALIEN and nid_src == i:
                break

            res.update(self.__get_array_cache(ptr.dereference(), ac_type,
                        nid_src, i))

        return res

    def get_all_array_caches(self):
        res = dict()

        percpu_cache = self.gdb_obj["array"]
        # TODO real limit
        res.update(self.__get_array_caches(percpu_cache, AC_PERCPU, -1, 10))

        for (nid, node) in self.__get_nodelists():
            shared_cache = node["shared"]
            res.update(self.__get_array_cache(shared_cache, AC_SHARED, nid, nid)
            alien_cache = node["alien"]
            # TODO check that this only happens for single-node systems?
            if (long(alien_cache) == 0L)
                continue
            # TODO real limit
            res.update(self.__get_array_caches(alien_cache, AC_ALIEN, nid, 10))

        return res
