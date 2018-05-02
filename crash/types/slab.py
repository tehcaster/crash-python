#!/usr/bin/env python
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

import gdb
import crash
import sys
import traceback
from crash.util import container_of, find_member_variant, get_symbol_value
from crash.util import safe_get_symbol_value
from percpu import get_percpu_var
from crash.infra import CrashBaseClass, export
from crash.types.list import list_for_each_entry
from crash.types.page import Page
from crash.types.node import Node
from crash.types.cpu import for_each_online_cpu
from crash.cache.slab import cache as caches_cache
from crash.types.node import numa_node_id

AC_PERCPU = "percpu"
AC_SHARED = "shared"
AC_ALIEN  = "alien"

slab_partial = 0
slab_full = 1
slab_free = 2

slab_list_name = {0: "partial", 1: "full", 2: "free"}

BUFCTL_END = ~0 & 0xffffffff

class Slab(CrashBaseClass):
    __types__ = [ 'struct slab', 'struct page', 'kmem_cache', 'kmem_bufctl_t',
                  'freelist_idx_t' ]
    __type_callbacks__ = [ ('struct page', 'check_page_type'),
                           ('struct slab', 'check_slab_type'),
                           ('kmem_bufctl_t', 'check_bufctl_type'),
                           ('freelist_idx_t', 'check_bufctl_type') ]

    slab_list_head = None
    page_slab = None
    real_slab_type = None
    bufctl_type = None

    @classmethod
    def check_page_type(cls, gdbtype):
        if cls.page_slab is None:
            cls.page_slab = True
            cls.real_slab_type = gdbtype
            cls.slab_list_head = 'lru'

    @classmethod
    def check_slab_type(cls, gdbtype):
        cls.page_slab = False
        cls.real_slab_type = gdbtype
        cls.slab_list_head = 'list'

    @classmethod
    def check_bufctl_type(cls, gdbtype):
        cls.bufctl_type = gdbtype

    @classmethod
    def from_addr(cls, slab_addr, kmem_cache):
        if not isinstance(kmem_cache, KmemCache):
            kmem_cache = KmemCache.from_addr(kmem_cache)
        slab_struct = gdb.Value(slab_addr).cast(cls.real_slab_type.pointer()).dereference()
        return Slab(slab_struct, kmem_cache)

    @classmethod
    def from_page(cls, page):
        kmem_cache_addr = long(page.get_slab_cache())
        kmem_cache = KmemCache.from_addr(kmem_cache_addr)
        if cls.page_slab:
            return Slab(page.gdb_obj, kmem_cache)
        else:
            slab_addr = long(page.get_slab_page())
            return Slab.from_addr(slab_addr, kmem_cache)

    @staticmethod
    def from_obj(addr):
        page = Page.from_addr(addr).compound_head()
        if not page.is_slab():
            return None

        return Slab.from_page(page)

    @classmethod
    def from_list(cls, list_head, kmem_cache, reverse=False):
        for gdb_slab in list_for_each_entry(list_head, cls.real_slab_type,
                        cls.slab_list_head, reverse=reverse):
            try:
                slab = Slab(gdb_slab, kmem_cache)
            except:
                print("failed to initialize slab object {:#x}: {}".format(
                            gdb_slab.address, sys.exc_info()[0]))
                #traceback.print_exc()
                slab = Slab(gdb_slab, kmem_cache, error = True)
            yield slab

    def __add_free_obj_by_idx(self, idx):
        objs_per_slab = self.kmem_cache.objs_per_slab
        bufsize = self.kmem_cache.buffer_size
        
        if (idx >= objs_per_slab):
            self.__error(": free object index %d overflows %d" % (idx,
                                                            objs_per_slab))
            return False

        obj_addr = self.s_mem + idx * bufsize
        if obj_addr in self.free:
            self.__error(": object %x duplicated on freelist" % obj_addr)
            return False
        else:
            self.free.add(obj_addr)
        
        return True

    def __populate_free(self):
        if self.free:
            return
        
        self.free = set()
        bufsize = self.kmem_cache.buffer_size
        objs_per_slab = self.kmem_cache.objs_per_slab

        if self.page_slab:
            page = self.gdb_obj
            freelist = page["freelist"].cast(self.bufctl_type.pointer())
            for i in range(self.inuse, objs_per_slab):
                obj_idx  = int(freelist[i])
                self.__add_free_obj_by_idx(obj_idx)

        else:
            bufctl = self.gdb_obj.address[1].cast(self.bufctl_type).address
            f = int(self.gdb_obj["free"])
            while f != BUFCTL_END:
                if not self.__add_free_obj_by_idx(f):
                    self.__error(": bufctl cycle detected")
                    break

                f = int(bufctl[f])

    def find_obj(self, addr):
        bufsize = self.kmem_cache.buffer_size
        objs_per_slab = self.kmem_cache.objs_per_slab
        
        if long(addr) < self.s_mem:
            return None

        idx = (long(addr) - self.s_mem) / bufsize
        if idx >= objs_per_slab:
            return None

        return self.s_mem + (idx * bufsize)

    def contains_obj(self, addr):
        obj_addr = self.find_obj(addr)

        if not obj_addr:
            return (False, 0L, None)

        self.__populate_free()
        if obj_addr in self.free:
            return (False, obj_addr, None)

        ac = self.kmem_cache.get_array_caches()

        if obj_addr in ac:
            return (False, obj_addr, ac[obj_addr])

        return (True, obj_addr, None)
    
    def __error(self, msg, misplaced = False):
        msg = "cache %s slab %x%s" % (self.kmem_cache.name,
                    long(self.gdb_obj.address), msg)
        self.error = True
        if misplaced:
            self.misplaced_error = msg
        else:
            print(msg)
 
    def __free_error(self, list_name):
        self.misplaced_list = list_name
        self.__error(": is on list %s, but has %d of %d objects allocated" %
                (list_name, self.inuse, self.kmem_cache.objs_per_slab), misplaced = True)

    def get_objects(self):
        bufsize = self.kmem_cache.buffer_size
        obj = self.s_mem
        for i in range(self.kmem_cache.objs_per_slab):
            yield obj
            obj += bufsize

    def get_allocated_objects(self):
        for obj in self.get_objects():
            c = self.contains_obj(obj)
            if c[0]:
                yield obj

    def check(self, slabtype, nid):
        self.__populate_free()
        num_free = len(self.free)
        max_free = self.kmem_cache.objs_per_slab

        if self.kmem_cache.off_slab and not Slab.page_slab:
            struct_slab_slab = Slab.from_obj(long(self.gdb_obj.address))
            if not struct_slab_slab:
                self.__error(": OFF_SLAB struct slab is not a slab object itself")
            else:
                struct_slab_cache = struct_slab_slab.kmem_cache.name
                if not self.kmem_cache.off_slab_cache:
                    if struct_slab_cache != "size-64" and struct_slab_cache != "size-128":
                        self.__error(": OFF_SLAB struct slab is in a wrong cache %s" %
                                        struct_slab_cache)
                    else:
                        self.kmem_cache.off_slab_cache = struct_slab_cache
                elif struct_slab_cache != self.kmem_cache.off_slab_cache:
                    self.__error(": OFF_SLAB struct slab is in a wrong cache %s" %
                                    struct_slab_cache)
                
                struct_slab_obj = struct_slab_slab.contains_obj(self.gdb_obj.address)
                if not struct_slab_obj[0]:
                    self.__error(": OFF_SLAB struct slab is not allocated")
                    print(struct_slab_obj)
                elif struct_slab_obj[1] != long(self.gdb_obj.address):
                    self.__error(": OFF_SLAB struct slab at wrong offset{}".format(
                                    long(self.gdb_obj.address) - struct_slab_obj[1]))

        if self.inuse + num_free != max_free:
            self.__error(": inuse=%d free=%d adds up to %d (should be %d)" %
                    (self.inuse, num_free, self.inuse + num_free, max_free))
            
        if slabtype == slab_free:
            if num_free != max_free:
                self.__free_error("slab_free")
        elif slabtype == slab_partial:
            if num_free == 0 or num_free == max_free:
                self.__free_error("slab_partial")
        elif slabtype == slab_full:
            if num_free > 0:
                self.__free_error("slab_full")

        if self.page_slab:
            slab_nid = self.page.get_nid()
            if nid != slab_nid:
                self.__error(": slab is on nid %d instead of %d" % 
                                                        (slab_nid, nid))
                print "free objects %d" % num_free

        ac = self.kmem_cache.get_array_caches()
        last_page_addr = 0
        for obj in self.get_objects():
            if obj in self.free and obj in ac:
                self.__error(": obj %x is marked as free but in array cache:" % obj)
                print(ac[obj])
            try:
                page = Page.from_addr(obj).compound_head()
            except:
                self.__error(": failed to get page for object %x" % obj)
                continue

            if long(page.gdb_obj.address) == last_page_addr:
                continue

            last_page_addr = long(page.gdb_obj.address)

            if page.get_nid() != nid:
                self.__error(": obj %x is on nid %d instead of %d" % 
                                               (obj, page.get_nid(), nid))
            if not page.is_slab():
                self.__error(": obj %x is not on PageSlab page" % obj)
            kmem_cache_addr = long(page.get_slab_cache())
            if kmem_cache_addr != long(self.kmem_cache.gdb_obj.address):
                self.__error(": obj %x is on page where pointer to kmem_cache points to %x instead of %x" %
                                            (obj, kmem_cache_addr, long(self.kmem_cache.gdb_obj.address)))

            if self.page_slab:
                continue

            slab_addr = long(page.get_slab_page())
            if slab_addr != self.gdb_obj.address:
                self.__error(": obj %x is on page where pointer to slab wrongly points to %x" %
                                                                        (obj, slab_addr))
        return num_free

    def __init__(self, gdb_obj, kmem_cache, error=False):
        self.error = error
        self.gdb_obj = gdb_obj
        self.kmem_cache = kmem_cache
        self.free = None
        self.misplaced_list = None
        self.misplaced_error = None

        if error:
            return

        if self.page_slab:
            self.inuse = int(gdb_obj["active"])
            self.page = Page.from_obj(gdb_obj)
        else:
            self.inuse = int(gdb_obj["inuse"])
        self.s_mem = long(gdb_obj["s_mem"])

class KmemCache(CrashBaseClass):
    __types__ = [ 'struct kmem_cache', 'struct alien_cache' ]
    __type_callbacks__ = [ ('struct kmem_cache', 'check_kmem_cache_type'),
                           ('struct alien_cache', 'setup_alien_cache_type') ]

    buffer_size_name = None
    nodelists_name = None
    percpu_name = None
    percpu_cache = None
    head_name = None
    alien_cache_type_exists = False

    @classmethod
    def check_kmem_cache_type(cls, gdbtype):
        cls.buffer_size_name = find_member_variant(gdbtype, ('buffer_size', 'size'))
        cls.nodelists_name = find_member_variant(gdbtype, ('nodelists', 'node'))
        cls.percpu_name = find_member_variant(gdbtype, ('cpu_cache', 'array'))
        cls.percpu_cache = bool(cls.percpu_name == 'cpu_cache')
        cls.head_name = find_member_variant(gdbtype, ('next', 'list'))

    @classmethod
    def setup_alien_cache_type(cls, gdbtype):
        cls.alien_cache_type_exists = True

    def __get_nodelist(self, node):
        return self.gdb_obj[KmemCache.nodelists_name][node]
        
    def __get_nodelists(self):
        for nid in Node.for_each_nid():
            node = self.__get_nodelist(nid)
            if long(node) == 0L:
                continue
            yield (nid, node.dereference())

    @classmethod
    def __init_kmem_caches(cls):
        if caches_cache.populated:
            return

        list_caches = safe_get_symbol_value("slab_caches")

        if not list_caches:
            list_caches = safe_get_symbol_value("cache_chain")

        for cache in list_for_each_entry(list_caches, cls.kmem_cache_type,
                                                                cls.head_name):
            name = cache["name"].string()
            kmem_cache = KmemCache(name, cache)
 
            caches_cache.kmem_caches[name] = kmem_cache
            caches_cache.kmem_caches_by_addr[long(cache.address)] = kmem_cache

        caches_cache.populated = True

    @staticmethod
    def from_addr(addr):
        if not addr in caches_cache.kmem_caches_by_addr:
            KmemCache.__init_kmem_caches()
            
        return caches_cache.kmem_caches_by_addr[addr]

    @staticmethod
    def from_name(name):
        KmemCache.__init_kmem_caches()
        return caches_cache.kmem_caches[name]

    @staticmethod
    def get_all_caches():
        KmemCache.__init_kmem_caches()
        return caches_cache.kmem_caches.values()

    @staticmethod
    def all_find_obj(addr):
        slab = Slab.from_obj(addr)
        if not slab:
            return None
        return slab.contains_obj(addr)

    def __init__(self, name, gdb_obj):
        self.name = name
        self.gdb_obj = gdb_obj
        self.array_caches = None
        
        self.objs_per_slab = int(gdb_obj["num"])
        self.buffer_size = int(gdb_obj[KmemCache.buffer_size_name])

        if long(gdb_obj["flags"]) & 0x80000000:
            self.off_slab = True
            self.off_slab_cache = None
        else:
            self.off_slab = False

    def __fill_array_cache(self, acache, ac_type, nid_src, nid_tgt):
        avail = int(acache["avail"])
        limit = int(acache["limit"])

        # TODO check avail > limit
        if avail == 0:
            return

        cache_dict = {"ac_type" : ac_type, "nid_src" : nid_src,
                        "nid_tgt" : nid_tgt}

#        print(cache_dict)
        if ac_type == AC_PERCPU:
            nid_tgt = numa_node_id(nid_tgt)

        for i in range(avail):
            ptr = long(acache["entry"][i])
#            print(hex(ptr))
            if ptr in self.array_caches:
                print ("WARNING: array cache duplicity detected!")
            else:
                self.array_caches[ptr] = cache_dict
            
            page = Page.from_addr(ptr)
            obj_nid = page.get_nid()

            if obj_nid != nid_tgt:
                print ("Object {:#x} in cache {} is on wrong nid {} instead of {}".format(
                            ptr, cache_dict, obj_nid, nid_tgt))

    def __fill_alien_caches(self, node, nid_src):
        alien_cache = node["alien"]

        # TODO check that this only happens for single-node systems?
        if long(alien_cache) == 0L:
            return

        for nid in Node.for_each_nid():
            array = alien_cache[nid].dereference()

            # TODO: limit should prevent this?
            if array.address == 0:
                continue

            if self.alien_cache_type_exists:
                array = array["ac"]

            # A node cannot have alien cache on the same node, but some
            # kernels (xen) seem to have a non-null pointer there anyway
            if nid_src == nid:
                continue

            self.__fill_array_cache(array, AC_ALIEN, nid_src, nid)

    def __fill_percpu_caches(self):
        cpu_cache = self.gdb_obj[KmemCache.percpu_name]

        for cpu in for_each_online_cpu():
            if (KmemCache.percpu_cache):
                array = get_percpu_var(cpu_cache, cpu)
            else:
                array = cpu_cache[cpu].dereference()

            self.__fill_array_cache(array, AC_PERCPU, -1, cpu)

    def __fill_all_array_caches(self):
        self.array_caches = dict()

        self.__fill_percpu_caches()

        # TODO check and report collisions
        for (nid, node) in self.__get_nodelists():
            shared_cache = node["shared"]
            if long(shared_cache) != 0:
                self.__fill_array_cache(shared_cache.dereference(), AC_SHARED, nid, nid)
            
            self.__fill_alien_caches(node, nid)

    def get_array_caches(self):
        if self.array_caches is None:
            self.__fill_all_array_caches()

        return self.array_caches

    def __get_allocated_objects(self, slab_list):
        for slab in Slab.from_list(slab_list, self):
            for obj in slab.get_allocated_objects():
                yield obj

    def get_allocated_objects(self):
        for (nid, node) in self.__get_nodelists():
            for obj in self.__get_allocated_objects(node["slabs_partial"]):
                yield obj
            for obj in self.__get_allocated_objects(node["slabs_full"]):
                yield obj

    def __check_slab(self, slab, slabtype, nid, errors):
        addr = long(slab.gdb_obj.address)
        free = 0

        if slab.error == False:
            free = slab.check(slabtype, nid)

        if slab.misplaced_error is None and errors['num_misplaced'] > 0:
            if errors['num_misplaced'] > 0:
                print("{} slab objects were misplaced, printing the last:".format(errors['num_misplaced']))
                print(errors['last_misplaced'])
                errors['num_misplaced'] = 0
                errors['last_misplaced'] = None

        if slab.error == False:
            errors['num_ok'] += 1
            errors['last_ok'] = addr
            if not errors['first_ok']:
                errors['first_ok'] = addr
        else:
            if errors['num_ok'] > 0:
                print("{} slab objects were ok between {:#x} and {:#x}".
                        format(errors['num_ok'], errors['first_ok'], errors['last_ok']))
                errors['num_ok'] = 0
                errors['first_ok'] = None
                errors['last_ok'] = None

            if slab.misplaced_error is not None:
                if errors['num_misplaced'] == 0:
                    print(slab.misplaced_error)
                errors['num_misplaced'] += 1
                errors['last_misplaced'] = slab.misplaced_error

        return free

    def ___check_slabs(self, slab_list, slabtype, nid, reverse=False):
        slabs = 0
        free = 0
        check_ok = True
        
        errors = {'first_ok': None, 'last_ok': None, 'num_ok': 0,
                    'first_misplaced': None, 'last_misplaced': None, 'num_misplaced': 0}
        try:
            for slab in Slab.from_list(slab_list, self, reverse=reverse):
                free += self.__check_slab(slab, slabtype, nid, errors)
                slabs += 1 
        except Exception as e:
            print("Unrecoverable error when traversing {} slab list: {}".format(
                                                slab_list_name[slabtype], e))
            check_ok = False
        
        if errors['num_ok'] > 0:
            print("{} slab objects were ok between {:#x} and {:#x}".
                    format(errors['num_ok'], errors['first_ok'], errors['last_ok']))

        if errors['num_misplaced'] > 0:
                print("{} slab objects were misplaced, printing the last:".format(errors['num_misplaced']))
                print(errors['last_misplaced'])

        return (check_ok, slabs, free)

    def __check_slabs(self, slab_list, slabtype, nid):
        
        print("checking {} slab list {:#x}".format(slab_list_name[slabtype],
                                                long(slab_list.address)))

        errors = {'first_ok': None, 'last_ok': None, 'num_ok': 0,
                    'first_misplaced': None, 'last_misplaced': None, 'num_misplaced': 0}

        (check_ok, slabs, free) = self.___check_slabs(slab_list, slabtype, nid)

        if not check_ok:
            print("Retrying the slab list in reverse order")
            (check_ok, slabs_rev, free_rev) = self.___check_slabs(slab_list,
                                                slabtype, nid, reverse=True)
            slabs += slabs_rev
            free += free_rev
    
        #print("checked {} slabs in {} slab list".format(
#                    slabs, slab_list_name[slabtype]))

        return free

    def check_array_caches(self):
        acs = self.get_array_caches()
        for ac_ptr in acs.keys():
            ac_obj_slab = Slab.from_obj(ac_ptr)
            if not ac_obj_slab:
                print("cached pointer {:#x} in {} not found in slab".format(
                        ac_ptr, acs[ac_ptr]))
            elif ac_obj_slab.kmem_cache.name != self.name:
                print("cached pointer {:#x} in {} belongs to wrong kmem cache {}".format(
                    ac_ptr, acs[ac_ptr], ac_obj_slab.kmem_cache.name))
            else:
                ac_obj_obj = ac_obj_slab.contains_obj(ac_ptr)
                if ac_obj_obj[0] == False and ac_obj_obj[2] is None:
                    print("cached pointer {:#x} in {} is not allocated: {}".format(
                        ac_ptr, acs[ac_ptr], ac_obj_obj))
                elif ac_obj_obj[1] != ac_ptr:
                    print("cached pointer {:#x} in {} has wrong offset: {}".format(
                        ac_ptr, acs[ac_ptr], ac_obj_obj))

    def check_all(self):
        for (nid, node) in self.__get_nodelists():
            free_declared = long(node["free_objects"])
            free_counted = self.__check_slabs(node["slabs_partial"],slab_partial, nid)
            free_counted += self.__check_slabs(node["slabs_full"], slab_full, nid)
            free_counted += self.__check_slabs(node["slabs_free"], slab_free, nid)
            if free_declared != free_counted:
                print ("free objects mismatch on node %d: declared=%d counted=%d" %
                                                (nid, free_declared, free_counted))
        self.check_array_caches()

