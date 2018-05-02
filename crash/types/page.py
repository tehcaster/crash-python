#!/usr/bin/env python
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

import gdb
import types
from crash.infra import CrashBaseClass, export
from crash.util import container_of, find_member_variant

# TODO: un-hardcode this
VMEMMAP_START   = 0xffffea0000000000
DIRECTMAP_START = 0xffff880000000000
PAGE_SIZE       = 4096L
NODES_SHIFT     = 10

#TODO debuginfo won't tell us, depends on version?
PAGE_MAPPING_ANON = 1

class Page(CrashBaseClass):
    __types__ = [ 'struct page', 'enum pageflags' ]
    __type_callbacks__ = [ ('struct page', 'setup_page_type' ),
                           ('enum pageflags', 'setup_pageflags' ) ]

    slab_cache_name = None
    slab_page_name = None
    compound_head_name = None
    vmemmap = None
    pageflags = dict()

    PG_tail = None
    PG_slab = None

    setup_page_type_done = False
    setup_pageflags_done = False
    setup_pageflags_finish_done = False

    @classmethod
    def setup_page_type(cls, gdbtype):
        cls.slab_cache_name = find_member_variant(gdbtype, ('slab_cache', 'lru'))
        cls.slab_page_name = find_member_variant(gdbtype, ('slab_page', 'lru'))
        cls.compound_head_name = find_member_variant(gdbtype, ('compound_head', 'first_page' ))
        cls.vmemmap = gdb.Value(VMEMMAP_START).cast(gdbtype.pointer())

        cls.setup_page_type_done = True
        if cls.setup_pageflags_done and not cls.setup_pageflags_finish_done:
            cls.setup_pageflags_finish()

    @classmethod
    def setup_pageflags(cls, gdbtype):
        for field in gdbtype.fields():
            cls.pageflags[field.name] = field.enumval

        cls.setup_pageflags_done = True
        if cls.setup_page_type_done and not cls.setup_pageflags_finish_done:
            cls.setup_pageflags_finish()

        cls.PG_slab = 1L << cls.pageflags['PG_slab']

    @classmethod
    def setup_pageflags_finish(cls):
        cls.setup_pageflags_finish_done = True
        if 'PG_tail' in cls.pageflags.keys():
            cls.PG_tail = 1L << cls.pageflags['PG_tail']
            cls.is_tail = cls.__is_tail_flag

        if cls.compound_head_name == 'first_page':
            cls.__compound_head = cls.__compound_head_first_page
            if cls.PG_tail is None:
                cls.PG_tail = 1L << cls.pageflags['PG_compound'] | 1L << cls.pageflags['PG_reclaim']
                cls.is_tail = cls.__is_tail_flagcombo

    @classmethod
    def from_pfn(cls, pfn):
        return Page(cls.vmemmap[pfn], pfn)

    @staticmethod
    def from_addr(addr):
        return Page.from_pfn((addr - DIRECTMAP_START) / PAGE_SIZE)

    @staticmethod
    def from_page_addr(addr):
        page_ptr = gdb.Value(addr).cast(Page.page_type.pointer())
        pfn = (addr - VMEMMAP_START) / Page.page_type.sizeof
        return Page(page_ptr.dereference(), pfn)

    @staticmethod
    def from_obj(gdb_obj):
        pfn = (long(gdb_obj.address) - VMEMMAP_START) / Page.page_type.sizeof
        return Page(gdb_obj, pfn)

    @staticmethod
    def for_each():
        # TODO works only on x86?
        max_pfn = long(gdb.lookup_global_symbol("max_pfn").value())
        for pfn in range(max_pfn):
            try:
                yield Page.from_pfn(pfn)
            except gdb.error, e:
                # TODO: distinguish pfn_valid() and report failures for those?
                pass

    def __is_tail_flagcombo(self):
        return bool((self.flags & self.PG_tail) == self.PG_tail)

    def __is_tail_flag(self):
        return bool(self.flags & self.PG_tail)

    def is_tail(self):
        return bool(self.gdb_obj['compound_head'] & 1)

    def is_slab(self):
        return bool(self.flags & self.PG_slab)

    def is_anon(self):
        mapping = long(self.gdb_obj["mapping"])
        return (mapping & PAGE_MAPPING_ANON) != 0

    def get_slab_cache(self):
        if Page.slab_cache_name == "lru":
            return self.gdb_obj["lru"]["next"]
        return self.gdb_obj[Page.slab_cache_name]

    def get_slab_page(self):
        if Page.slab_page_name == "lru":
            return self.gdb_obj["lru"]["prev"]
        return self.gdb_obj[Page.slab_page_name]

    def get_nid(self):
        # TODO unhardcode
        return self.flags >> (64 - NODES_SHIFT)

    def __compound_head_first_page(self):
        return long(self.gdb_obj['first_page'])

    def __compound_head(self):
        return long(self.gdb_obj['compound_head']) - 1

    def compound_head(self):
        if not self.is_tail():
            return self

        return Page.from_page_addr(self.__compound_head())
        
    def __init__(self, obj, pfn):
        self.gdb_obj = obj
        self.pfn = pfn
        self.flags = long(obj["flags"])
