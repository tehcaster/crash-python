#!/usr/bin/python3
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

from typing import Dict, Union, TypeVar, Iterable, Callable, Tuple,\
                   Optional

from math import log, ceil

import crash
from crash.util import find_member_variant, get_typed_pointer
from crash.util.symbols import Types, Symvals, TypeCallbacks
from crash.util.symbols import SymbolCallbacks, MinimalSymbolCallbacks
from crash.cache.syscache import config
from crash.exceptions import DelayedAttributeError
from crash.types.stack_depot import StackTrace

import gdb

#TODO debuginfo won't tell us, depends on version?
PAGE_MAPPING_ANON = 1

types = Types(['unsigned long', 'struct page', 'enum pageflags',
               'enum zone_type', 'struct mem_section', 'enum page_ext_flags',
               'struct page_owner'])
symvals = Symvals(['mem_section', 'max_pfn', 'page_ext_size', 'page_owner_ops'])

PageType = TypeVar('PageType', bound='Page')

_PAGE_FLAGS_CHECK_AT_FREE = \
    ["PG_lru", "PG_locked", "PG_private", "PG_private_2", "PG_writeback",
     "PG_reserved", "PG_slab", "PG_active", "PG_unevictable", "PG_mlocked"]

gfpflag_names = list()
pageflag_names = list()

class Page:
    slab_cache_name = None
    slab_page_name = None
    compound_head_name = None
    vmemmap_base = 0xffffea0000000000
    vmemmap: gdb.Value
    directmap_base = 0xffff880000000000
    pageflags: Dict[str, int] = dict()
    page_ext_flags: Dict[str, int] = dict()

    PG_tail = -1
    PG_slab = -1
    PG_lru = -1
    PG_head = -1

    PAGE_FLAGS_CHECK_AT_FREE = 0
    PAGE_FLAGS_CHECK_AT_PREP = 0

    setup_page_type_done = False
    setup_pageflags_done = False
    setup_pageflags_finish_done = False

    ZONES_WIDTH = -1
    NODES_WIDTH = -1
    # TODO have arch provide this?
    BITS_PER_LONG = -1

    PAGE_SIZE = 4096
    PAGE_SHIFT = 12

    # TODO these are from x86 SLES kernels
    sparsemem = True
    sparsemem_vmemmap = True
    sparsemem_extreme = True
    SECTION_SIZE_BITS = 27 # Depends on sparsemem=True
    SECTIONS_PER_ROOT = -1 # Depends on SPARSEMEM_EXTREME

    _is_tail: Callable[['Page'], bool]
    _compound_head: Callable[['Page'], int]

    @classmethod
    def setup_page_type(cls, gdbtype: gdb.Type) -> None:
        # TODO: should check config, but that failed to work on ppc64, hardcode
        # 64k for now
        if crash.current_target().arch.name() == "powerpc:common64":
            cls.PAGE_SHIFT = 16
            # also a config
            cls.directmap_base = 0xc000000000000000

            cls.sparsemem = True
            cls.sparsemem_vmemmap = False
            cls.sparsemem_extreme = False
            cls.SECTION_SIZE_BITS = 24

        cls.PAGE_SIZE = 1 << cls.PAGE_SHIFT

        cls.slab_cache_name = find_member_variant(gdbtype, ['slab_cache', 'lru'])
        cls.slab_page_name = find_member_variant(gdbtype, ['slab_page', 'lru'])
        cls.compound_head_name = find_member_variant(gdbtype, ['compound_head', 'first_page'])
        if not hasattr(cls, 'vmemmap'):
            cls.vmemmap = gdb.Value(cls.vmemmap_base).cast(gdbtype.pointer())

        cls.setup_page_type_done = True
        if cls.setup_pageflags_done and not cls.setup_pageflags_finish_done:
            cls.setup_pageflags_finish()

    @classmethod
    def setup_mem_section(cls, gdbtype: gdb.Type) -> None:
        if cls.sparsemem_extreme:
            cls.SECTIONS_PER_ROOT = cls.PAGE_SIZE // gdbtype.sizeof
        else:
            cls.SECTIONS_PER_ROOT = 1

    @classmethod
    def pfn_to_section(cls, pfn: int) -> gdb.Value:
        section_nr = pfn >> (cls.SECTION_SIZE_BITS - cls.PAGE_SHIFT)
        root_idx = section_nr // cls.SECTIONS_PER_ROOT
        offset = section_nr & (cls.SECTIONS_PER_ROOT - 1)
        section = symvals.mem_section[root_idx][offset]
       
        return section 

    @classmethod
    def pfn_to_page(cls, pfn: int) -> gdb.Value:
        if not cls.sparsemem_vmemmap:
            section = cls.pfn_to_section(pfn)            

            pagemap = section["section_mem_map"] & ~3
            return (pagemap.cast(types.page_type.pointer()) + pfn).dereference()

        # pylint doesn't have the visibility it needs to evaluate this
        # pylint: disable=unsubscriptable-object
        return cls.vmemmap[pfn]

    @classmethod
    def setup_page_ext_flags(cls, gdbtype: gdb.Type) -> None:
        for field in gdbtype.fields():
            cls.page_ext_flags[field.name] = field.enumval

    @classmethod
    def setup_pageflags(cls, gdbtype: gdb.Type) -> None:
        for field in gdbtype.fields():
            cls.pageflags[field.name] = field.enumval
    
        cls.setup_pageflags_done = True
        if cls.setup_page_type_done and not cls.setup_pageflags_finish_done:
            cls.setup_pageflags_finish()

        cls.PG_slab = 1 << cls.pageflags['PG_slab']
        cls.PG_lru = 1 << cls.pageflags['PG_lru']
        cls.PG_head = 1 << cls.pageflags['PG_head']

        flags_check = 0
        for flagname in _PAGE_FLAGS_CHECK_AT_FREE:
            flags_check |= 1 << cls.pageflags[flagname]

        cls.PAGE_FLAGS_CHECK_AT_FREE = flags_check
        NR_PAGEFLAGS = cls.pageflags["__NR_PAGEFLAGS"]
        cls.PAGE_FLAGS_CHECK_AT_PREP = (1 << NR_PAGEFLAGS) - 1

    @classmethod
    def setup_vmemmap_base(cls, symbol: gdb.Symbol) -> None:
        cls.vmemmap_base = int(symbol.value())
        # setup_page_type() was first and used the hardcoded initial value,
        # we have to update
        cls.vmemmap = gdb.Value(cls.vmemmap_base).cast(types.page_type.pointer())

    @classmethod
    def setup_directmap_base(cls, symbol: gdb.Symbol) -> None:
        cls.directmap_base = int(symbol.value())

    @classmethod
    def setup_zone_type(cls, gdbtype: gdb.Type) -> None:
        max_nr_zones = gdbtype['__MAX_NR_ZONES'].enumval
        cls.ZONES_WIDTH = int(ceil(log(max_nr_zones, 2)))

    @classmethod
    # pylint: disable=unused-argument
    def setup_nodes_width(cls, symbol: Union[gdb.Symbol, gdb.MinSymbol]) -> None:
        """
        Detect NODES_WITH from the in-kernel config table

        Args:
            symbol: The ``kernel_config_data`` symbol or minimal symbol.
                It is not used directly.  It is used to determine whether
                the config data should be available.
        """
        # TODO: handle kernels with no space for nodes in page flags
        try:
            cls.NODES_WIDTH = int(config['NODES_SHIFT'])
        except (KeyError, DelayedAttributeError):
            # XXX
            print("Unable to determine NODES_SHIFT from config, trying 8")
            cls.NODES_WIDTH = 8
        # piggyback on this callback because type callback doesn't seem to work
        # for unsigned long
        cls.BITS_PER_LONG = types.unsigned_long_type.sizeof * 8

    @classmethod
    def setup_pageflags_finish(cls) -> None:
        cls.setup_pageflags_finish_done = True
        cls._is_tail = cls.__is_tail_compound_head_bit
        cls._compound_head = cls.__compound_head_uses_low_bit

        if 'PG_tail' in cls.pageflags.keys():
            cls.PG_tail = 1 << cls.pageflags['PG_tail']
            cls._is_tail = cls.__is_tail_flag

        if cls.compound_head_name == 'first_page':
            cls._compound_head = cls.__compound_head_first_page
            if cls.PG_tail == -1:
                cls.PG_tail = 1 << cls.pageflags['PG_compound'] | 1 << cls.pageflags['PG_reclaim']
                cls._is_tail = cls.__is_tail_flagcombo

    @classmethod
    def from_obj(cls, page: gdb.Value) -> 'Page':
        pfn = (int(page.address) - Page.vmemmap_base) // types.page_type.sizeof
        max_pfn = int(symvals.max_pfn)
        if pfn < 0 or pfn > max_pfn:
            return None
        return Page(page, pfn)

    @classmethod
    def from_page_addr(cls, addr: int) -> 'Page':
        page_ptr = gdb.Value(addr).cast(types.page_type.pointer())
        return cls.from_obj(page_ptr.dereference())

    def __init__(self, obj: gdb.Value, pfn: int) -> None:
        self.gdb_obj = obj
        self.address = int(obj.address)
        self.pfn = pfn
        self.flags = int(obj["flags"])

    def __is_tail_flagcombo(self) -> bool:
        return bool((self.flags & self.PG_tail) == self.PG_tail)

    def __is_tail_flag(self) -> bool:
        return bool(self.flags & self.PG_tail)

    def __is_tail_compound_head_bit(self) -> bool:
        return bool(self.gdb_obj['compound_head'] & 1)

    def is_tail(self) -> bool:
        return self._is_tail()

    def is_slab(self) -> bool:
        return bool(self.flags & self.PG_slab)

    def is_lru(self) -> bool:
        return bool(self.flags & self.PG_lru)

    def is_head(self) -> bool:
        return bool(self.flags & self.PG_head)

    def is_anon(self) -> bool:
        mapping = int(self.gdb_obj["mapping"])
        return (mapping & PAGE_MAPPING_ANON) != 0

    def is_buddy(self) -> bool:
        page_type = int(self.gdb_obj["page_type"])
        
        base = 0xf0000000
        PG_buddy = 0x00000080
        return (page_type & (base | PG_buddy)) == base

    def get_slab_cache(self) -> gdb.Value:
        if Page.slab_cache_name == "lru":
            return self.gdb_obj["lru"]["next"]
        return self.gdb_obj[Page.slab_cache_name]

    def get_slab_page(self) -> gdb.Value:
        if Page.slab_page_name == "lru":
            return self.gdb_obj["lru"]["prev"]
        return self.gdb_obj[Page.slab_page_name]

    def get_nid(self) -> int:
        # TODO: this only works when there are no sections (i.e. sparsemem_vmemmap)
        return self.flags >> (self.BITS_PER_LONG - self.NODES_WIDTH)

    def get_zid(self) -> int:
        shift = self.BITS_PER_LONG - self.NODES_WIDTH - self.ZONES_WIDTH
        zid = self.flags >> shift & ((1 << self.ZONES_WIDTH) - 1)
        return zid

    def get_count(self) -> int:
        head = self.compound_head()
        return int(head.gdb_obj["_refcount"]["counter"])

    def __compound_head_first_page(self) -> int:
        return int(self.gdb_obj['first_page'])

    def __compound_head_uses_low_bit(self) -> int:
        return int(self.gdb_obj['compound_head']) - 1

    def __compound_head(self) -> int:
        return self._compound_head()

    def compound_head(self) -> 'Page':
        if not self.is_tail():
            return self

        return self.__class__.from_page_addr(self.__compound_head())

    def compound_order(self) -> int:
        head = self.compound_head()
        first_tail = Page.pfn_to_page(head.pfn + 1)
        return int(first_tail["compound_order"])
		
    def page_count(self) -> int:
        head = self.compound_head()
        return int(head.gdb_obj["_refcount"]["counter"])

    def page_mapcount(self) -> int:
        return int(self.gdb_obj["_mapcount"]["counter"])

    def dump_page_owner(self) -> None:
        section = Page.pfn_to_section(self.pfn)
        base = section["page_ext"]
        page_ext_size = int(symvals.page_ext_size)
        page_ext_addr = int(base) + self.pfn * page_ext_size

        page_ext = get_typed_pointer(page_ext_addr, base.type)

        ext_flags = int(page_ext["flags"])
        has_page_owner = ext_flags & 1 << self.page_ext_flags["PAGE_EXT_OWNER"] != 0
        page_owner_alloc = ext_flags & 1 << self.page_ext_flags["PAGE_EXT_OWNER_ALLOCATED"] != 0

        print(f"page_owner={has_page_owner} page_owner_allocated={page_owner_alloc}")

        page_owner_offset = int(symvals.page_owner_ops["offset"])
        page_owner = get_typed_pointer(page_ext_addr + page_owner_offset, types.page_owner_type)

        print(page_owner.dereference())
        order = int(page_owner["order"])
        migreason = int(page_owner["last_migrate_reason"])
        flags_str = gfpflags_to_str(int(page_owner["gfp_mask"]))
        print(f"order={order}, gfp_mask={flags_str}, mig={migreason}")

        alloc_stack = StackTrace.from_handle(page_owner["handle"])
        print("Allocation stack:")
        alloc_stack.dump()

    def dump(self) -> None:
        print("dumping page:")
        self.dump_page_owner()
        
		

type_cbs = TypeCallbacks([('struct page', Page.setup_page_type),
                          ('enum pageflags', Page.setup_pageflags),
                          ('enum page_ext_flags', Page.setup_page_ext_flags),
                          ('enum zone_type', Page.setup_zone_type),
                          ('struct mem_section', Page.setup_mem_section)])
msymbol_cbs = MinimalSymbolCallbacks([('kernel_config_data',
                                       Page.setup_nodes_width)])

def _setup_flag_names(symbol: gdb.Symbol) -> None:
    global gfpflag_names, pageflag_names

    flag_names = list()
    array = symbol.value()
    i = 0
    val = array[0]
    while val["mask"] != 0 and val["name"] != 0:
        flag_names.append((int(val["mask"]), str(val["name"].string())))
        i += 1
        val = array[i]
    if symbol.name == "gfpflag_names":
        gfpflag_names = flag_names
    elif symbol.name == "pageflag_names":
        pageflag_names = flag_names
    else:
        raise RuntimeException("unknown symbol passed")
    
def flags_to_str(flags: int, flagnames: list) -> str:
    out = ""
    for (val, name) in flagnames:
        if flags & val != val:
            continue
        if out == "":
            out = name
        else:
            out += "|" + name

        flags &= ~val

    return out

def gfpflags_to_str(flags: int) -> str:
    return flags_to_str(flags, gfpflag_names)

def pageflags_to_str(flags: int) -> str:
    NR_PAGEFLAGS = Page.pageflags["__NR_PAGEFLAGS"]
    flags &= (1 << NR_PAGEFLAGS) - 1
    return flags_to_str(flags, pageflag_names)

# TODO: this should better be generalized to some callback for
# "config is available" without refering to the symbol name here
symbol_cbs = SymbolCallbacks([('vmemmap_base', Page.setup_vmemmap_base),
                              ('page_offset_base',
                               Page.setup_directmap_base),
                              ('gfpflag_names', _setup_flag_names),
                              ('pageflag_names', _setup_flag_names)])

def page_addr(struct_page_addr: int) -> int:
    pfn = (struct_page_addr - Page.vmemmap_base) // types.page_type.sizeof
    return Page.directmap_base + (pfn * Page.PAGE_SIZE)

def pfn_to_page(pfn: int) -> 'Page':
    return Page(Page.pfn_to_page(pfn), pfn)

def page_from_addr(addr: int) -> 'Page':
    pfn = (addr - Page.directmap_base) // Page.PAGE_SIZE
    return pfn_to_page(pfn)

def safe_page_from_page_addr(addr: int) -> Optional[Page]:
    if addr < Page.vmemmap_base:
        return None
    pfn = (addr - Page.vmemmap_base) // types.page_type.sizeof
    if pfn > int(symvals.max_pfn):
        return None
    return pfn_to_page(pfn)

def page_from_gdb_obj(gdb_obj: gdb.Value) -> 'Page':
    pfn = (int(gdb_obj.address) - Page.vmemmap_base) // types.page_type.sizeof
    return Page(gdb_obj, pfn)

def for_each_struct_page_pfn() -> Iterable[Tuple[gdb.Value, int]]:
    # TODO works only on x86?
    max_pfn = int(symvals.max_pfn)
    for pfn in range(max_pfn):
        try:
            yield (Page.pfn_to_page(pfn), pfn)
        except gdb.error:
            # TODO: distinguish pfn_valid() and report failures for those?
            pass

def for_each_page() -> Iterable[Page]:
    # TODO works only on x86?
    max_pfn = int(symvals.max_pfn)
    for pfn in range(max_pfn):
        try:
            yield pfn_to_page(pfn)
        except gdb.error:
            # TODO: distinguish pfn_valid() and report failures for those?
            pass

# Optimized to filter flags on gdb.Value before instantiating Page
def for_each_page_flag(flag: int) -> Iterable[Page]:
    for (struct_page, pfn) in for_each_struct_page_pfn():
        try:
            if struct_page["flags"] & flag == 0:
                continue
            yield Page(struct_page, pfn)
        except gdb.error:
            pass
