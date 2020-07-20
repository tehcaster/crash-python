#!/usr/bin/python3
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

import crash

import gdb

from crash.util import get_minsymbol_value, get_minsymbol_pointer, \
                       get_minsymbol_addr, get_typed_pointer
from crash.util.symbols import Types, Symvals
from crash.types.module import for_each_module
from crash.cache.syscache import config_enabled

#symbols = Symbols(['kallsyms_num_syms', 'kallsyms_addresses'])
symvals = Symvals(['mod_tree'])
types = Types(['unsigned long', 'unsigned int', 'int', 'u8', 'u16', 'char *'])

class Kallsyms:

    _config_setup_done = False
    _CONFIG_KALLSYMS_BASE_RELATIVE = None
    _CONFIG_KALLSYMS_ABSOLUTE_PERCPU = None

    _stext_addr = None
    _end_addr = None
   
    module_addr_min = None
    module_addr_max = None 

    kallsyms_num_syms = None
    kallsyms_relative_base = None
    kallsyms_offsets = None
    kallsyms_names = None
    kallsyms_markers = None
    kallsyms_token_table = None
    kallsyms_token_index = None

    @classmethod
    def _config_setup(cls) -> None:
        if cls._config_setup_done:
            return

        cls._CONFIG_KALLSYMS_BASE_RELATIVE = \
            config_enabled("KALLSYMS_BASE_RELATIVE")

        cls._CONFIG_KALLSYMS_ABSOLUTE_PERCPU = \
            config_enabled("KALLSYMS_ABSOLUTE_PERCPU")
    
        cls.kallsyms_num_syms = int(get_minsymbol_value("kallsyms_num_syms", 
                                    types.unsigned_int_type))
        cls.kallsyms_names = get_minsymbol_pointer("kallsyms_names",
                                                   types.u8_type)
        cls.kallsyms_markers = get_minsymbol_pointer("kallsyms_markers",
                                                     types.unsigned_long_type)
        cls.kallsyms_token_table = get_minsymbol_pointer("kallsyms_token_table",
                                                         types.u8_type)
        cls.kallsyms_token_index = get_minsymbol_pointer("kallsyms_token_index",
                                                         types.u16_type)

        cls._stext_addr = get_minsymbol_addr("_stext")
        cls._end_addr = get_minsymbol_addr("_end")

        cls.module_addr_min = int(symvals.mod_tree["addr_min"])
        cls.module_addr_max = int(symvals.mod_tree["addr_max"])

        if cls._CONFIG_KALLSYMS_BASE_RELATIVE:
            cls.kallsyms_relative_base = int(get_minsymbol_value("kallsyms_relative_base",
                                             types.unsigned_long_type))
            cls.kallsyms_offsets = get_minsymbol_pointer("kallsyms_offsets",
                                                         types.int_type)

        cls._config_setup_done = True

    @classmethod
    def _sym_address(cls, idx: int) -> int:
        if not cls._CONFIG_KALLSYMS_BASE_RELATIVE:
            raise NotImplementedError("kallsyms support for !CONFIG_KALLSYMS_BASE_RELATIVE")

        if not cls._CONFIG_KALLSYMS_ABSOLUTE_PERCPU:             
            raise NotImplementedError("kallsyms support for !CONFIG_KALLSYMS_ABSOLUTE_PERCPU")

        offset = int(cls.kallsyms_offsets[idx])
        #print(f"idx {idx} kallsyms_offsets {int(cls.kallsyms_offsets):x}")
        
        if offset >= 0:
            #print("offset is positive")
            return offset

        ret = cls.kallsyms_relative_base - 1 - offset
        #print(f"offset {offset} is negative, base {cls.kallsyms_relative_base:x} addr {ret:x}")
    
        return ret

    @classmethod
    def _get_symbol_pos(cls, addr: int) -> (int, int, int):
        low = 0
        high = cls.kallsyms_num_syms

        while high - low > 1:
            mid = low + (high - low) // 2
            if cls._sym_address(mid) <= addr:
                low = mid
            else:
                high = mid

        while low and cls._sym_address(low-1) == cls._sym_address(low):
            low -= 1

        symbol_start = cls._sym_address(low)
        symbol_end = None
    
        for i in range(low + 1, cls.kallsyms_num_syms):
            if cls._sym_address(i) > symbol_start:
                symbol_end = cls._sym_address(i)
                break

        if symbol_end is None:
            print("kallsyms symbol_end failed, faking it")
            symbol_end = addr

        return (low, addr - symbol_start, symbol_end - symbol_start)

    @classmethod
    def _get_symbol_offset(cls, pos: int) -> int:
        marker = int(cls.kallsyms_markers[pos >> 8])

        name = cls.kallsyms_names + marker

        for i in range(pos & 0xFF):
            name = name + int(name.dereference()) + 1

        return int(name - cls.kallsyms_names)
    
    @classmethod
    def _expand_symbol(cls, off: int) -> str:
        out = ""
        skipped_first = False

        data = cls.kallsyms_names + off
        length = int(data.dereference())
        data += 1

        for i in range(length):
            idx1 = int(data[i])
            idx2 = int(cls.kallsyms_token_index[idx1])
            tptr = cls.kallsyms_token_table + idx2

            while int(tptr.dereference()) != 0:
                if skipped_first:
                    char = int(tptr.dereference())
                    out += chr(char)
                else:
                    skipped_first = True
                tptr += 1

        return out

    @classmethod
    def _symname(cls, kallsyms, symnum):
        offset = int(kallsyms["symtab"][symnum]["st_name"])
        string_addr = int(kallsyms["strtab"]) + offset
        string = get_typed_pointer(string_addr, types.char_p_type)
        return string.string()

    @classmethod
    def get_ksymbol(cls, mod: gdb.Value, addr: int, nextval: int, modname: str):
        kallsyms = mod["kallsyms"]
        best = 0

        for i in range(1, int(kallsyms["num_symtab"])):
            # XXX SHN_UNDEF is defined as 0
            if kallsyms["symtab"][i]["st_shndx"] == 0:
                continue
            name = cls._symname(kallsyms, i)
            if name == "":
                continue
            # XXX something with is_arm_mapping_symbol
            
            st_value = int(kallsyms["symtab"][i]["st_value"])
            best_st_value = int(kallsyms["symtab"][best]["st_value"])

            if st_value <= addr and st_value > best_st_value:
                best = i
            
            if st_value > addr and st_value < nextval:
                nextval = st_value

        if best == 0:
            return f"unknown symbol [{modname}]"

        name = cls._symname(kallsyms, best)
        st_value = int(kallsyms["symtab"][best]["st_value"])
        size = nextval - st_value
        offset = addr - st_value

        return f"{name}+0x{offset:x}/0x{size:x} (+{offset}/{size}) [{modname}]"

    @classmethod
    def module_address_lookup(cls, addr: int):
        # XXX simpler than implementing the tree find
        for mod in for_each_module():

            init_base = int(mod["init_layout"]["base"])
            init_size = int(mod["init_layout"]["size"])
            if addr >= init_base and addr < init_base + init_size:
                name = mod["name"].string()
                return cls.get_ksymbol(mod, addr, init_base + init_size, f"{name}(init)")

            core_base = int(mod["core_layout"]["base"])
            core_size = int(mod["core_layout"]["size"])
            if addr >= core_base and addr < core_base + core_size:
                name = mod["name"].string()
                return cls.get_ksymbol(mod, addr, core_base + core_size, name)

        return None

def kallsyms_lookup(addr: int) -> str:
    Kallsyms._config_setup()

    if addr >= Kallsyms._stext_addr and addr <= Kallsyms._end_addr:

        (pos, offset, size) = Kallsyms._get_symbol_pos(addr)

        sym = Kallsyms._expand_symbol(Kallsyms._get_symbol_offset(pos))

        return f"{sym}+0x{offset:x}/0x{size:x} (+{offset}/{size})"

    if addr >= Kallsyms.module_addr_min and addr <= Kallsyms.module_addr_max:

        mod_ksymbol = Kallsyms.module_address_lookup(addr)

        if mod_ksymbol:
            return mod_ksymbol

        return "unknown module symbol"    

    return "unknown symbol"
