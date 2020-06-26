#!/usr/bin/python3
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

import crash

import gdb

from crash.util import get_minsymbol_value, get_minsymbol_pointer
from crash.util.symbols import Types
from crash.cache.syscache import config_enabled

#symbols = Symbols(['kallsyms_num_syms', 'kallsyms_addresses'])
types = Types(['unsigned long', 'unsigned int', 'int', 'u8', 'u16'])

class Kallsyms:

    _config_setup_done = False
    _CONFIG_KALLSYMS_BASE_RELATIVE = None
    _CONFIG_KALLSYMS_ABSOLUTE_PERCPU = None

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
                                                     types.unsigned_int_type) 
        cls.kallsyms_token_table = get_minsymbol_pointer("kallsyms_token_table",
                                                         types.u8_type)
        cls.kallsyms_token_index = get_minsymbol_pointer("kallsyms_token_index",
                                                         types.u16_type)

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
        
        if offset >= 0:
            return offset
    
        return cls.kallsyms_relative_base - 1 - offset

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

def kallsyms_lookup(addr: int) -> str:
    Kallsyms._config_setup()

    (pos, offset, size) = Kallsyms._get_symbol_pos(addr)

    sym = Kallsyms._expand_symbol(Kallsyms._get_symbol_offset(pos))

    return f"{sym}+0x{offset:x}/0x{size:x} (+{offset}/{size})"
