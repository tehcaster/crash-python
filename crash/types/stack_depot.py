#!/usr/bin/python3
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

import crash
from crash.util.symbols import Types, Symvals

import gdb

types = Types(['union handle_parts', 'struct stack_record'])

symvals = Symvals(['stack_slabs'])

# TODO not sure how to determine from dump
STACK_ALLOC_ALIGN = 4

class StackTrace:

    def __init__(self, nr_entries: int, entries: gdb.Value) -> None:
        self.nr_entries = nr_entries
        self.entries = entries

    def dump(self):
        for i in range(self.nr_entries):
            addr = int(self.entries[i])
            print(hex(addr))

    @classmethod
    def from_handle(cls, handle: gdb.Value) -> 'StackTrace':
        
        parts = handle.address.cast(types.union_handle_parts_type.pointer())
        print(parts.dereference())

        slab = symvals.stack_slabs[parts["slabindex"]]
        offset = parts["offset"] << STACK_ALLOC_ALIGN
        record = slab + offset
        record = record.cast(types.stack_record_type.pointer())

        return StackTrace(int(record["size"]), record["entries"]) 
