#!/usr/bin/python3
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

from typing import List

from crash.util import array_size, array_for_each
from crash.util.symbols import Types
from crash.types.percpu import get_percpu_var
from crash.types.vmstat import VmStat
from crash.types.cpu import for_each_online_cpu
from crash.types.list import list_for_each_entry, CorruptListError
import crash.types.page
from crash.types.page import pageflags_to_str

import gdb

class Zone:

    types = Types(['struct page'])

    def __init__(self, obj: gdb.Value, zid: int) -> None:
        self.gdb_obj = obj
        self.zid = zid
        self.nid = int(obj["node"])

    def is_populated(self) -> bool:
        return self.gdb_obj["present_pages"] != 0

    def get_vmstat(self) -> List[int]:
        stats = [0] * VmStat.nr_stat_items
        vm_stat = self.gdb_obj["vm_stat"]

        for item in range(0, VmStat.nr_stat_items):
            # TODO abstract atomic?
            stats[item] = int(vm_stat[item]["counter"])
        return stats

    def add_vmstat_diffs(self, diffs: List[int]) -> None:
        for cpu in for_each_online_cpu():
            pageset = get_percpu_var(self.gdb_obj["pageset"], cpu)
            vmdiff = pageset["vm_stat_diff"]
            for item in range(0, VmStat.nr_stat_items):
                diffs[item] += int(vmdiff[item])

    def get_vmstat_diffs(self) -> List[int]:
        diffs = [0] * VmStat.nr_stat_items
        self.add_vmstat_diffs(diffs)
        return diffs

    # mimic check_new_page_bad(), but not completely, we have not yet
    # grabbed the page from freelist, so instead of -1 mapcount we want
    # PageBuddy, and buddy page order match the freelist's
    def _check_freelist_page(self, page, expected_order):
        errors = ""

        page_count = page.page_count()
        if page_count != 0:
            errors += f"page_count={page_count} "

        if not page.is_buddy():
            mapcount = page.page_mapcount()
            errors += f"not PageBuddy (raw mapcount={mapcount}) "

        page_order = int(page.gdb_obj["private"])
        if page_order != expected_order:
            errors += f"buddy_order={page_order} "

        mapping = int(page.gdb_obj["mapping"])
        if mapping != 0:
            errors += f"mapping=0x{mapping:x} "

        flags = int(page.gdb_obj["flags"])
        if flags & page.PAGE_FLAGS_CHECK_AT_PREP != 0:
            bad_flags = pageflags_to_str(flags & page.PAGE_FLAGS_CHECK_AT_PREP) 
            errors += f"flags {bad_flags} "

        memcg = int(page.gdb_obj["mem_cgroup"])
        if memcg != 0:
            errors += f"memcg=0x{memcg:x} "

        return errors

    # mimic free_pages_check_bad()
    def _check_pcplist_page(self, page):
        errors = ""

        page_count = page.page_count()
        if page_count != 0:
            errors += f"page_count={page_count} "

        mapcount = page.page_mapcount()
        if mapcount != -1:
            errors += f"raw_page_mapcount={mapcount} "

        mapping = int(page.gdb_obj["mapping"])
        if mapping != 0:
            errors += f"mapping=0x{mapping:x} "

        if page.is_buddy():
            errors += f"PageBuddy()=true "

        flags = int(page.gdb_obj["flags"])
        if flags & page.PAGE_FLAGS_CHECK_AT_FREE != 0:
            bad_flags = pageflags_to_str(flags & page.PAGE_FLAGS_CHECK_AT_FREE)
            errors += f"flags {bad_flags} "

        memcg = int(page.gdb_obj["mem_cgroup"])
        if memcg != 0:
            errors += f"memcg=0x{memcg:x} "

        return errors

    def _check_free_area(self, area: gdb.Value, is_pcp: bool, order_cpu: int) -> None:
        nr_free = 0
        if is_pcp:
            list_array_name = "lists"
            error_desc = "pcplist"
            order_cpu_desc = f"cpu {order_cpu}"
        else:
            list_array_name = "free_list"
            error_desc = "free area"
            order_cpu_desc = f"order {order_cpu}"
        for mt in range(array_size(area[list_array_name])):
            free_list = area[list_array_name][mt]
            for reverse in [False, True]:
                if reverse:
                    print("Retrying list in reverse direction")
                try:
                    for page_obj in list_for_each_entry(free_list,
                                                        self.types.page_type,
                                                        "lru",
                                                        reverse=reverse):
                        page = crash.types.page.Page.from_obj(page_obj)
                        if not page:
                            print(f"page 0x{int(page_obj.address):x} is not a valid page pointer on "
                                  f"{error_desc} of node {self.nid} zone {self.zid}, {order_cpu_desc} mt {mt}")
                            continue
                        
                        nr_free += 1

                        if is_pcp:
                            errors = self._check_pcplist_page(page)
                        else:
                            errors = self._check_freelist_page(page, order_cpu)
                        
                        if errors != "":
                            print(f"page 0x{int(page_obj.address):x} pfn {page.pfn} on {error_desc} of node "
                                  f"{self.nid} zone {self.zid}, {order_cpu_desc} mt {mt} had unexpected state: {errors}")
                        if page.get_nid() != self.nid or page.get_zid() != self.zid:
                            print(f"page 0x{int(page_obj.address):x} pfn {page.pfn} misplaced on "
                                  f"{error_desc} of node {self.nid} zone {self.zid}, {order_cpu_desc} mt {mt} "
                                  f"has flags for node {page.get_nid()} zone {page.get_zid()}")
                except CorruptListError as e:
                    print(f"Error traversing {error_desc} 0x{int(area.address):x} for {order_cpu_desc} mt {mt}: {e}")
                    continue
                except BufferError as e:
                    print(f"Error traversing {error_desc} 0x{int(area.address):x} for {order_cpu_desc} mt {mt}: {e}")
                    continue
                break
        nr_expected = area["count"] if is_pcp else area["nr_free"]
        if nr_free != nr_expected:
            print(f"nr_free mismatch in {error_desc} 0x{int(area.address):x} for {order_cpu_desc}: "
                  f"expected {nr_expected}, counted {nr_free}")

    def check_free_pages(self) -> None:
        for order in range(array_size(self.gdb_obj["free_area"])):
            area = self.gdb_obj["free_area"][order]
            self._check_free_area(area, False, order)
        for cpu in for_each_online_cpu():
            pageset = get_percpu_var(self.gdb_obj["pageset"], cpu)
            self._check_free_area(pageset["pcp"], True, cpu)
