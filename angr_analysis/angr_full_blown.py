import logging
from os import major
from pathlib import Path

from angr.exploration_techniques.director import ExecuteAddressGoal
logging.getLogger("angr").setLevel(logging.CRITICAL)

import angr
import kernel_types
import archinfo
import claripy
import sys
import collections
import IPython
from threading import Event, Timer
import ipdb
import time
import argparse

from importlib import reload  # To avoid root logger being set by the environment
reload(logging)

MMMAPIOSPACE = False
ZWOPENPROCESS = False
ZWMAPVIEWOFSECTION = False
mem_string = ""
handler = None


def check_imports(proj):
    global MMMAPIOSPACE
    global ZWOPENPROCESS
    global ZWMAPVIEWOFSECTION

    print("\nLooking for MmMapIoSpace, ZwOpenProcess, ZwMapViewOfSection Imports..\n")
    #logging.debug("Looking for MmMapIoSpace, ZwOpenProcess, ZwMapViewOfSection Imports..\n")

    mmmap_addr = proj.loader.find_symbol("MmMapIoSpace")
    zwopenprocess = proj.loader.find_symbol("ZwOpenProcess")
    zwmapview = proj.loader.find_symbol("ZwMapViewOfSection")
    import_addr = {}

    if zwopenprocess:
        print("[+] Found ZwOpenProcess: ", hex(zwopenprocess.rebased_addr))
        #logging.info("[+] Found ZwOpenProcess: %s", hex(zwopenprocess.rebased_addr))

        ZWOPENPROCESS = True
        import_addr['ZwOpenProcess'] = zwopenprocess.rebased_addr

    else:
        print("ZwOpenProcess import not found!\n")
        #logging.info("ZwOpenProcess import not found!\n")

    if mmmap_addr:
        print("[+] Found MmapIoSpace: ", hex(mmmap_addr.rebased_addr))
        MMMAPIOSPACE = True
        import_addr['MmapIoSpace'] = mmmap_addr.rebased_addr
        #logging.info("[+] Found MmapIoSpace: %s", hex(mmmap_addr.rebased_addr))

    else:
        print("MmMapIoSpace import not found!\n")
        #logging.info("MmMapIoSpace import not found!\n")

    if zwmapview:

        print("[+] Found ZwMapViewOfSection: ", hex(zwmapview.rebased_addr))
        ZWMAPVIEWOFSECTION = True
        import_addr['ZwMapViewOfSection'] = zwmapview.rebased_addr
        #logging.info("[+] Found ZwMapViewOfSection: %s", hex(zwmapview.rebased_addr))

    else:
        print("ZwMapViewOfSection import not found!\n")
        #logging.info("ZwMapViewOfSection import not found!\n")

    return import_addr


def find_driver_type(proj):
    iocreatedevice_addr = proj.loader.find_symbol("IoCreateDevice")
    driver_type = ""
    if iocreatedevice_addr:

        print("Found WDM driver: ", hex(iocreatedevice_addr.rebased_addr))
        #logging.info("Found WDM driver: %s", hex(iocreatedevice_addr.rebased_addr))
        driver_type = "wdm"
    else:
        print("Different driver type detected..")
        #logging.info("Different driver type detected..")

    return driver_type


def ioctl_handler_hook(state):
    global handler
    ioctl_handler_addr = state.solver.eval(state.inspect.mem_write_expr)
    state.globals['ioctl_handler'] = int(ioctl_handler_addr)
    handler = int(ioctl_handler_addr)


FIRST_ADDR = 0x444f0000


def next_base_addr(size=0x1000):
    global FIRST_ADDR
    v = FIRST_ADDR
    FIRST_ADDR += size
    return v


def read_concrete_utf16_string(state, addr):
    i = 0
    while True:
        assert i <= 0x1000
        val = state.memory.load(addr + i, 2, endness=state.arch.memory_endness)
        concrete = state.solver.eval_one(val)
        if concrete == 0:
            return state.memory.load(addr, i + 2)
        i += 2


def find_ioctl_handler(proj):
    global ioctl_handler
    global handler

    do_addr = next_base_addr()
    driver_object = claripy.BVS("driver_object", 8 * 0x100)
    rp_addr = next_base_addr()
    registry_path = claripy.BVS("registry_path", 8 * 0x100)

    # init_state = proj.factory.call_state(proj.entry, do_addr, rp_addr, cc=mycc, add_options=angr.options.unicorn)
    init_state = proj.factory.call_state(proj.entry, do_addr, rp_addr, cc=mycc)
    init_state.globals['open_section_handles'] = ()
    init_state.globals['driver_object_addr'] = do_addr

    init_state.memory.store(do_addr, driver_object)
    init_state.memory.store(rp_addr, registry_path)
    print("DriverObject @ {}".format(hex(do_addr)))
    #logging.info("DriverObject @ %s", hex(do_addr))

    #init_state.inspect.b('mem_write', when=angr.BP_AFTER, action=lambda s: print("MEM_WRITE @ {} to {}".format(s, s.inspect.mem_write_address)))
    init_state.inspect.b("mem_write", mem_write_address=do_addr + (0xe0 if proj.arch.name == archinfo.ArchAMD64.name else 0x70), when=angr.BP_AFTER, action=ioctl_handler_hook)

    print("\n[+] Finding the IOCTL Handler..\n\n")
    #logging.debug("[+] Finding the IOCTL Handler..\n")

    sm = proj.factory.simgr(init_state)

    dfs = angr.exploration_techniques.DFS()
    sm.use_technique(dfs)

    ed_ioctl = ExplosionDetector(threshold=100)
    sm.use_technique(ed_ioctl)

    def filter_func(s):
        if 'ioctl_handler' not in s.globals:
            return False
        retval = mycc.return_val(angr.types.BASIC_TYPES['long int']).get_value(s)
        return not s.solver.satisfiable(extra_constraints=[retval != 0])

    for i in range(0x100000):
        #while len(sm.active) > 0 and not ed_ioctl.state_exploded_bool:
        sm.step()
        sm.move(from_stash='deadended', to_stash='found', filter_func=filter_func)
        print(sm, {_s: _ss for _s, _ss in sm.stashes.items() if _ss})
        #sm.explore()
        if len(sm.found) or not len(sm.active):
            break
    else:
        print("DriverEntry hit limit of executions, could not locate")

    if sm.errored:
        # ipdb.set_trace()
        print('\n'.join(map(repr, proj.loader.all_objects)))
        for s in sm.errored:
            print(f"ERROR: {repr(s)}", file=sys.stderr)

    if not sm.found:
        # import ipdb; ipdb.set_trace()
        print(f"Could not find a successful DriverEntry run!!! {sm=}, {sm.stashes}")
        #logging.error("Could not find a successful DriverEntry run!!!")
        #ipdb.set_trace()
        #assert False

    success_state = sm.found[0]

    ioctl_handler = success_state.globals['ioctl_handler'] or handler
    print("[+] Found ioctl handler @ {:x}".format(ioctl_handler))
    #logging.critical("[+] Found ioctl handler @ %s", ioctl_handler)
    return ioctl_handler, success_state


def find_ioctls(proj: angr.Project, driver_base_state: angr.SimState, ioctl_handler_addr, target_addr):
    irp_addr = 0x1337000
    irsp_addr = 0x6000000
    ioctl_inbuf_addr = 0x7000000
    type3_input_buf_addr = 0x8000000

    if 'device_object_addr' in driver_base_state.globals:
        device_object_addr = claripy.BVV(driver_base_state.globals['device_object_addr'], driver_base_state.arch.bits)
    else:
        device_object_addr = claripy.BVS('device_object_ptr', driver_base_state.arch.bits)
    state: angr.SimState = proj.factory.call_state(ioctl_handler_addr, device_object_addr, irp_addr, cc=mycc,
                                    # base_state=driver_base_state, add_options=angr.options.unicorn)
                                    base_state=driver_base_state)
    state.globals['open_section_handles'] = tuple()
    irp = claripy.BVS("irp_buf", 8 * 0x200)
    ioctl_inbuf = claripy.BVS("ioctl_inbuf", 8 * 0x200).reversed
    type3_input_buf = claripy.BVS('ioctl_type3_inbuf', 8 * 0x200)

    state.memory.store(irp_addr, irp)
    state.memory.store(ioctl_inbuf_addr, ioctl_inbuf)
    state.memory.store(type3_input_buf_addr, type3_input_buf)

    major_func, minor_func, output_buf_length, input_buf_length, ioctlcode = map(lambda x: claripy.BVS(*x), [
        ("MajorFunction", 8), ("MinorFunction", 8), ('OutputBufferLength', 32), ('InputBufferLength', 32),
        ('IoControlCode', 32)])

    state.add_constraints(major_func == 14)

    state.mem[irp_addr].IRP.Tail.Overlay.s.u.CurrentStackLocation = irsp_addr
    state.mem[irp_addr].IRP.AssociatedIrp.SystemBuffer = ioctl_inbuf_addr

    state.mem[irsp_addr].IO_STACK_LOCATION.MajorFunction = major_func
    state.mem[irsp_addr].IO_STACK_LOCATION.MinorFunction = minor_func

    _params = state.mem[irsp_addr].IO_STACK_LOCATION.Parameters
    # Hack, here we need to use .val because we had to have the hacky POINTER_ALIGNED_ULONG to get the offsets right
    _params.DeviceIoControl.OutputBufferLength.val = output_buf_length
    _params.DeviceIoControl.InputBufferLength.val = input_buf_length
    _params.DeviceIoControl.IoControlCode.val = ioctlcode
    _params.DeviceIoControl.Type3InputBuffer = type3_input_buf_addr
    sm = proj.factory.simgr(state)

    sm.populate('found', [])

    if ARGS.directed:
        def hit_callback(
            goal: angr.exploration_techniques.director.BaseGoal,
            state: angr.SimState,
            simgr: angr.SimulationManager
        ):
            print('#' * 80)
            print(f"hit goal {goal=} {state=} {simgr=}")
            print('#' * 80)
            simgr.populate('found', [state])

        director = angr.exploration_techniques.Director(
            # peek_blocks=200,
            # peek_functions=10,
            goal_satisfied_callback=hit_callback)
        director.add_goal(ExecuteAddressGoal(target_addr))
        sm.use_technique(director)

    # Explosion Detection HERE!!
    dfs = angr.exploration_techniques.DFS()
    sm.use_technique(dfs)

    ed = ExplosionDetector(threshold=10000)
    sm.use_technique(ed)

    if not ARGS.directed:
        exp = angr.exploration_techniques.Explorer(find=target_addr)
        sm.use_technique(exp)

    sol = None

    while len(sm.active) > 0 and not ed.state_exploded_bool:
        #new_state = sm.active[0]
        #state_addr = new_state.solver.eval(new_state.regs.pc)
        #sm.step()
        sm.step()
        print(sm)

        if sm.found:
            print("Found sol early..")
            sol = sm.found[0]
            break

    print("\nFinding the IOCTL codes..")
    #logging.debug("Finding the IOCTL codes..")
    ioctl = ""

    if ed.state_exploded_bool:
        print("\nState Exploded!")
        # ipdb.set_trace()

    if sm.errored:
        # ipdb.set_trace()
        for s in sm.errored:
            print(f"ERROR: {repr(s)}", file=sys.stderr)

    if sol:
        #sol = sm.found[0]
        #IPython.embed()
        ioctl = sol.solver.eval(ioctlcode)
        print("[+] Boom! Here is the IOCTL: ", hex(ioctl))
        #logging.critical("[+] Boom! Here is the IOCTL: %s", hex(ioctl))

    else:
        import ipdb; ipdb.set_trace()
        print("No IOCTL codes found!")
        # import ipdb; ipdb.set_trace()
        #logging.info("No IOCTL codes found!")

    return sol, ioctl


def MmMapIoSpace_analysis(found_state):

    prototype = mycc.guess_prototype((0, 0))
    # import ipdb; ipdb.set_trace()
    PhysicalAddress, NumberOfBytes = mycc.get_args(found_state, prototype)

    if PhysicalAddress.symbolic and NumberOfBytes.symbolic:
        print("[+] Address and Size are user controlled: Addr={}, size={} ..".format(PhysicalAddress, NumberOfBytes))
        print("[+] Driver's MmMapIoSpace is potentially vulnerable!!")
        #logging.critical("[+] Address and Size are user controlled: Addr=%s, size=%s ..", PhysicalAddress, NumberOfBytes)
        #logging.critical("[+] Driver's MmMapIoSpace is potentially vulnerable!!")

    if PhysicalAddress.symbolic and not NumberOfBytes.symbolic:
        print("[+] Address is user controlled: Addr={}, mapping {} bytes ..".format(PhysicalAddress, NumberOfBytes))
        print("[+] Driver's MmMapIoSpace is potentially vulnerable!!")
        #logging.critical("[+] Address is user controlled: Addr=%s, mapping %s bytes ..", PhysicalAddress, NumberOfBytes)
        #logging.critical("[+] Driver's MmMapIoSpace is potentially vulnerable!!")


def ZwMapViewOfSection_analysis(found_state):
    prototype = mycc.guess_prototype((0,))
    # import ipdb; ipdb.set_trace()
    handle, = mycc.get_args(found_state, prototype)
    if not handle.symbolic:
        return

    if any('handle_ZwOpenSection' not in v for v in handle.variables):
        print("[+] SectionHandle is user controlled, handle={} ..".format(handle))
        print("[+] Driver's ZwMapViewOfSection is potentially vulnerable!!")
        #logging.critical("[+] SectionHandle is user controlled, handle=%s ..",handle)
        #logging.critical("[+] Driver's ZwMapViewOfSection is potentially vulnerable!!")
    else:
        # Okay, now we have to check what this handle refers to
        handles = dict(found_state.globals['open_section_handles'])
        if handle not in handles:
            print("[+] ZwMapViewOfSection called on unknown handle!! Handle={} ...".format(repr(handle)))
            #logging.error("[+] ZwMapViewOfSection called on unknown handle!! Handle=%s ...", repr(handle))
            return

        if handles[handle] == '\\Device\\PhysicalMemory':
            print("[+] ZwMapViewOfSection is potentially vulnerable, mapping PhysicalMemory .. ")
            #logging.critical("[+] ZwMapViewOfSection is potentially vulnerable, mapping \\Device\\PhysicalMemory .. ")


def ZwOpenProcess_analysis(found_state):
    prototype = mycc.guess_prototype((0, 0, 0, 0))
    # import ipdb; ipdb.set_trace()
    _, _, _, ClientID = mycc.get_args(found_state, prototype)
    if ClientID.symbolic:
        print("[+] ClientID of the process is user controlled, ClientID={} .. ".format(ClientID))
        print("[+] Driver's ZwOpenProcess is potentially vulnerable!!")
        #logging.critical("[+] ClientID of the process is user controlled, ClientID=%s.. ",ClientID)
        #logging.critical("[+] Driver's ZwOpenProcess is potentially vulnerable!!")



class HookIoCreateDevice(angr.SimProcedure):
    def run(self, DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive,
            DeviceObject):
        devobjaddr = next_base_addr()
        self.state.globals['device_object_addr'] = devobjaddr
        #print("HookIoCreateDevice: Placing device object at {:08x}!".format(devobjaddr))
        #logging.debug("HookIoCreateDevice: Placing device object at %s!", devobjaddr)
        device_object = claripy.BVS('device_object', 8 * 0x400)
        self.state.memory.store(devobjaddr, device_object)
        self.state.mem[devobjaddr].DEVICE_OBJECT.Flags = 0
        self.state.mem[DeviceObject].PDEVICE_OBJECT = devobjaddr

        new_device_extension_addr = next_base_addr()
        self.state.globals['device_extension_addr'] = new_device_extension_addr
        #print("HookIoCreateDevice: Placing device extension at {:08x}!".format(new_device_extension_addr))
        #logging.debug("HookIoCreateDevice: Placing device extension at %s!", new_device_extension_addr)
        device_extension = claripy.BVV(0, 8 * self.state.solver.eval_one(DeviceExtensionSize))
        self.state.memory.store(new_device_extension_addr, device_extension)
        self.state.mem[devobjaddr].DEVICE_OBJECT.DeviceExtension = new_device_extension_addr

        return 0


class HookIoCreateSymbolicLink(angr.SimProcedure):
    def run(self, SymbolicLinkName, DeviceName):
        return 0


class HookZwOpenSection(angr.SimProcedure):
    def run(self, SectionHandle, DesiredAccess, ObjectAttributes):
        new_handle = claripy.BVS('handle_ZwOpenSection', self.state.arch.bits)
        self.state.memory.store(SectionHandle, new_handle, endness=self.state.arch.memory_endness)

        object_name_struct = self.state.mem[ObjectAttributes].OBJECT_ATTRIBUTES.ObjectName.deref
        try:
            object_name = object_name_struct.Buffer.deref.wstring.concrete
        except:
            return

        # print("[+] Writing {} to {}".format(new_handle, SectionHandle))
        self.state.globals['open_section_handles'] += ((new_handle, object_name),)
        return 0


def read_ptr(state, addr):
    return state.memory.load(addr, state.arch.bits, endness=state.arch.memory_endness)


def write_ptr(state, addr, ptr):
    return state.memory.store(addr, ptr, endness=state.arch.memory_endness)

def opportunistically_eval_one(state, value, msg_on_multi):
    conc_vals = state.solver.eval_upto(value, 2)
    if len(conc_vals) > 1:
        print(msg_on_multi)
        print(f"Concretizing to {hex(conc_vals[0])}")
        state.solver.add(value == conc_vals[0])
    return conc_vals[0]

class HookRtlInitUnicodeString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        try:
            string_orig = self.state.mem[SourceString].wstring.resolved
        except:
            string_orig = claripy.Concat(claripy.BVS("symbolic_init_unicode_string", 8 * 10), claripy.BVV(0, 16))

        byte_length = string_orig.length // 8
        new_buffer = next_base_addr(size=byte_length + 0x20)
        self.state.memory.store(new_buffer, string_orig)

        unistr = self.state.mem[DestinationString].struct._UNICODE_STRING

        self.state.memory.store(DestinationString, claripy.BVV(0, unistr._type.size))
        unistr.Length = byte_length - 2
        unistr.MaximumLength = byte_length
        unistr.Buffer = new_buffer

        # IPython.embed()

        return 0

class HookRtlCopyUnicodeString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        memcpy = angr.procedures.SIM_PROCEDURES['libc']['memcpy']
        src_unistr = self.state.mem[SourceString].struct._UNICODE_STRING
        src_len = src_unistr.Length

        dst_unistr = self.state.mem[DestinationString].struct._UNICODE_STRING
        dst_maxi_len = src_unistr.MaximumLength

        conc_src_len = opportunistically_eval_one(
            self.state,
            src_len.resolved,
            f"Symbolic CopyUnicodeString source size...???? {src_unistr=} size={src_len=}")
        conc_dst_max_len = opportunistically_eval_one(
            self.state,
            dst_maxi_len.resolved,
            f"Symbolic CopyUnicodeString source maximum length...???? {dst_unistr=} size={dst_maxi_len=}")

        self.inline_call(memcpy, dst_unistr.Buffer.resolved, src_unistr.Buffer.resolved, min(conc_src_len, conc_dst_max_len))

        return 0


class HookExAllocatePool(angr.SimProcedure):
    def run(self, pool_type, size):
        conc_sizes = self.state.solver.eval_upto(size, 2)
        if len(conc_sizes) > 1:
            print(f"Symbolic ExAllocatePool size...???? {pool_type=} {size=}")
            print(f"Concretizing to {hex(conc_sizes[0])}")
            self.state.solver.add(size == conc_sizes[0])

        addr = next_base_addr(conc_sizes[0])
        return addr

class HookExAllocatePoolWithTag(angr.SimProcedure):
    def run(self, pool_type, size, tag):
        conc_sizes = self.state.solver.eval_upto(size, 2)
        if len(conc_sizes) > 1:
            print(f"Symbolic ExAllocatePoolWithTag size...???? {pool_type=} {size=} {tag=}")
            print(f"Concretizing to {hex(conc_sizes[0])}")
            self.state.solver.add(size == conc_sizes[0])

        addr = next_base_addr(conc_sizes[0])
        return addr


class HookObReferenceObjectByHandle(angr.SimProcedure):

    def run(self, Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation):
        print("JASimproc")
        return 0

def print_constraint(found_path):

    constraints = found_path.solver.constraints
    #logging.info("Constraints:")
    for constraint in constraints:
        constraint_str = "%s" % constraint
        if "InputBufferLength" in constraint_str:
            print("[+] Input Buffer Size: ", constraint)
            #logging.info("[+] Input Buffer Size: %s", constraint)

        if "inbuf" in constraint_str:
            print("[+] Input Buffer: ", constraint)
            #logging.info("[+] IOCTL: %s", constraint)

        if "OutputBufferLength" in constraint_str:
            print("[+] Output Buffer Size: ", constraint)
            #logging.info("[+] Output Buffer Size: %s", constraint)

    #print("ELSE: ", constraints)


# Super fancy, mind boggling state explosion detector
class ExplosionDetector(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, stashes=('active', 'deferred', 'errored', 'cut'), threshold=1000):
        super(ExplosionDetector, self).__init__()
        self._stashes = stashes
        self._threshold = threshold
        self.timed_out = Event()
        self.timed_out_bool = False
        self.state_exploded_bool = False

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        total = 0

        if len(simgr.unconstrained) > 0:
            #l.debug("Nuking unconstrained")
            # import ipdb; ipdb.set_trace()
            print("Nuking unconstrained states..")
            simgr.move(from_stash='unconstrained', to_stash='_Drop', filter_func=lambda _: True)

        if self.timed_out.is_set():
            #l.critical("Timed out, %d states: %s" % (total, str(simgr)))
            print("Timed out, %d states: %s" % (total, str(simgr)))
            self.timed_out_bool = True
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)

        for st in self._stashes:
            if hasattr(simgr, st):
                total += len(getattr(simgr, st))

        if total >= self._threshold:
            #l.critical("State explosion detected, over %d states: %s" % (total, str(simgr)))
            print("State explosion detected, over %d states: %s" % (total, str(simgr)))
            self.state_exploded_bool = True
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)

        return simgr

def find_utf_16le_str(data, string):
    cursor = 0
    found = collections.deque()
    device_name = ""
    while cursor < len(data):
        cursor = data.find(string, cursor)
        if cursor == -1:
            break
        terminator = data.find(b'\x00\x00', cursor)
        if (terminator - cursor) % 2:
            terminator += 1
        match = data[cursor:terminator].decode('utf-16le')
        if match not in found:
            device_name = match
            found.append(match)
        cursor += len(string)

    return device_name


def find_device_names(path):
    with open(path, 'rb') as f:
        data = f.read()
        names = []
        for dd in DOS_DEVICES:
            names.append(find_utf_16le_str(data, dd))

        if len(names) == 0:
            print("\nNo Device Name has been found")
            #logging.info("No Device Name has been found")

        else:
            name = []
            for i in names:
                if i:
                    for j in i[::-1]:
                        if j != "\\":
                            name.append(j)
                        else:
                            name.reverse()
                            break

                    dd_name = "\\\\\\\\.\\\\" + "".join(name)
                    print("\nDriver DEVICE_NAME: ", dd_name)
                    #logging.info("Driver DEVICE_NAME: %s", dd_name)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directed',
        default=False,
        action='store_true',
        help='Whether to use directed symbolic execution'
    )
    parser.add_argument('driver_path', type=Path, help='The path to the driver to analyze')
    ARGS = parser.parse_args()

    proj = angr.Project(ARGS.driver_path, auto_load_libs=False)
    # Custom CC hooking for the SimProcs
    if proj.arch.name == archinfo.ArchX86.name:
        mycc = angr.calling_conventions.SimCCStdcall(proj.arch)
    else:
        mycc = angr.calling_conventions.SimCCMicrosoftAMD64(proj.arch)
    proj.hook_symbol("ZwOpenSection", HookZwOpenSection(cc=mycc))
    proj.hook_symbol("RtlInitUnicodeString", HookRtlInitUnicodeString(cc=mycc))
    proj.hook_symbol("RtlCopyUnicodeString", HookRtlCopyUnicodeString(cc=mycc))
    proj.hook_symbol("IoCreateDevice", HookIoCreateDevice(cc=mycc))
    proj.hook_symbol("IoCreateSymbolicLink", HookIoCreateSymbolicLink(cc=mycc))
    proj.hook_symbol("ExAllocatePool", HookExAllocatePool(cc=mycc))
    proj.hook_symbol("ExAllocatePoolWithTag", HookExAllocatePoolWithTag(cc=mycc))
    proj.hook_symbol('memmove', angr.procedures.SIM_PROCEDURES['libc']['memcpy']())
    # proj.hook_symbol("ObReferenceObjectByHandle", HookObReferenceObjectByHandle(cc=mycc))

    # cfg = proj.analyses.CFGEmulated(keep_state=False, normalize=True, starts=[ioctl_func_addr])

    driver_type = find_driver_type(proj)

    DOS_DEVICES = ['\\DosDevices\\'.encode('utf-16le'), '\\??\\'.encode('utf-16le')]


    if driver_type == "wdm":

        start_time = time.time()

        find_device_names(ARGS.driver_path)

        targets = check_imports(proj)

        if targets:
            ioctl_handler_addr, driver_base_state = find_ioctl_handler(proj)
            #ioctl_handler_addr = 0x1400045A0
            if ioctl_handler_addr is not None:

                if MMMAPIOSPACE:
                    mmmap_addr = int(targets["MmapIoSpace"])
                    found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, mmmap_addr)

                    if ioctl_code:
                        print("[+] IOCTL for MmapIoSpace: ", hex(ioctl_code))
                        #logging.info("[+] IOCTL for MmapIoSpace: %s", hex(ioctl_code))
                        MmMapIoSpace_analysis(found_path)
                        print_constraint(found_path)

                if ZWMAPVIEWOFSECTION:
                    zwmap_addr = int(targets["ZwMapViewOfSection"])
                    found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, zwmap_addr)

                    if ioctl_code:
                        print("[+] IOCTL for ZwMapViewOfSection: ", hex(ioctl_code))
                        #logging.info("[+] IOCTL for ZwMapViewOfSection: %s", hex(ioctl_code))
                        ZwMapViewOfSection_analysis(found_path)
                        print_constraint(found_path)

                if ZWOPENPROCESS:
                    zwopen_addr = int(targets["ZwOpenProcess"])
                    found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, zwopen_addr)

                    if ioctl_code:
                        print("[+] IOCTL for ZwOpenProcess: ", hex(ioctl_code))
                        #logging.info("[+] IOCTL for ZwOpenProcess: %s", hex(ioctl_code))
                        ZwOpenProcess_analysis(found_path)
                        print_constraint(found_path)

        print("--- %s seconds ---" % (time.time() - start_time))
