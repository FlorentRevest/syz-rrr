# Copyright 2024 Google LLC
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

from rrr.perfetto_trace_pb2 import Trace, TracePacket, TrackEvent
from perfetto.trace_processor import TraceProcessor, TraceProcessorConfig
from pygdbmi.gdbcontroller import GdbController
import pandas as pd # Not the same Panda!
from pandare import Panda
import multiprocessing
from enum import Enum
import urllib.request
import subprocess
import hashlib
import shutil
import time
import stat
import json
import uuid
import io
import os
import re

# Panda VM characteristics
arch = "x86_64"
mem = "1G"
# A lot of security features get in the way of good tracing so disable them:
# nokaslr: Makes kernelspace symbols extraction easier
# sysctl.kernel.randomize_va_space=0: Makes userspace symbols extraction easier
# mitigations=off: disables a lot of CPU bug mitigations, for example:
# - nopti: share page tables between kernel and userspace, makes tracing easier
# - nospectre_v2: disable RSB stuffing on context switches which confuses the
#   callstack_instr plugin with many calls that never return
extra_qemu_kernel_args = "-kernel {} -append \"root=/dev/sda rw init=/init nokaslr sysctl.kernel.randomize_va_space=0 mitigations=off\""
extra_qemu_machine_args = "-nographic -nodefaults"
expect_prompt="(REPRODUCER DID NOT CRASH|KASAN|KCSAN|UBSAN|BUG|WARNING|INFO|protection fault)"

# Short boot-script that sets up a minimal environment to run a reproducer on a key press
ready_serial_signal = "READY TO RUN REPRO"
init_code = f"""#!/bin/sh

# Mount various important file systems
mount -t proc none /proc
mount -t sysfs none /sys
mount -t tmpfs none /run
mount -t tmpfs none /tmp
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
mount -t securityfs none /sys/kernel/security
mount -t configfs none /sys/kernel/config
mount -t binfmt_misc none /proc/sys/fs/binfmt_misc
mount -t fusectl none /sys/fs/fuse/connections
mount -t pstore none /sys/fs/pstore
mount -t bpf none /sys/fs/bpf
mount -t tracefs none /sys/kernel/tracing
mkdir -p /dev/pts /dev/shm
mount -t devpts none /dev/pts
mount -t tmpfs none /dev/shm

# Use the serial line to notify our wrapper of boot completion
echo {ready_serial_signal}

# Wait for an enter key before running the reproducer
read

# Run the reproducer
/repro

# If we're here, it didn't crash the kernel. Write something and wait
echo REPRODUCER DID NOT CRASH
read

# If we end up here, someone is debugging manually, drop them into a shell
setsid /sbin/getty -l /bin/sh -n 115200 ttyS0
"""

# Small helper for conditional logging
logging = True
def log(str):
    if logging:
        print(str)

# To cache URLs that were already downloaded, implement a hash
def strHash(str):
    return hashlib.sha1(str.encode("UTF-8")).hexdigest()[:10]

# Download a file if not already downloaded
def cached_download(url, download_dest_prefix, download_dest_suffix=""):
    path = download_dest_prefix + "-" + strHash(url) + download_dest_suffix

    if os.path.exists(path):
        log(f"Re-using {path} as cache for {url}...")
    else:
        log(f"Downloading {path} from {url} ...")
        urllib.request.urlretrieve(url, path)

    return path

# Write a file to disk if not already existing
def cached_file(content, dest_prefix, dest_suffix=""):
    path = dest_prefix + "-" + strHash(content) + dest_suffix

    if os.path.exists(path):
        log(f"Re-using {path} as cache...")
    else:
        log(f"Writing {path} ...")
        with open(path, 'w') as f:
            f.write(content)

    return path

# Origin of a .config, either from a URL or on-disk
class Config:
    @classmethod
    def from_str(cls, cfg):
        return cls(cached_file(cfg, "config"))

    @classmethod
    def from_url(cls, url):
        return cls(cached_download(url, "config"))

    def __init__(self, path="/dev/null", disabled_cfgs=[], enabled_cfgs=["DEBUG_INFO_DWARF4", "DEBUG_INFO_BTF"]):
        self.path = path
        self.disabled_cfgs = disabled_cfgs
        self.enabled_cfgs = enabled_cfgs

    def enable(self, cfg):
        self.enabled_cfgs.append(cfg)

    def disable(self, cfg):
        self.disabled_cfgs.append(cfg)

# Origin of a stimulus source code, either from a URL or on-disk
class Stimulus:
    @classmethod
    def from_str(cls, code):
        return cls(cached_file(code, "stimulus", ".c"))

    @classmethod
    def from_url(cls, url):
        return cls(cached_download(url, "stimulus", ".c"))

    def __init__(self, path, force_rebuild=False):
        build_path, _ = os.path.splitext(path)

        if force_rebuild or not os.path.exists(build_path):
            log(f"Building {build_path} from {path} ...")
            gcc = subprocess.run(["gcc", "-g", "-pthread", "-static", "-o", build_path, path],
                                 capture_output=True, text=True)
            if gcc.returncode:
                raise Exception("Compiling {path} failed: " + gcc.stderr)
        else:
            log(f"Skipping {build_path} build from {path}")

        self.built_path = build_path

# Origin of a kernel source code, either from a git URL or on-disk directory
class Kernel:
    @classmethod
    def from_git(cls, config=Config(), commit_hash="HEAD", path="linux/",
                 url="git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
                 force_rebuild=False):
        # Only clone linux once
        if not os.path.exists(path):
            log(f"Cloning {url} to {path} ...")
            clone = subprocess.run(["git", "clone", url, path],
                                   capture_output=True, text=True)
            if clone.returncode:
                raise Exception("Cloning linux failed: " + clone.stdout)
        else:
            log(f"Re-using existing {path}")
            revparse = subprocess.run(["git", "rev-parse", "--verify", commit_hash],
                                      capture_output=True, text=True, cwd=path)
            if revparse.returncode:
                log(f"{commit_hash} missing - fetching {url} in {path} ...")
                clone = subprocess.run(["git", "fetch", url],
                                       capture_output=True, text=True, cwd=path)

        # Checkout the crashing hash in linux
        log(f"Checking out {commit_hash} ...")
        checkout = subprocess.run(["git", "checkout", commit_hash],
                                  capture_output=True, text=True, cwd=path)
        if checkout.returncode:
            raise Exception("Checking out commit hash failed: " + checkout.stderr)

        return cls(path, config, force_rebuild)

    def __init__(self, path, config=Config(), force_rebuild=False):
        self.path = path
        build_path = os.path.join(self.path, "arch", "x86", "boot", "bzImage")

        if force_rebuild or not os.path.exists(build_path):
            # Copy .config
            log("Configuring the kernel ...")
            shutil.copyfile(config.path, os.path.join(self.path, ".config"))
            subprocess.run(["make", "olddefconfig"],
                           capture_output=True, text=True, cwd=self.path)

            if len(config.disabled_cfgs) != 0:
                cmd = ["scripts/config"]
                for cfg in config.disabled_cfgs:
                    cmd.append("-d")
                    cmd.append(cfg)
                log(f"Disabling {', '.join(config.disabled_cfgs)}")
                subprocess.run(cmd, capture_output=True, text=True, cwd=self.path)

            if len(config.enabled_cfgs) != 0:
                cmd = ["scripts/config"]
                for cfg in config.enabled_cfgs:
                    cmd.append("-e")
                    cmd.append(cfg)
                log(f"Enabling {', '.join(config.enabled_cfgs)}")
                subprocess.run(cmd, capture_output=True, text=True, cwd=self.path)

            # Build on all CPUs
            log("Building the kernel ...")
            make = subprocess.run(["make", "-j", str(os.cpu_count())],
                                   capture_output=True, text=True, cwd=self.path)
            if make.returncode:
                raise Exception("Building Linux failed: " + make.stderr)
        else:
            log(f"Skipping kernel build and re-using {build_path}")

        self.built_path = build_path
        self.debug_path = os.path.join(self.path, "vmlinux")

        # DWARF is a pain to parse, but BTF is a joy, let's extract it in JSON
        log("Extracting BTF debug info ...")
        btf_path = os.path.join(self.path, "vmlinux.btf")
        pahole = subprocess.run(["pahole", "--btf_encode_detached", btf_path, self.debug_path],
                                capture_output=True, text=True)
        if pahole.returncode:
            raise Exception("Extracting BTF failed: " + pahole.stderr)

        log("Extracting BTF debug info as JSON ...")
        pahole = subprocess.run(["bpftool", "btf", "dump", "-j", "file", btf_path],
                                capture_output=True, text=True)
        if pahole.returncode:
            raise Exception("Extracting BTF JSON failed: " + pahole.stderr)
        self.types = json.loads(pahole.stdout)["types"]

        # PANDA's OSI requires certain offsets to be extracted in a file, do it with gdb
        self.info_path = "kernelinfo.conf"
        log(f"Generating {self.info_path} for PANDA ...")
        info_file = open(self.info_path, "w+")

        file_bzImage = subprocess.run(["file", self.built_path],
                                      capture_output=True, text=True)
        if file_bzImage.returncode:
            raise Exception("Extracting information about the bzImage failed: " + file_bzImage.stderr)
        version_pattern = r'version (\d+)\.(\d+)\.(\d+)'
        version_match = re.search(version_pattern, file_bzImage.stdout)

        print(f"[linux:1.0:64]",file=info_file)
        print(f"name = Linux",file=info_file)
        print(f"version.a = {version_match.group(1)}",file=info_file)
        print(f"version.b = {version_match.group(2)}",file=info_file)
        print(f"version.c = {version_match.group(3)}",file=info_file)

        gdbmi = GdbController()
        gdbmi.write(f'-interpreter-exec console "file {self.debug_path}"')

        def gdb_printf(format, value, timeout_sec=10):
            ret = ""
            responses = gdbmi.write(r'-interpreter-exec console "printf \"' + format + r'\", ' + value + r'"',
                                    timeout_sec=timeout_sec)
            for response in responses:
                if not response['type'] == 'console':
                    continue
                ret = ret + response['payload']

            return ret

        # The first gdb command can take a while, use a longer timeout
        per_cpu_offset_addr = gdb_printf("%llu", f"&__per_cpu_offset", timeout_sec=30)
        per_cpu_offset_0_addr = gdb_printf("%llu", f"__per_cpu_offset[0]")
        switch_task_hook_addr = gdb_printf("%llu", f"&finish_task_switch")
        print(f"task.per_cpu_offsets_addr = {per_cpu_offset_addr}",file=info_file)
        print(f"task.per_cpu_offset_0_addr = {per_cpu_offset_0_addr}",file=info_file)
        print(f"task.switch_task_hook_addr = {switch_task_hook_addr}",file=info_file)

        init_task_addr = gdb_printf("%llu", f"&init_task")
        current_task_addr = gdb_printf("%llu", f"&current_task")
        print(f"task.current_task_addr = {current_task_addr}",file=info_file)
        print(f"task.init_addr = {init_task_addr}",file=info_file)

        comm_size = gdb_printf("%u", f"(size_t)sizeof(((struct task_struct*)0)->comm)")
        print(f"task.comm_size = {comm_size}",file=info_file)

        f_path_offset = gdb_printf("%d", f"(int)&((struct file*)0)->f_path.dentry")
        print(f"fs.f_path_dentry_offset = {f_path_offset}",file=info_file)
        offset = gdb_printf("%d", f"(int)&((struct file*)0)->f_path.mnt")
        print(f"fs.f_path_mnt_offset = {offset}",file=info_file)

        mnt_parent_offset = int(gdb_printf("%lld", "(int64_t)&((struct mount)*0)->mnt_parent"))
        mnt_mountpoint_offset = int(gdb_printf("%lld", "(int64_t)&((struct mount)*0)->mnt_mountpoint"))
        mnt_offset = int(gdb_printf("%lld", "(int64_t)&((struct mount)*0)->mnt"))
        print(f"path.mnt_parent_offset = {mnt_parent_offset - mnt_offset}",file=info_file)
        print(f"path.mnt_mountpoint_offset = {mnt_mountpoint_offset - mnt_offset}",file=info_file)

        # Offsets that no longer exist
        print("mm.mmap_offset = -1",file=info_file)
        print("vma.vm_next_offset = -1",file=info_file)

        structs = {"task_struct": ("task", ["tasks", "pid", "tgid", "group_leader",
                                            "thread_group", "real_parent", "parent", "mm",
                                            "stack", "real_cred", "cred", "comm", "files",
                                            "start_time"]),
                   "cred": ("cred", ["uid", "gid", "euid", "egid"]),
                   "mm_struct": ("mm", ["pgd", "arg_start", "start_brk", "brk", "start_stack"]),
                   "vm_area_struct": ("vma", ["vm_mm", "vm_start", "vm_end", "vm_flags", "vm_file"]),
                   "file": ("fs", ["f_pos"]),
                   "files_struct": ("fs", ["fdt", "fdtab"]),
                   "fdtable": ("fs", ["fd"]),
                   "qstr": ("qstr", ["name"]),
                   "dentry": ("path", ["d_name", "d_iname", "d_parent", "d_op"]),
                   "dentry_operations": ("path", ["d_dname"]),
                   "vfsmount": ("path", ["mnt_root"])}

        for name, (short_name, fields) in structs.items():
            size = gdb_printf("%u", f"(size_t)sizeof(struct {name})")
            print(f"{short_name}.size = {size}",file=info_file)
            for field in fields:
                offset = gdb_printf("%d", f"(int)&((struct {name}*)0)->{field}")
                print(f"{short_name}.{field}_offset = {offset}",file=info_file)

        gdbmi.exit()
        info_file.close()

# Origin of a rootfs (busybox + stimulus)
class Rootfs:
    def __init__(self, stimulus, busybox_url="https://github.com/mirror/busybox", busybox_commit_hash="1_36_0",
                 busybox_path="busybox/", rootfs_path="rootfs/", image_path="rootfs.qcow2"):
        if not os.path.exists(busybox_path):
            log(f"Cloning {busybox_url} to {busybox_path} ...")
            clone = subprocess.run(["git", "clone", busybox_url, busybox_path],
                                   capture_output=True, text=True)
            if clone.returncode:
                raise Exception("Cloning busybox failed: " + clone.stdout)
        else:
            log(f"Re-using existing {busybox_path}")
            revparse = subprocess.run(["git", "rev-parse", "--verify", busybox_commit_hash],
                                      capture_output=True, text=True, cwd=busybox_path)
            if revparse.returncode:
                log(f"{busybox_commit_hash} missing - fetching {busybox_url} in {path} ...")
                clone = subprocess.run(["git", "fetch", busybox_url],
                                       capture_output=True, text=True, cwd=busybox_path)

        # Checkout the crashing hash in busybox
        log(f"Checking out {busybox_commit_hash} ...")
        checkout = subprocess.run(["git", "checkout", busybox_commit_hash],
                                  capture_output=True, text=True, cwd=busybox_path)
        if checkout.returncode:
            raise Exception("Checking out commit hash failed: " + checkout.stderr)

        # Build Busybox
        self.busybox_debug_path = os.path.join(busybox_path, "busybox_unstripped")
        if not os.path.exists(self.busybox_debug_path):
            log("Building Busybox ...")
            defconfig = subprocess.run(["make", "defconfig"], capture_output=True, text=True, cwd=busybox_path)
            if defconfig.returncode:
                raise Exception("Configuring Busybox failed: " + defconfig.stderr)
            set_static = subprocess.run(["sed", "-i", "s@# CONFIG_STATIC is not set@CONFIG_STATIC=y@", ".config"],
                                        capture_output=True, text=True, cwd=busybox_path)
            if set_static.returncode:
                raise Exception("Configuring Busybox failed: " + set_static.stderr)
            make = subprocess.run(["make", "-j", str(os.cpu_count())],
                                  capture_output=True, text=True, cwd=busybox_path)
            if make.returncode:
                raise Exception("Building Busybox failed: " + make.stderr)
            make = subprocess.run(["make", "install", f"CONFIG_PREFIX={os.path.join(os.getcwd(), rootfs_path)}"],
                                  capture_output=True, text=True, cwd=busybox_path)
            if make.returncode:
                raise Exception("Installing Busybox failed: " + make.stderr)
        else:
            log(f"Skipping Busybox build and re-using {self.busybox_debug_path}")

        # Create a rootfs skeleton
        log(f"Filling {rootfs_path} ...")
        for dir in ["proc", "sys", "run", "tmp", "dev"]:
            # Ignore if the directory already exists
            try:
                os.makedirs(os.path.join(rootfs_path, dir))
            except FileExistsError:
                pass

        # Install the static reproducer
        repro_path = os.path.join(rootfs_path, "repro")
        shutil.copyfile(stimulus.built_path, repro_path)
        self.stimulus_debug_path = stimulus.built_path

        # Instal an init script
        init_path = os.path.join(rootfs_path, "init")
        with open(init_path, "w") as init:
            init.write(init_code)

        # Chmod +x /init and /repro
        for path in [init_path, repro_path]:
            mode = os.stat(path).st_mode
            os.chmod(path, mode | stat.S_IEXEC)

        # Generate the qcow2 image
        log(f"Generating {image_path} ...")
        virtmakefs = subprocess.run(["virt-make-fs", "--format=qcow2", "--type=ext4",
                                     rootfs_path, image_path], capture_output=True, text=True)
        if virtmakefs.returncode:
            raise Exception("Generating a qcow2 image failed: " + virtmakefs.stderr)

        self.path = image_path

def has_snapshot(rootfs):
    result = subprocess.run(['qemu-img', 'snapshot', '-l', rootfs.path], stdout=subprocess.PIPE)
    return b"root" in result.stdout

# Panda analysis passes
# Run in different processes because each Panda object requires a fresh address space
def __snapshot(rootfs, kernel):
    panda = Panda(arch=arch, mem=mem, expect_prompt=expect_prompt, qcow=rootfs.path,
                  extra_args=extra_qemu_machine_args + " " + extra_qemu_kernel_args.format(kernel))

    @panda.queue_blocking
    def setup():
        panda.serial_read_until(ready_serial_signal.encode())
        log("Reached snapshot point. Giving Panda 5 second to save it...")

        charptr = panda.ffi.new("char[]", bytes("root", "utf-8"))
        panda.queue_main_loop_wait_fn(panda.libpanda.panda_snap, [charptr])
        panda.queue_main_loop_wait_fn(panda.libpanda.panda_cont)
        time.sleep(5)
        log("Saved snapshot")

        panda.end_analysis()

    panda.run()

# Boots the VM and record a snasphot at the end of the boot, just before running /repro
def snapshot(rootfs, kernel):
    p = multiprocessing.Process(target=__snapshot, args=(rootfs, kernel.built_path))
    p.start()
    p.join()

    if p.exitcode:
        raise "Taking snapshot failed"

def __record(rootfs, output):
    panda = Panda(arch=arch, mem=mem, expect_prompt=expect_prompt, qcow=rootfs.path,
                  extra_args=extra_qemu_machine_args)

    @panda.queue_blocking
    def drive():
        panda.revert_sync("root")
        log("Starting record...")
        panda.run_monitor_cmd(f"begin_record {output}")

        panda.serial_console.send_eol()
        panda.serial_console.expect(timeout=None)
        print(panda.serial_console.get_partial())

        panda.run_monitor_cmd("end_record")
        log("Finished record")
        panda.end_analysis()

    panda.run()

def record(kernel, rootfs, output="record"):
    if not has_snapshot(rootfs):
        print("No booted snapshot found. Booting once...")
        snapshot(rootfs, kernel)

    p = multiprocessing.Process(target=__record, args=(rootfs, output))
    p.start()
    p.join()

    if p.exitcode:
        raise "Recording execution failed"
    return output

def __replay(rootfs):
    panda = Panda(arch=arch, mem=mem, expect_prompt=expect_prompt, qcow=rootfs.path,
                  extra_args=extra_qemu_machine_args)

    # Start the Panda replay
    panda.run_replay(record)

def replay(rootfs):
    p = multiprocessing.Process(target=__replay, args=[rootfs])
    p.start()
    p.join()

    if p.exitcode:
        raise "Replay failed"

# Syzbot bug pages parsing and extraction utilities
def contains_word_case_insensitive(string, word):
  return re.search(rf"\b{word}\b", string, flags=re.IGNORECASE) is not None

def from_syzbot(url, crash_nb=0, reduce_config=True):
    # Allow the argument to be just the bug id - for brevity
    if not url.startswith("https://syzkaller.appspot.com/bug?extid="):
        url = "https://syzkaller.appspot.com/bug?extid=" + url

    # Download the bug page's HTML
    bug_path = cached_download(url, "bug")
    with open(bug_path, "r", encoding="latin-1") as f:
        bug_html = f.read()

    # Extract the 'Crashes' table
    crashes = pd.read_html(io.StringIO(bug_html), match="C repro", extract_links="body")[0]
    if len(crashes) == 0:
        raise Exception("Crashes table is empty")

    # Find the buggy commit hash and the URLs of the reproducer and .config
    buggy_commit = crashes["Commit"][crash_nb][0]
    repro_url = 'https://syzkaller.appspot.com' + crashes['C repro'][crash_nb][1]
    config_url = 'https://syzkaller.appspot.com' + crashes['Config'][crash_nb][1]
    # TODO: Handle Syz reproducers

    # Create a config and a stimulus
    config = Config.from_url(config_url)
    stimulus = Stimulus.from_url(repro_url)

    # To optimize boot-time, disable slow but unnecessary CONFIG options
    if reduce_config:
        # KCov is only useful during fuzzing, this saves 70% of boot-time
        config.disable("KCOV")
        # Slow boots mean that the hung task detector can panic the boot
        config.disable("CONFIG_BOOTPARAM_HUNG_TASK_PANIC")

        # Disale CONFIGs if the bug doesn't contain certain keywords
        disable_rules = [
            # Only keep the sanitizers that reported the bug
            ("kasan",  ["KASAN"]),
            ("ubsan",  ["UBSAN"]),
            ("kmsan",  ["KMSAN"]),
            ("kcsan",  ["KCSAN"]),
            ("kfence", ["KFENCE"]),
            ("rcu",    ["PROVE_RCU"]),
            ("lock",   ["LOCKDEP", "PROVE_LOCKING"]),
            # Disable slow subsystems that don't appear in the backtrace
            ("usb",    ["USB"]),
            ("vivid",  ["VIDEO_VIVID"]),
            # TODO: DEBUG_LIST, DEBUG_PLIST, DEBUG_SG, DEBUG_NOTIFIERS, DEBUG_MAPLE_TREE,
            # DEBUG_IRQFLAGS, DEBUG_ATOMIC_SLEEP, DEBUG_SPINLOCK, DEBUG_MUTEXES,
            # DEBUG_WW_MUTEX_SLOWPATH, DEBUG_RWSEMS, DEBUG_LOCK_ALLOC, DEBUG_TIMEKEEPING,
            # DEBUG_PREEMPT, DEBUG_VM, SOUND, FB, DRM
        ]
        for keyword, configs_to_disable in disable_rules:
            if not contains_word_case_insensitive(bug_html, keyword):
                for cfg in configs_to_disable:
                    config.disable(cfg)

    return Kernel.from_git(config, buggy_commit), Rootfs(stimulus)

# Function tracing capabilities
class CType(Enum):
    VOID = 1
    BOOL = 2
    UINT = 3
    INT = 4
    STR = 5
    PTR = 6

class Func:
    def __init__(self, symbol):
        self.symbol = symbol
        self.ret_type = CType.VOID
        self.arg_names = []
        self.arg_types = []
        self.iid = None

    def add_arg(self, name, t):
        self.arg_names.append(name)
        self.arg_types.append(t)

def __trace(kernel, rootfs, record, trace_path, ignored_addresses, func_map):
    panda = Panda(arch=arch, mem=mem, expect_prompt=expect_prompt, qcow=rootfs.path,
                  extra_args=extra_qemu_machine_args, os_version="linux-64-linux:1.0")

    # Create a Perfetto trace
    trace = Trace()
    tp = trace.packet.add()
    tp.trusted_packet_sequence_id = 1
    tp.sequence_flags = TracePacket.SequenceFlags.SEQ_INCREMENTAL_STATE_CLEARED
    tp.first_packet_on_sequence = True

    # Perfetto packets need unique 64 bit IDs, this generates some
    def uuid64():
        return uuid.uuid4().int>>64

    # Find the address of some interesting functions
    set_task_comm_addr = -1
    switch_to_asm_addr = -1
    for addr, func in func_map.items():
        if func.symbol == "__set_task_comm":
            set_task_comm_addr = addr
        elif func.symbol == "__switch_to_asm":
            switch_to_asm_addr = addr

    # Keep track of Perfetto "groups" and "tracks" (see .proto file) by PID and TID
    process_map = {}
    thread_map = {}
    def get_track(cpu):
        proc = panda.plugins['osi'].get_current_process(cpu)
        proc_uuid = uuid64()
        if not proc.pid in process_map:
            tp = trace.packet.add()
            tp.track_descriptor.uuid = proc_uuid
            tp.track_descriptor.process.pid = proc.pid
            tp.track_descriptor.process.process_name = panda.ffi.string(proc.name).decode('unicode_escape')

            process_map[proc.pid] = tp
        else:
            proc_uuid = process_map[proc.pid].track_descriptor.uuid

        thread = panda.plugins['osi'].get_current_thread(cpu)
        if not thread.tid in thread_map:
            tp = trace.packet.add()
            tp.track_descriptor.uuid = uuid64()
            tp.track_descriptor.parent_uuid = proc_uuid
            tp.track_descriptor.thread.pid = proc.pid
            tp.track_descriptor.thread.tid = thread.tid
            tp.track_descriptor.thread.thread_name = "Thread"

            thread_map[thread.tid] = tp
            # TODO: unwind the stack to backfill functions called before tracing

            return tp.track_descriptor.uuid

        return thread_map[thread.tid].track_descriptor.uuid

    # Keep track of symbol names and source code info by IID
    func_iids_map = {}

    def fill_slice_name(tp, addr, f):
        nonlocal func_iids_map
        iid = func_iids_map.get(addr, None)
        if iid == None:
            iid = len(func_iids_map) + 1

            ev = tp.interned_data.event_names.add()
            ev.iid = iid

            if f != None:
                ev.name = f.symbol

                ev = tp.interned_data.source_locations.add()
                ev.iid = iid
                ev.file_name = ""
                ev.function_name = ""
                ev.line_number = 0
            else:
                ev.name = f"0x{addr:x}"

            func_iids_map[addr] = iid

        tp.track_event.name_iid = iid
        tp.track_event.source_location_iid = iid

    da_name_iids_map = {}
    def addDebugAnnotation(tp, name, val, t):
        if t == CType.VOID:
            return

        da = tp.track_event.debug_annotations.add()

        iid = da_name_iids_map.get(name, None)
        if iid == None:
            iid = len(da_name_iids_map) + 1
            ev = tp.interned_data.debug_annotation_names.add()
            ev.iid = iid
            ev.name = name
            da_name_iids_map[name] = iid
        da.name_iid = iid

        if t == CType.BOOL:
            da.bool_value = val != 0
        elif t == CType.UINT:
            da.uint_value = val
        elif t == CType.INT:
            da.int_value = val
        elif t == CType.STR:
            # TODO: Extract strings
            da.pointer_value = val
        elif t == CType.PTR:
            da.pointer_value = val

    # Track the number of executed instructions, block by block
    n_insns = 0
    @panda.cb_before_block_exec
    def bbe(cpu, tb):
        nonlocal n_insns
        n_insns += tb.icount

    # Load Panda's OSI manually to provide it our custom kernel info file
    panda.load_plugin("osi", args={"disable-autoload": True})
    panda.load_plugin("osi_linux", args={"kconf_file": kernel.info_path, "kconf_group": "linux:1.0:64"})

    # Use OSI to track function calls and returns on a per-thread basis
    panda.load_plugin("callstack_instr", args={"stack_type": "threaded"})

    # Keep track of context switches to associate "flow ids" (arrows in the UI)
    track_is_context_switching = 0
    def track_context_switches(track_uuid, addr, is_call):
        nonlocal f
        nonlocal n_insns
        nonlocal track_is_context_switching

        # On context switch in, end the current arrow
        if track_is_context_switching != 0 and track_is_context_switching != track_uuid:
            tp = trace.packet.add()
            tp.timestamp = n_insns
            tp.track_event.type = TrackEvent.Type.TYPE_INSTANT
            tp.track_event.track_uuid = track_uuid
            tp.trusted_packet_sequence_id = 1
            tp.track_event.terminating_flow_ids.append(1)
            fill_slice_name(tp, addr, f)

            track_is_context_switching = 0

        # On context switch out, start an arrow
        if is_call and addr == switch_to_asm_addr:
            tp = trace.packet.add()
            tp.timestamp = n_insns
            tp.track_event.type = TrackEvent.Type.TYPE_INSTANT
            tp.track_event.track_uuid = track_uuid
            tp.trusted_packet_sequence_id = 1
            tp.track_event.flow_ids.append(1)
            fill_slice_name(tp, addr, f)

            track_is_context_switching = tp.track_event.track_uuid

    @panda.ppp("callstack_instr", "on_call")
    def on_call(cpu, addr):
        nonlocal n_insns
        if addr in ignored_addresses:
            return

        # Create a call (slice begin) trace packet
        tp = trace.packet.add()
        tp.timestamp = n_insns
        tp.track_event.type = TrackEvent.Type.TYPE_SLICE_BEGIN
        tp.track_event.track_uuid = get_track(cpu)
        tp.track_event.category_iids.append(1)
        f = func_map.get(addr, None)
        fill_slice_name(tp, addr, f)
        tp.trusted_packet_sequence_id = 1

        # Add a boolean debug annotation to indicate if running in kernel space
        addDebugAnnotation(tp, "in_kernel", panda.in_kernel(cpu), CType.BOOL)

        # Add args debug annotation if this function has args
        if f != None:
            for i, name in enumerate(f.arg_names):
                # On x86_64, we can read a max of 6 args, only those in registers
                if i >= 6:
                    continue

                val = panda.arch.get_arg(cpu, i)
                addDebugAnnotation(tp, name, val, f.arg_types[i])

        track_context_switches(tp.track_event.track_uuid, addr, True)

    @panda.ppp("callstack_instr", "on_ret")
    def on_ret(cpu, addr):
        nonlocal n_insns
        nonlocal f
        if addr in ignored_addresses:
            return

        # Create a ret (slice end) trace packet
        tp = trace.packet.add()
        tp.timestamp = n_insns
        tp.track_event.type = TrackEvent.Type.TYPE_SLICE_END
        tp.track_event.track_uuid = get_track(cpu)
        tp.trusted_packet_sequence_id = 1

        # Add return debug annotation if this function returns something
        f = func_map.get(addr, None)
        if f != None:
            ret = panda.arch.get_return_value(cpu)
            addDebugAnnotation(tp, "ret", ret, f.ret_type)

        # Handle process renames
        if addr == set_task_comm_addr:
            proc = panda.plugins['osi'].get_current_process(cpu)
            name = panda.ffi.string(proc.name).decode('unicode_escape')
            process_map[proc.pid].track_descriptor.process.process_name = name

        track_context_switches(tp.track_event.track_uuid, addr, False)

    # Start the Panda replay
    panda.run_replay(record)

    # Write the Perfetto trace to disk
    log(f"Writing trace to {record}")
    with open(trace_path, "wb") as f:
        f.write(trace.SerializeToString())
    log("Trace written")

    return trace_path

def trace(kernel, rootfs, record, output="trace"):
    # Some symbols (like sanitizer instrumentations) make the trace a lot bigger
    # and harder to read. Skip them by default. We could make this configurable if
    # inspecting their arguments proves useful to debugging.
    ignored_symbols_re = re.compile(r'kasan_check_range|__kasan_check_|__asan_|__sanitizer_cov_trace_|.*lockdep_')
    ignored_addresses = set()

    # Parse all known ELF symbol tables
    elf_files = [kernel.debug_path, rootfs.busybox_debug_path, rootfs.stimulus_debug_path]
    func_map = {}
    symbol_map = {}
    for elf_file in elf_files:
        with open(elf_file, 'rb') as f:
            log("Parsing " + elf_file + " debug info...")

            result = subprocess.run(['nm', elf_file], stdout=subprocess.PIPE)
            if b"no symbols" in result.stdout:
                continue
            for line in result.stdout.split(b"\n"):
                elements = line.split()
                if len(elements) == 3:
                    address = int(elements[0], 16)
                    name = elements[2].decode('unicode_escape')

                    if re.match(ignored_symbols_re, name):
                        ignored_addresses.add(address)

                    f = Func(name)
                    func_map[address] = f
                    symbol_map[name] = f

    def ctypeFromBtfId(n):
        # TODO: Extract types better from BTF information
        return CType.UINT

    for t in kernel.types:
        if t["kind"] == "FUNC":
            # Only consider symbols we found in our symbols table
            f = symbol_map.get(t["name"], None)
            if f == None:
                continue

            type_id = t["type_id"]
            proto_t = kernel.types[type_id - 1]

            f.ret_type = ctypeFromBtfId(proto_t["ret_type_id"])

            for param in proto_t["params"]:
                f.add_arg(param["name"], ctypeFromBtfId(param["type_id"]))

    p = multiprocessing.Process(target=__trace, args=(kernel, rootfs, record,
                                                      output, ignored_addresses, func_map))
    p.start()
    p.join()

    if p.exitcode:
        raise "Tracing failed"
    return output

# HTTP Server to open a trace in Perfetto
def serve_trace(path):
   log("Starting a RPC server for the trace on :9001 (pre-processing the trace can take time) ...")
   cfg = TraceProcessorConfig(unique_port=False)
   tp = TraceProcessor(trace=path, config=cfg)
   log("You can now open https://ui.perfetto.dev/ and click on 'Yes, use loaded trace'")
   input("Press a key to stop...")

# TODO: Add a wrapper for gdb commands that runs:
#  panda-system-x86_64 -replay /record/repro -nographic -m 1G -s -S -panda checkpoint
#  gdb linux/vmlinux -ex "target remote :1234"
