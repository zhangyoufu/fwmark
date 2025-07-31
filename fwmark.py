#!/usr/bin/env python3
import ctypes.util
import os
import pathlib
import subprocess

class _align_8(ctypes.Structure):
    _fields_ = [
        ('_dummy', ctypes.c_uint64 * 0),
    ]

## union bpf_attr member structures

class bpf_prog_load_attr(ctypes.Structure):
    _anonymous_ = ['_align']
    _fields_ = [
        ('_align', _align_8),
        ('prog_type', ctypes.c_uint32),
        ('insn_cnt', ctypes.c_uint32),
        ('insns', ctypes.c_uint64),
        ('license', ctypes.c_uint64),
        # remaining fields are zeroed by bpf syscall
    ]

class bpf_prog_attach_attr(ctypes.Structure):
    _anonymous_ = ['_align']
    _fields_ = [
        ('_align', _align_8),
        ('target_fd', ctypes.c_uint32),
        ('attach_bpf_fd', ctypes.c_uint32),
        ('attach_type', ctypes.c_uint32),
        # remaining fields are zeroed by bpf syscall
    ]

## bpf syscall number

match os.uname()[4]:
    case 'x86_64':
        __NR_bpf = 321
    case 'aarch64':
        __NR_bpf = 280
    case _:
        raise NotImplementedError
        # if you want to port this script, add syscall number here
        # and make sure bit order in bpf_insn matches

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

## syscall wrapper

def bpf(cmd: int, attr: bpf_prog_load_attr | bpf_prog_attach_attr) -> int:
    return libc.syscall(__NR_bpf, cmd, ctypes.byref(attr), ctypes.sizeof(attr))

## bpf command constants

BPF_PROG_LOAD = 5
BPF_PROG_ATTACH = 8

## bpf attach type constants

BPF_CGROUP_INET_SOCK_CREATE = 2

## bpf syscall helpers

def bpf_prog_load(prog_type, instructions, license='GPL'):
    bpf_prog = bytearray().join(bytes(insn) for insn in instructions)
    insns = (ctypes.c_ubyte * len(bpf_prog)).from_buffer(bpf_prog)
    if isinstance(license, str):
        license = license.encode()
    license = ctypes.create_string_buffer(license)
    attr = bpf_prog_load_attr(
        prog_type=prog_type,
        insn_cnt=len(instructions),
        insns=ctypes.addressof(insns),
        license=ctypes.addressof(license),
    )
    ret = bpf(BPF_PROG_LOAD, attr)
    if ret == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return ret

def bpf_prog_attach(prog_fd, target_fd, attach_type):
    attr = bpf_prog_attach_attr(
        target_fd=target_fd,
        attach_bpf_fd=prog_fd,
        attach_type=attach_type,
    )
    ret = bpf(BPF_PROG_ATTACH, attr)
    if ret == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

## BPF register constants

BPF_REG_0 = 0
BPF_REG_1 = 1

## BPF  instruction classes

BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05

## BPF_SIZE

BPF_W = 0x00

## BPF_MODE

BPF_MEM = 0x60

## BPF_SRC

BPF_K = 0x00
BPF_X = 0x08

## ???

BPF_EXIT = 0x90
BPF_MOV = 0xb0

## BPF instructions

class bpf_insn(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('code', ctypes.c_ubyte),
        ('dst_reg', ctypes.c_ubyte, 4), # bit-order only tested on amd64
        ('src_reg', ctypes.c_ubyte, 4),
        ('off', ctypes.c_int16),
        ('imm', ctypes.c_int32),
    ]

BPF_EXIT_INSN = lambda: bpf_insn(
    code=BPF_JMP | BPF_EXIT,
)

BPF_MOV32_IMM = lambda dst, imm: bpf_insn(
    code=BPF_ALU | BPF_MOV | BPF_K,
    dst_reg=dst,
    imm=imm,
)

BPF_STX_MEM = lambda size, dst, src, off: bpf_insn(
    code=BPF_STX | size | BPF_MEM,
    dst_reg=dst,
    src_reg=src,
    off=off,
)

## BPF program types

BPF_PROG_TYPE_CGROUP_SOCK = 9

## BPF context

class bpf_sock(ctypes.Structure):
    _fields_ = [
        ('bound_dev_if', ctypes.c_uint32),
        ('family', ctypes.c_uint32),
        ('type', ctypes.c_uint32),
        ('protocol', ctypes.c_uint32),
        ('mark', ctypes.c_uint32),
        ('priority', ctypes.c_uint32),
        ('src_ip4', ctypes.c_uint32),
        ('src_ip6', ctypes.c_uint32 * 4),
        ('src_port', ctypes.c_uint32),
        ('dst_port', ctypes.c_uint32),
        ('dst_ip4', ctypes.c_uint32),
        ('dst_ip6', ctypes.c_uint32 * 4),
        ('state', ctypes.c_uint32),
        ('rx_queue_mapping', ctypes.c_int32),
    ]

## /proc/mounts

def read_mangled_path(s, escape=b' \t\n\\'):
    if not isinstance(s, bytes):
        raise TypeError('mangled path should be byte string')
    if not isinstance(escape, bytes):
        raise TypeError('escape charset should be byte string')
    if b'\\' not in escape:
        raise ValueError('escape charset does not contain backslash')
    result = bytearray()
    it = iter(s)
    for x in it:
        if x in escape:
            break
        if x == 0x5C: # backslash
            try:
                escape_sequence = bytes(next(it) for i in range(3))
            except StopIteration:
                raise ValueError('short read in escape sequence')
            for x in escape_sequence:
                if x not in b'01234567':
                    raise ValueError('invalid escape sequence')
            x = int(escape_sequence, 8)
            if x > 255:
                raise ValueError('invalid escape sequence')
        result.append(x)
    return bytes(result)

def find_all_cgroup2_mounts():
    with open('/proc/mounts', 'rb') as f:
        return [
            pathlib.Path(os.fsdecode(read_mangled_path(line[8:])))
            for line in f
            if line.startswith(b'cgroup2 ')
        ]

## /proc/self/cgroup

def get_self_cgroup():
    with open('/proc/self/cgroup', 'rb') as f:
        for line in f:
            if line.startswith(b'0::/'):
                return pathlib.PurePath(os.fsdecode(line[4:-1]))
    raise RuntimeError('unable to get cgroup hierarchy for current process')

def get_self_slice():
    dot = pathlib.PurePath('.')
    path = get_self_cgroup()
    while path.suffix != '.slice':
        if path == dot:
            raise RuntimeError('unable to find systemd.slice for current process')
        path = path.parent
    return path

## main

def main():
    import argparse

    ## parse arguments
    parser = argparse.ArgumentParser(description='run program in a new cgroup with specified fwmark')
    parser.add_argument('--cgroup2', type=pathlib.Path, default=None, help='cgroup2 mountpoint, usually under /sys/fs/cgroup')
    parser.add_argument('fwmark', type=lambda s: int(s, 0), help='fwmark to be applied')
    parser.add_argument('command', nargs=argparse.REMAINDER, help='command to be executed (default to $SHELL if omitted)')
    args = parser.parse_args()

    ## check arguments
    if not 0 <= args.fwmark <= 2**32-1:
        raise ValueError('invalid fwmark')
    if not args.command:
        args.command = [os.environ['SHELL']]

    ## determine cgroup2 mountpoint
    mounts = find_all_cgroup2_mounts()
    if args.cgroup2 is None:
        if len(mounts) == 1:
            args.cgroup2 = mounts[0]
        elif len(mounts) == 0:
            raise RuntimeError('no cgroup2 mountpoint available')
        else:
            raise RuntimeError('multiple cgroup2 mountpoint available, choose one via command line argument')
    else:
        if args.cgroup2 not in mounts:
            raise RuntimeError(f'{arg.cgroup2} is not a cgroup2 mountpoint')

    ## create cgroup (random systemd.scope under current systemd.slice)
    systemd_scope_name = f'fwmark-{args.fwmark:08X}-{os.urandom(8).hex()}.scope'
    systemd_slice_path = get_self_slice()
    cgroup_path = args.cgroup2 / systemd_slice_path / systemd_scope_name
    cgroup_path.mkdir(mode=0o755)
    cgroup_fd = os.open(cgroup_path, os.O_RDONLY | os.O_DIRECTORY)

    ## load bpf program
    bpf_prog = [
        BPF_MOV32_IMM(BPF_REG_0, args.fwmark),
        BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, bpf_sock.mark.offset),
        BPF_MOV32_IMM(BPF_REG_0, 1),
        BPF_EXIT_INSN(),
    ]
    bpf_prog_fd = bpf_prog_load(BPF_PROG_TYPE_CGROUP_SOCK, bpf_prog)

    ## attach bpf program to cgroup
    bpf_prog_attach(bpf_prog_fd, cgroup_fd, BPF_CGROUP_INET_SOCK_CREATE)

    ## bind-mount /etc/resolv.conf
    resolv_conf_path = f'/etc/fwmark/resolv.conf/{args.fwmark}'
    if hasattr(os, 'unshare') and os.path.exists(resolv_conf_path):
        os.unshare(os.CLONE_NEWNS)
        mountpoint = subprocess.check_output(['stat', '--printf', '%m', '/etc/resolv.conf'])
        subprocess.check_call(['mount', '--make-slave', mountpoint])
        subprocess.check_call(['mount', '--no-canonicalize', '--bind', resolv_conf_path, '/etc/resolv.conf'])
        subprocess.check_call(['mount', '--make-shared', mountpoint]) # slave,shared

    ## execute command
    os.environ['FWMARK'] = str(args.fwmark)
    os.execlp(
        'systemd-run',
        'systemd-run',
        '--quiet',
        '--collect',
        f'--slice={systemd_slice_path.name}',
        '--scope',
        f'--unit={systemd_scope_name}',
        *args.command,
    )

if __name__ == '__main__':
    main()
