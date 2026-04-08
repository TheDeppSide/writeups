# 🚩 CTF Writeups & Exploits

Welcome to my personal archive of Capture The Flag (CTF) writeups! This repository is a dump of my solutions, exploit scripts, reverse engineering notes, and the inevitable rabbit holes I fell down along the way. 

Whether it's a clean one-shot ROP chain or a messy script held together by duct tape and `time.sleep(1)`, you'll find it here.

---

## 📂 Repository Layout

To keep things sane, everything is organized by the CTF event, then by the specific challenge. The structure looks like this:

```text
📦 ctf-writeups
 ┣ 📜 README.md                 <-- You are here!
 ┗ 📂 [Event Name]              <-- e.g., ritsec-2026
    ┗ 📂 [Challenge Name]       <-- e.g., doMonkeysSwim
       ┣ 📂 bin                 <-- Challenge attachments (binaries, libc, source code)
       ┣ 📜 solve.py            <-- The final, working exploit script
       ┗ 📜 writeup.md          <-- The step-by-step breakdown and methodology
```

*Note: Binaries and `libc` files are included in the `bin/` directories for archival and reproduction purposes, so you can test the exploits locally.*

---

## 🗺️ The Legend (Writeup Index)

Below is a living index of all the writeups currently in this repository, sorted by event. Click on any challenge name to jump straight to the writeup.

| Event | Category | Challenge | Points | Description | Link |
| :--- | :---: | :--- | :---: | :--- | :---: |
| **RITSEC 2026** | `Pwn` | **doMonkeysSwim** | 23 | Bypassing an off-by-a-bit overflow by executing a stack pivot into `.bss` on a statically linked binary. | [Read Here](./RITSEC_CTF_2026/doMonkeysSwim/writeup.md) |

---

## 🛠️ Toolkit & Environment

For those curious, my typical pwn/rev environment consists of:
* **OS:** Ubuntu
* **Framework:** [pwntools](https://github.com/Gallopsled/pwntools) (Python 3)
* **Debugger:** GDB with [pwndbg](https://github.com/pwndbg/pwndbg)
* **Disassembler/Decompiler:** IDA Pro / Ghidra / Binary Ninja

---
*Have fun!* 👾