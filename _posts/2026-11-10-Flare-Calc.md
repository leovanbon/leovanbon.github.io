---
layout: post
title: FlareCalc
image: /attachment/flarecalc-preview.png
date: 2026-11-10
categories:
  - writeup
  - flare-on
tags:
  - flare-on
---

I got a prize in this year's FLARE-On, 
but all i did was slop my way through it 💀

![](attachment/Pasted%20image%2020261110212617.png)

To give the medal some meaning, I put in the effort to reproduce the solution to this one challenge. Took me some time, though I learnt quite a few things along the way.

![426](attachment/Pasted%20image%2020261110213658.png)
# 7 - FlareCalc

![](attachment/Pasted%20image%2020261026151135.png)

## calculator

Welp, I was given a calculator `FlareCalc.exe`.

![](attachment/Pasted%20image%2020261026151232.png)

### find WndProc

My first goal was to locate the window procedure—`lpfnWndProc`.
I found `CreateWindowExW` in the imports and checked its xrefs:

![](attachment/Pasted%20image%2020261026151757.png)

![](attachment/Pasted%20image%2020261026151918.png)

Following the xrefs of `hInstance` led me here. This handle identifies the executable module and is used when registering the window class and creating windows:

![](attachment/Pasted%20image%2020261026151959.png)

Inside `sub_140006BE0`, I found the window class registration:

![](attachment/Pasted%20image%2020261026152017.png)

That gave me the [window-procedure function](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nc-winuser-wndproc):

```
sub_140003B20(HWND hWndParent, UINT a2, WPARAM a3, __int64 *a4)
```

![](attachment/Pasted%20image%2020261026171732.png)

### display updates

I checked the refs of `hWnd` at `0x1400E9230`. This is the handle of the child `EDIT` control that displays the input and result, separate from the main window handle.

It is passed to `SetWindowTextW` and `SetWindowTextA`. I switched to dynamic analysis, set breakpoints at these two APIs, and tested the calc features to map the calls.

![](attachment/Pasted%20image%2020261027142613.png)

I mapped these calls:

| call addrs  | trigger                                           |
| :---------- | :------------------------------------------------ |
| 0x140004359 | refreshes the display after pressing `0-9`              |
| 0x1400045A4 | clears the current calculation and displays `0`       |
| 0x140004775 | displays the `NOT` bitwise-complement (`~`) result |
| 0x140005695 | displays the arithmetic result                     |
| 0x140005A25 | displays the selected operation                    |

Pressing Backspace also triggers a call at `0x1400061DC`. So far, these were pretty much all basic calculator features.

I was left with three calls at `0x140003F3F`, `0x140003FDF`, and `0x1400054EE`.

### explain unexplained calls

I started with `0x140003FDF` because IDA showed a constant `L"0"` here:

![](attachment/Pasted%20image%2020261027144512.png)

I noticed that the check on `a3` matched the `C` button check at `0x1400045A4`:

![](attachment/Pasted%20image%2020261027144810.png)

My guess was that this cleared the display in a special mode controlled by `dword_1400E8F00`.

![](attachment/Pasted%20image%2020261027154644.png)

Message code `0x4A` is `WM_COPYDATA`. This branch receives text sent by another part of the program. Let’s follow that lead to find the sender.

From window creation, I already had the class name and window title. `FindWindowW` can locate the main calculator window using those strings.

![](attachment/Pasted%20image%2020261027160736.png)

I checked the string xrefs and found this in `sub_1400026B0`:

![](attachment/Pasted%20image%2020261027161259.png)

Scrolling up a bit, I spotted `843*952`. I gave it a cheap try.

![](attachment/Pasted%20image%2020261027162143.png)

lol

![](attachment/Pasted%20image%2020261027162250.png)

It gave me scrolling rickroll lyrics. I expected a timer to drive the animation through repeated `SetWindowText` calls.

*I enabled the breakpoints again and confirmed the two roles: `0x140003F3F` updates the scrolling text on timer ticks, while `0x140003FDF` handles `C` in scrolling mode, stops the timer, and sets the display to 0.*

Now, back to the `=` handler to see how the expression reaches that callback.

From the button creation code, I knew the ID for `=` was `214`. That led me to the start of the handler:

![](attachment/Pasted%20image%2020261030230705.png)

I noticed some expressions being loaded into stack variables and inspected them at runtime:

![](attachment/Pasted%20image%2020261030233857.png)

They were `843*952`, `931-482`, `525+193`, and `742*186`. Back in IDA, I found this repeating pattern:


![](attachment/Pasted%20image%2020261031000628.png)

`sub_140001130` compares the two buffers after their lengths have been checked; a return value of zero means they match. For `525+193`, `742*186`, and `931-482`, the matching branch decrypts a message and jumps to `LABEL_315`.

(The `843*952` match takes a separate path: it schedules `sub_1400026B0`, which decrypts the lyrics and sends them through `WM_COPYDATA`.)

![](attachment/Pasted%20image%2020261031020429.png)

*That explained the `SetWindowTextW` call at `0x1400054EE`: it displays the decoded message for those three expression matches.*

I tried `525+193`, and this was what I got.

![](attachment/Pasted%20image%2020261031002754.png)

I tried the other expressions, but none gave me the real flag, and following their execution paths gave me no clues. So I went back to the `=` handler.

### = handler

![](attachment/Pasted%20image%2020261031153320.png)

I checked the calculation logic:

![](attachment/Pasted%20image%2020261031161450.png)

Inside `sub_140003570`, I found an array of function pointers loaded into stack variables.

![](attachment/Pasted%20image%2020261031161800.png)

Further down, I found this call:

![](attachment/Pasted%20image%2020261031161858.png)

So it selects the function for the arithmetic operation and executes it on two operands.

![](attachment/Pasted%20image%2020261031175443.png)

Back in `sub_140003A20`, `sub_140007690` stores the results in the history at `qword_1400E9238`.

### results history

![](attachment/Pasted%20image%2020261031224348.png)

I checked the xrefs of `qword_1400E9238`, but nothing seemed special.
I noticed that `0x1400E9238 + 0x8 = 0x1400E9240`, so I checked `qword_1400E9240` for more information.

![](attachment/Pasted%20image%2020261031224916.png)

There it was: the same formula used when storing the results. `sub_140002A90` appeared just once, as an exception handler in `sub_140003A20`.

![](attachment/Pasted%20image%2020261031225521.png)

The handler expects exception code `0xC000008E`, which is `EXCEPTION_FLT_DIVIDE_BY_ZERO`.

 ![](attachment/Pasted%20image%2020261031231123.png)

*Why would a divide-by-zero handler check the calculation history?*

Further down, I saw `sub_140007690` called again to copy the history into a local variable. From this call, I could infer what the fields represented:

![](attachment/Pasted%20image%2020261102183249.png)

Following that pattern, I found another copy:

![](attachment/Pasted%20image%2020261102184214.png)


![](attachment/Pasted%20image%2020261102184601.png)

Then I found these checks:

![](attachment/Pasted%20image%2020261102232606.png)

I confirmed through dynamic analysis that:

- The newest-value check is `0x1D09AFAD ^ 0x1D8DF040 = 8675309`
- The second-newest is `0x18CFC3C6 ^ 0x1D8DF040 = 88224646`
- The third-newest is `(0x1C527F9B ^ 0x1D8DF040) / 10000000 = 3.1428571`

*It uses `cvttsd2si`, so I expected entering those decimal values directly to work.*

### first stage done?

So I filled the history with these values and triggered the exception. The calc loaded some more DLLs.

![](attachment/Pasted%20image%2020261103093324.png)

`bp LoadLibraryA` and `bp LoadLibraryW`

![](attachment/Pasted%20image%2020261103124759.png)

I followed the address in the memory map and saw that the region was not backed by any file.

![](attachment/Pasted%20image%2020261103124943.png)

`bp VirtualAlloc`

![](attachment/Pasted%20image%2020261103125126.png)

The call was at `140001EAD`.

![](attachment/Pasted%20image%2020261103140933.png)

The resolved APIs are:

0. `GetModuleFileNameW`
1. `CreateFileW`
2. `SetFilePointer`
3. `ReadFile`
4. `VirtualAlloc`
5. `CloseHandle`
6. `TrySubmitThreadpoolCallback`

With that, I identified the APIs used in `sub_1400019D0`. It allocates memory and reads a payload of `0x8149D` bytes into it.

![](attachment/Pasted%20image%2020261103164916.png)

It then makes this call at `140001F8D`

![](attachment/Pasted%20image%2020261103165148.png)

passing these arguments:

![](attachment/Pasted%20image%2020261108122802.png)

Summarize, the path to hidden loader is:
```
0x140003B20 - Window procedure

```

Let's dive into the shellcode.

## shellcode

I dumped the payload.

![](attachment/Pasted%20image%2020261106104926.png)
lol

I loaded it into IDA and set the compiler options to Windows x64.

![](attachment/Pasted%20image%2020261107145910.png)

Then I defined `sub_6D3A` (the entry point called by the calc).

![](attachment/Pasted%20image%2020261107150531.png)

It looked kinda clean.

![](attachment/Pasted%20image%2020261107150547.png)

### api provider

Back at the `LoadLibraryA` breakpoint, I traced the call to offset `D5A3`.

![](attachment/Pasted%20image%2020261107152148.png)

`v22` is the resolved pointer to `LoadLibraryA`. Let’s see how it gets filled:

![](attachment/Pasted%20image%2020261107152917.png)

The call has the form `sub_D7EA(dll, hash, &dest, 0)`. I set a breakpoint at the return, logged the resolved APIs, and profited:

`API={a:[[rsp+18]]} caller={a:[rsp]}`

![](attachment/Pasted%20image%2020261107172929.png)

I watched the log roll, then set `bp socket` and ran until return:

![](attachment/Pasted%20image%2020261107174601.png)

It seemed to require admin privileges, so I tried again with elevated x64dbg. This time, two `socket` calls succeeded.

They were an IPv6 UDP socket, `socket(23, 2, 0)`, and a raw IPv4 socket, `socket(2, 3, 0)`.

`recv` also showed up in the log. I set a breakpoint there, which led me to `F354` in `sub_DB36`, which looked like an API dispatcher:

![](attachment/Pasted%20image%2020261108105400.png)

The arguments come from fixed offsets in `v36`, and the result goes back into the same block. Let’s follow that pointer.

### flar on the heap

![](attachment/Pasted%20image%2020261108110015.png)

The block starts with `FLAR` and sits on the heap.

In the static analysis, I found this at the start of the API dispatcher:

![](attachment/Pasted%20image%2020261108110832.png)

Inside, we have:

![](attachment/Pasted%20image%2020261108122454.png)

It scans the heap for a `FLAR` block. Several functions call it on entry.

One of those xrefs was in `sub_97BE`.

![](attachment/Pasted%20image%2020261108123214.png)

`sub_97BE` runs early and creates the block if it is missing. The other functions reuse it through the heap scan. So this is the shared context.

Keep these function offsets handy—we’ll encounter them throughout the shellcode.

### icmp packet

Now, back to `recv` to see how the received data is processed. The breakpoint hit again:

![](attachment/Pasted%20image%2020261108143542.png)

I saved the buffer pointer at `recv` entry. After it returned with a positive byte count, I set `bpmrange <packet ptr>, eax, r` to catch the next read.

The memory breakpoint hit:

![](attachment/Pasted%20image%2020261108172556.png)

Another stub, called from `sub_113AE`. I dumped it into IDA and matched the accesses against the [IPv4 header layout](https://en.wikipedia.org/wiki/IPv4#Packet_structure), since this was the raw socket.

![](attachment/Pasted%20image%2020261108222447.png)

It checks for an ICMP Echo Request, skips the IP and ICMP headers, then checks for `FLAR` at the start of the payload.

![](attachment/Pasted%20image%2020261108225625.png)

![](attachment/Pasted%20image%2020261109163524.png)

Next, it hashes the string at payload offset `10` and compares the result with `ctx + 165`.

I traced the checker back through `sub_113AE` to `sub_6D3A`. Here is where `ctx + 165` gets initialized:

![](attachment/Pasted%20image%2020261109003523.png)

At runtime, the string was `8675309-88224646-31428571`. Those calculator values again.

![](attachment/Pasted%20image%2020261109004657.png)

So far, we have this layout for the custom ICMP payload:

| offset | size     | what                                                |
| :----- | :------- | :-------------------------------------------------- |
| `+0`   | 4 bytes  | `FLAR`                                              |
| `+4`   | 4 bytes  | *not checked*                                       |
| `+8`   | 2 bytes  | *not checked, but passed to the API dispatcher* |
| `+10`  | Variable | password string; added a null terminator            |

I set a hardware breakpoint: `bph <packet ptr>+9, r, 1`

![](attachment/Pasted%20image%2020261109155050.png)

and tried sending a packet from my host machine:

```python
import socket, struct, sys

target = "192.168.122.104"  # win vm addr
callback = "192.168.122.1"  # my virbr0 addr
port = 4444
password = b"8675309-88224646-31428571"


def checksum(data):
    data += b"\0" * (len(data) % 2)
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


# I guessed these fields were an IP address and port.
payload = b"FLAR" + socket.inet_aton(callback) + struct.pack("!H", port)
payload += password + b"\0"

header = struct.pack("!BBHHH", 8, 0, 0, 12345, 1)
header = struct.pack("!BBHHH", 8, 0, checksum(header + payload), 12345, 1)
icmp = header + payload

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.sendto(icmp, (target, 0))
s.close()
print("sent")
```

The hardware breakpoint hit in the packet checker again. This time, I followed the call to the API dispatcher:

![](attachment/Pasted%20image%2020261109144100.png)

The API is `ntohs`: it converts the two bytes at payload offset `+8` from network byte order. So that field is the port.

![](attachment/Pasted%20image%2020261109155425.png)

After stepping out through the calls, I traced the checker to the call at payload offset `7BDC`. The surrounding loop receives packets until one passes the checks:

![](attachment/Pasted%20image%2020261109160448.png)

Continuing execution brought me to `7F72`, after `socket(2, 1, 6)`. This creates an IPv4 TCP socket. The API log (set up earlier) then showed `connect` (*nice, new progress*).

Let’s break there and inspect the destination:

![](attachment/Pasted%20image%2020261109165751.png)

The dispatcher uses the local IP when building the connection address, ignoring the IP from the packet. I patched the destination to my Linux host: `C0 A8 7A 01` (`192.168.122.1`), started `nc -lvnp 4444` (port `4444` to match the ICMP packet), and continued.

![](attachment/Pasted%20image%2020261109170110.png)

There we go.

### tcp dispatching

The program waited for input. I typed into `nc` and caught another `recv`. This one reads a single byte into `v6`, which selects a handler in the TCP command dispatch loop:

![](attachment/Pasted%20image%2020261109171951.png)

I focused on the large `0x33` handler.

![](attachment/Pasted%20image%2020261110181845.png)

It calls `recv` again, this time reading one byte into `v7`.

The received byte, `v7[0]`, is then passed to `sub_113AE`, along with the value at `ctx + 73` and a pointer to `ctx + 41`.

After the call succeeds, its output replaces the value at `ctx + 73`, which becomes the first argument on the next call. If it reaches `4485`, execution enters what looks like the victory branch below.

I tried forcing the exit ID, but that wasn’t enough—the branch also uses the state at `ctx + 41`.

The `0x10` handler resets `ctx + 73` to `52090` and clears 32 bytes at `ctx + 41`.

![](attachment/Pasted%20image%2020261110181751.png)

So this looks like a game: each input updates the current position, while the buffer carries state between steps.

### stubs launcher

From the earlier traces, I recognized `sub_113AE`: both the `recv` wrapper and the ICMP checker ran through it. Now the `0x33` handler uses it too. Let’s see how it selects and executes those stubs.

![](attachment/Pasted%20image%2020261110153217.png)

`sub_10F56` reconstructs the record for the indirect call. After execution, `sub_11722` wipes the buffer.

![](attachment/Pasted%20image%2020261110154936.png)

Inside `sub_10F56`, the identified APIs help explain the flow. It finds the encoded record, copies it into a temporary buffer, XOR-decodes it, and removes the inserted junk bytes. The resulting buffer is what `sub_113AE` executes:

![](attachment/Pasted%20image%2020261110165414.png)

And then:

![](attachment/Pasted%20image%2020261110162813.png)

I broke at `shellcode_base + 0x10FD6`, just after the container lookup returned, then dumped `RAX` using the length at `[RSP+48]`:

```text
savedata "C:\Users\mouse\Desktop\container.bin", rax, dword:[rsp+48]
```

With the container dumped and the key recovered, I reproduced the decoder in Python *(my codex friend did this, I was fed up atp)*:

``` python
import hashlib
import sys
from pathlib import Path

key = b"8675309-88224646-31428571" # yes, still those calculator results
data = Path("container.bin").read_bytes()
outdir = Path("stubs")


def read_field(pos):
    size = data[pos + 1]
    pos += 2
    if size & 0x80:
        width = size & 0x7f
        size = int.from_bytes(data[pos:pos + width], "big")
        pos += width
    return pos, pos + size


def advance(seed):
    return (seed * 1103515245 + 12345) & 0xffffffff


def decode(record_id, encoded):
    digest = hashlib.md5(key + record_id.to_bytes(4, "little")).digest()
    seed = 0
    for byte in digest:
        seed = (31 * seed + byte) & 0xffffffff

    plain = bytearray(encoded)
    for i in range(len(plain)):
        seed = advance(seed)
        plain[i] ^= seed & 0xff

    seed = 9271
    for byte in key:
        seed = (129 * seed + byte) & 0xffffffff

    result = bytearray()
    pos = 0
    while pos < len(plain):
        result.append(plain[pos])
        seed = advance(seed)
        skip = seed % 3 + 1
        for _ in range(skip):
            seed = advance(seed)
        pos += 1 + skip
    return result

pos, end = read_field(0)
outdir.mkdir(parents=True, exist_ok=True)
count = 0
while pos < end:
    entry, next_entry = read_field(pos)
    start, stop = read_field(entry)
    record_id = int.from_bytes(data[start:stop], "big")
    start, stop = read_field(stop)
    (outdir / f"{record_id}.bin").write_bytes(decode(record_id, data[start:stop]))
    pos = next_entry
    count += 1

print(f"Decoded {count} records into {outdir}")
```

## kind of a directed graph

The extractor produced 1,035 entries.

![](attachment/Pasted%20image%2020261110183131.png)

We start at node `52090`, with arguments `(tcp_byte, ctx + 41, 0)`. Let’s take a look:

![](attachment/Pasted%20image%2020261110190029.png)

I checked a few more stubs. Most are 128–188 bytes and follow the same pattern: take an input byte, modify the shared state, and return the next node ID. They also contain the same delay loop.

`3821.bin` came out as garbage because I decoded an entry that already contains plaintext main shellcode. I removed it along with the helper and flag-related entries (`3822–3829`, `4485`, and `9990`), leaving 1,024 maze nodes in `stubs/`. The search treats `4485` as the exit without executing it.
 
That gives us a directed graph. Each input byte selects a transition, but we also need to carry the updated state along the path. The starting point is `52090` with 32 zero bytes; the target is `4485`.

### unicorn & dfs 

Each node accepts one byte, so there are 256 candidates to try. Most return IDs that don’t exist. DFS follows the valid transitions while carrying a separate copy of the state for each branch.

The delay loop always leaves the sum at `0x6A4AE6E0`, so the emulator supplies its final values and continues after it. I bounded the search at 32 steps.

We can emulate each step with Unicorn:

```python
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *

# setting up the emulator
stub_base, stack, ctx41_addr, return_addr = 0x1000000, 0x2000000, 0x3000000, 0x4000000
u = Uc(UC_ARCH_X86, UC_MODE_64)

for addr, size in [(stub_base, 0x1000000), (stack, 0x10000),
                   (ctx41_addr, 0x1000), (return_addr, 0x1000)]:
    u.mem_map(addr, size)

u.reg_write(UC_X86_REG_RDX, ctx41_addr)
u.reg_write(UC_X86_REG_RSP, stack + 0x8000)

initial_regs = u.context_save()

# Find the delay loops
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
def find_hook_points(instructions):
    for j, ins in enumerate(instructions):
        if j >= 7 and ins.mnemonic == 'jb' and ins.operands[0].imm < ins.address:
            if instructions[j - 7].mnemonic == 'add' and instructions[j - 7].op_str == 'ecx, eax':
                delay_loops[ins.operands[0].imm] = (ins.address + ins.size,
                    instructions[j - 6].operands[0].mem.disp, instructions[j - 3].operands[0].mem.disp)


# Load the stubs and locate their delay loops
stubs = {int(p.stem): p.read_bytes() for p in Path('stubs').glob('*.bin')}
stub_addrs, delay_loops = {}, {}
for i, node_id in enumerate(sorted(stubs)):
    addr = stub_base + i * 0x1000
    stub_addrs[node_id] = addr
    u.mem_write(addr, stubs[node_id])
    find_hook_points(list(md.disasm(stubs[node_id], addr)))

# Replace the million-iteration loop with its final values
def hook(u, addr, size, _):
    if addr in delay_loops:
        end, total, counter = delay_loops[addr]
        sp = u.reg_read(UC_X86_REG_RSP)
        u.mem_write(sp + total, struct.pack('<I', 0x6a4ae6e0))
        u.mem_write(sp + counter, struct.pack('<I', 1000000))
        u.reg_write(UC_X86_REG_EAX, 1000000)
        u.reg_write(UC_X86_REG_ECX, 0x6a4ae6e0)
        u.reg_write(UC_X86_REG_EFLAGS, 0x246)
        u.reg_write(UC_X86_REG_RIP, end)

u.hook_add(UC_HOOK_CODE, hook)

# run
def run(node_id, input_byte, ctx41):
    u.context_restore(initial_regs)
    u.mem_write(ctx41_addr, ctx41)
    u.mem_write(stack, bytes(0x10000))
    u.mem_write(stack + 0x8000, struct.pack('<Q', return_addr))
    u.reg_write(UC_X86_REG_RCX, input_byte)
    u.emu_start(stub_addrs[node_id], return_addr, count=1000)
    if u.reg_read(UC_X86_REG_RIP) != return_addr:
        raise RuntimeError(f'Node {node_id} did not return')
    return u.reg_read(UC_X86_REG_EAX), bytes(u.mem_read(ctx41_addr, 32))


def dfs(node_id=52090, ctx41=bytes(32), inputs=b''):
    if node_id == 4485:
        return inputs
    if len(inputs) >= 32:  # search depth limit
        return
    for input_byte in range(256):
        next_id, next_ctx41 = run(node_id, input_byte, ctx41)
        if next_id in stubs or next_id == 4485:
            result = dfs(next_id, next_ctx41, inputs + bytes([input_byte]))
            if result:
                return result

print(dfs())
```

Ran it:

![](attachment/Pasted%20image%2020261110211303.png)

I sent the recovered input with `0x33` before each byte:

![](attachment/Pasted%20image%2020261110211606.png)

## flag

`t3mplat3s_asn_and_j1t_0h_my@flare-on.com`

![](attachment/Pasted%20image%2020261110211658.png)

*nice challenge*

p/s: the `asn` in the flag refers to [ASN.1](https://en.wikipedia.org/wiki/ASN.1#Example), which defines the structure of the containter holding all the encoded stubs/records
