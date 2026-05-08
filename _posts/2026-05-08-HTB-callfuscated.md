---
layout: post
title: HTB - callfuscated
date: 2026-05-08
categories:
  - writeup
  - htb
tags:
  - htb
---

They give us an ELF file

![](attachment/Pasted%20image%2020260508184715.png)

I put it in IDA and analyze:

## de-callfuscating

This binary is filled with many trampoline jumps.

![](attachment/Pasted%20image%2020260508184506.png)

Scrolling through, the obfuscation pattern is:

```
call next_block

next_block:
	pop r8
	<real instruction>
	call another_block
```

Note that the `call` instruction does two things: 
- pushes addr of the next instruction onto the stack
- and jumps to the target. 

The `pop r8` discards the *return address* from the stack, allowing the program continue linearly

The obfuscate algo is equivalent to this clean logic:

```
jmp next_block

next_block:
	<real instruction>
	jmp another_block
```

The following script nop-ed the `pop r8` and patched `call` to `jmp` .

```
import struct
import sys

BASE = 0x400000

def target_of_call(buf, off):
    rel = struct.unpack_from("<i", buf, off + 1)[0]
    return BASE + off + 5 + rel


buf = bytearray(open('crackme', "rb").read())

for off in range(len(buf) - 5):
	if buf[off] != 0xE8:
		continue

	target = target_of_call(buf, off)
	target_off = target - BASE

	if 0 <= target_off < len(buf) - 1 and buf[target_off : target_off + 2] == b"\x41\x58":
		buf[off] = 0xE9
		buf[target_off : target_off + 2] = b"\x90\x90"

open('patched_crackme', "wb").write(buf)
print("done")
```

## a vm awaits

IDA handled the `jmp` and got me this clean pseudocode.

It seems this is VM-obfuscated

![](attachment/Pasted%20image%2020260508194813.png)

and the VM handlers are heavily MBA-obfuscated 

![](attachment/Pasted%20image%2020260508200000.png)

In this case, i'll guess its semantics by sampling some pairs `(7,3), (11,6), (16,4)`. These are the pairs that produce unique, distinguishable outputs for each common arithmetic and bitwise operation.

Deduced that:
- `sub_401F18` ~ add
- `sub_4050AA` ~ sub
- `sub_401166` ~ mul
- `sub_4080D6`~ and
- `sub_406E47` ~ or
- `sub_405C1F` ~ xor

### vm reversal

I began by dumping the bytecode.

![](attachment/Pasted%20image%2020260508203453.png)

Then, i replicate the VM behavior

```
import struct
import sys


INPUT_BASE = 0x40F080


def u32(x):
    return x & 0xFFFFFFFF


def hx(x):
    return f"0x{u32(x):08x}"


def pop2(stack):
    b = stack.pop()
    a = stack.pop()
    return a, b

password = "A"*64
data = open("dump", "rb").read()
code = list(struct.unpack("<" + "I" * (len(data) // 4), data))[:0x24A]
mem = {INPUT_BASE + i: c for i, c in enumerate(password.encode() + b"\x00")}

stack = []
pc = 0

while pc < len(code):
    ip = pc
    op = code[pc]
    pc += 1

    if op == 0:
        val = code[pc]
        pc += 1
        stack.append(val)
        msg = f"PUSH {hx(val)}"

    elif op == 1:
        val = stack.pop()
        msg = f"POP {hx(val)}"

    elif op == 2:
        a, b = pop2(stack)
        stack.append(u32(a + b))
        msg = f"ADD {hx(a)} + {hx(b)}"

    elif op == 3:
        a, b = pop2(stack)
        stack.append(u32(a - b))
        msg = f"SUB {hx(a)} - {hx(b)}"

    elif op == 5:
        a, b = pop2(stack)
        stack.append(u32(a * b))
        msg = f"MUL {hx(a)} * {hx(b)}"

    elif op == 6:
        a, b = pop2(stack)
        stack.append(u32(a & b))
        msg = f"AND {hx(a)} & {hx(b)}"

    elif op == 7:
        a, b = pop2(stack)
        stack.append(u32(a | b))
        msg = f"OR  {hx(a)} | {hx(b)}"

    elif op == 8:
        a, b = pop2(stack)
        stack.append(u32(a ^ b))
        msg = f"XOR {hx(a)} ^ {hx(b)}"

    elif op == 9:
        addr = code[pc]
        pc += 1
        stack.append(mem.get(addr, 0))
        msg = f"LOAD_ABS [{addr:#x}]"

    elif op == 10:
        addr = stack.pop()
        val = mem.get(u32(addr), 0)
        stack.append(val)
        ch = f" '{chr(val)}'" if 32 <= val <= 126 else ""
        msg = f"LOAD_PTR [{u32(addr):#x}] -> {val:#x}{ch}"

    else:
        print(f"{ip:04d}: unknown opcode {op:#x}")
        break

    top = hx(stack[-1]) if stack else "<empty>"
    print(f"{ip:04d}: {msg:<35} top={top} stack_depth={len(stack)}")

print()
if stack:
    print(f"final top = {hx(stack[-1])}")
    print("Correct" if u32(stack[-1]) == 0 else "Incorrect")
else:
    print("empty stack")
```

Analyzed the log:

![](attachment/Pasted%20image%2020260508205855.png)

Retrieve the stored xoring values from the dump and we are done

```
print(bytes.fromhex(hex(0x0915033a ^ 0x41414141)[2:]
                    + hex(0x427d7872 ^ 0x11111111)[2:] 
                    + hex(0x30310a00 ^ 0x55555555)[2:]
                    + hex(0x2a052e32 ^ 0x5a5a5a5a)[2:]
                    + hex(0xcff5ecdf ^ 0xaaaaaaaa)[2:]
                    + hex(0x1914031e ^ 0x77777777)[2:]
                    + hex(0xf6f7c6ad ^ 0x99999999)[2:]
                    + hex(0x6c6a524e ^ 0x33333333)[2:]))

```

## flag

nice challenge
`HTB{Sliced_Up_the_Function_4_Ya}`