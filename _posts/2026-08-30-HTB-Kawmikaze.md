---
layout: post
title: HTB - Kawmikaze
date: 2026-08-31
categories:
  - writeup
  - htb
tags:
  - htb
  - malware
---
	Following the recent breach at ShanoCorp, the Incident Response team identified additional affected hosts within the environment. A suspicious binary was recovered from one of the systems. Investigators determined that the endpoint protection solution had been disabled, and correlation with Prefetch artifacts confirmed the sample was executed shortly afterward. Preliminary Event Log analysis indicates the process was executed with elevated privileges.

The challenge artifact is `Kawmikaze`, a PE file. We are given 14 tasks; my approach was to understand the binary as a whole first, then answer the tasks afterward.

## Init phase

I loaded the binary into IDA and noticed that the PE contains several TLS callbacks. These callbacks run before the `main` function.

![](attachment/Pasted%20image%2020260830204205.png)

TLS callbacks are legitimate initialization hooks, but malware authors and software protectors often use them for **stealth and anti-debugging**. Let's take a look at them.

The first callback checks for opcode `0xCC`, the `INT3` software-breakpoint instruction. This is a classic debugger check.

![](attachment/Pasted%20image%2020260830204430.png)

The next TLS callback uses Windows Filter Manager enumeration APIs to check minifilter drivers, which are commonly used by security products.

![](attachment/Pasted%20image%2020260831001156.png)

Running with elevated `x64dbg` showed that the target driver is `PROCMON` (Process Monitor).

![](attachment/Pasted%20image%2020260831001325.png)

The last TLS callback mangles `sub_140001570` if the target driver is present.

![](attachment/Pasted%20image%2020260831001719.png)

---

Then I moved on to `main`.

There is an `IsDebuggerPresent()` call here, so I enabled ScyllaHide in `x64dbg`.

![](attachment/Pasted%20image%2020260831074639.png)

## API resolver

A familiar scene appears at `sub_1400013E0`.

![](attachment/Pasted%20image%2020260831082125.png)

A breakpoint before the `ret` reveals everything cleanly.

![](attachment/Pasted%20image%2020260831082020.png)

I renamed the variables and proceeded to the next part.
 
## Registry as storage

![](attachment/Pasted%20image%2020260831101131.png)

A breakpoint at the `RegCreateKeyExW` call reveals the registry key and value:

![](attachment/Pasted%20image%2020260831115548.png)

So, after `sub_140001570` returns, we have this:

![](attachment/Pasted%20image%2020260831114515.png)

## WMI persistence

`sub_140001720` follows the usual COM setup flow for [creating a WMI application](https://learn.microsoft.com/vi-vn/windows/win32/wmisdk/creating-a-wmi-application-using-c-).

![](attachment/Pasted%20image%2020260831121823.png)

Note that `ROOT\subscription` is a special built-in WMI namespace used to store permanent WMI event subscriptions.

After connecting to WMI, the program creates three WMI objects:

### `__EventFilter`

![](attachment/Pasted%20image%2020260831123459.png)

The filter is the trigger. Here it watches for new `Win32_LogonSession` instances, so the subscription fires when a user logs on through one of the selected logon types.

```wql
SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogonSession' AND (TargetInstance.LogonType = 2 OR TargetInstance.LogonType = 3 OR TargetInstance.LogonType = 7 OR TargetInstance.LogonType = 10 OR TargetInstance.LogonType = 11) 
```

### `CommandLineEventConsumer`

![](attachment/Pasted%20image%2020260831123955.png)

The consumer is the action. Its `CommandLineTemplate` property contains the command that WMI will launch when the filter condition matches.

```powershell
powershell.exe -nop -w hidden -EncodedCommand <encoded_payload>
```

### `__FilterToConsumerBinding`

![](attachment/Pasted%20image%2020260831124043.png)

The binding links the trigger to the action. Once this object is written, WMI knows that the logon-session filter should execute the command-line consumer.

Together, these objects form a permanent WMI event subscription: the malware does not execute the PowerShell command directly here, but registers it so WMI can run it later.

This [reference](https://0xdbgman.github.io/posts/persistence-the-art-of-staying-in/#phase-5-wmi-event-subscriptions--the-fileless-ghost) explains the persistence technique in more detail.

## Final stage

The PowerShell command can be decoded with:

```python
import base64; print(base64.b64decode(encoded_payload).decode("utf-16le"))
```

The recovered command reads `HKCU\Software\Win32Cache\State`, Base64-decodes it, and treats the result as AES-encrypted data.

![](attachment/Pasted%20image%2020260831144239.png)

The loader flow is:

```text
registry State -> Base64 decode -> AES-CBC decrypt -> MD5 check -> Base64 decode -> Invoke-Expression
```

Then it brute-forces a four-letter lowercase key to recover the expected plaintext and Base64-decodes it again for the final payload.

```python
import base64, hashlib, itertools, string
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

data = base64.b64decode(reg_state_value)
iv = bytes(range(16))
expected = "f2571e71a503a7ff80a7a603ce0c1965"

for x in itertools.product(string.ascii_lowercase, repeat=4):
	word = ''.join(x)
	key = hashlib.sha256(word.encode()).digest()[:16]
	
	try:
		plain = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), 16).decode()
		  
		if hashlib.md5(plain.encode()).hexdigest() == expected:
			print("Key word:", word)
			print(base64.b64decode(plain).decode())
			break
	except (ValueError, UnicodeDecodeError):
		pass
```

Running the script recovers the key and final payload:

![](attachment/Pasted%20image%2020260831150340.png)

This is a TLS PowerShell reverse shell that connects to `10.10.15.38.1337`.

## Task answers

### Task 1

> Which opcode is checked as part of the first evasion technique?

The first evasion technique is anti-debugging. It checks for opcode `0xCC` (`INT3`) in `TlsCallback_0`.

### Task 2 

> Which PE structure contains the value used by the malware to derive its decoding key?

The decoding key is `qword_14000B6F8[0:3]`. In `main`, we have:

```c
qword_14000B6F8 = GetModuleHandleW(nullptr) + dword_140006080;
```

`GetModuleHandleW(nullptr)` returns the base address of the current executable in memory, and `dword_140006080 = 0x65`.

So the key is `run`.

![](attachment/Pasted%20image%2020260831152928.png)

It comes from the `IMAGE_DOS_HEADER`/DOS stub area.

### Task 3

> What is the string utilized in a runtime check to evade a particular driver?

![](attachment/Pasted%20image%2020260831153020.png)

`PROCMON`, verified with `x64dbg`.

### Task 4

> What type of obfuscation routine did the malware utilize?

The payloads and strings are decrypted with `sub_140002740`.


![](attachment/Pasted%20image%2020260831153149.png)


![](attachment/Pasted%20image%2020260831114219.png)

This is XOR obfuscation.

### Task 5

> What is the value of the decode key for the obfuscation?

It is `run`, as described in Task 2.

### Task 6 & 7

> What is the value of the decoy key?
>
> What is the corrupted offset?

The decoy key is `DOS`, activated in `TlsCallback_0` if opcode `0xCC` is present at the `main` entry point.

![](attachment/Pasted%20image%2020260831154038.png)

![](attachment/Pasted%20image%2020260831154431.png)

The corrupted offset is `0x6C` (`0x65 + 7`).

### Task 8

> Which hash is used to resolve the function pointer for CoSetProxyBlanket?

![](attachment/Pasted%20image%2020260831154626.png)

`0x79EF43A5`

### Task 9

> Where on the host is the final encrypted payload stored?

`HKCU\Software\Win32Cache\State`. It is decrypted and launched by the PowerShell command.

### Task 10

> Provide all values that cause the final payload to be activated.

The WMI event filter checks for:

```sql
SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogonSession' AND (TargetInstance.LogonType = 2 OR TargetInstance.LogonType = 3 OR TargetInstance.LogonType = 7 OR TargetInstance.LogonType = 10 OR TargetInstance.LogonType = 11) 
```

So the values are `2, 3, 7, 10, 11`.

### Task 11

> Which encryption algorithm is utilized by the staged payload?

`AES` in CBC mode, from the decoded PowerShell payload.

### Task 12

> What is the IV for the staged payload?

`iv = bytes(range(16))` is `00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F`.

### Task 13

> What is the decryption key for the staged payload?

`anti`, derived from my Python replica of the command.

### Task 14

> What is the IP address and port of the command-and-control (C2) server?

`10.10.15.38:1337`, also from my Python replica.

---


