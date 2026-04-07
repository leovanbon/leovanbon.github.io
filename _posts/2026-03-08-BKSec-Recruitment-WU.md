---
layout: post
title: "BKSec Recruitment Writeups"
date: 2026-03-08 00:00:00 +0000
categories: [writeup, ctf]
tags: [bksec, reverse]
---

# Welcome

`BKSEC{ctf_has_always_been_fun_til_now?}`


#  very cool native app (REV)

The challenge provides an ipa.

![](attachment/7acd52405f2fdb239f6189aa2eb322c9.png)

Inside it, there are 2 files that caught my eye: the Mach-O64 `HermesChallenge` and the binary `main.jsbundle`.

I tried analyzing the Mach-O64 but it didn't give me anything useful.

I proceed edto analyzing the `.jsbundle`, putting it in DiE

![](attachment/776fcc849136063b822441a4d8ad5f50.png)

With that information, I found the tool : https://github.com/P1sec/hermes-dec
(after struggling a bit with the syntax) I got the desired .js; let's take a look:

![](attachment/379693bd68bc736e365ba94dc119c999.png)

We have an "unfinished" flag at `_q3m`.
Scroll down a little

![](attachment/160536194595d392222cfcbb0f4b3902.png)

There are some suspicious skips, 
This `_w9p` should be the one that checks those missing characters.

![](attachment/96521f96578a1976cadc0ec16f47f766.png)

![](attachment/ecf8a89fe9feadf14d8150a5d32d7798.png)

I fed it all to the LLM and it got me the full thing:

![](attachment/25c562d36a2314c435f499742620fe82.png)



# IoT_ez_or_hard

This challenge is about inspecting a firmware update. %% (which was kind of broken and my task is to analyze to see how it works and recovers the flag (the author accidentally hinted this)) %%

## Extracting

The challenge provides me a `router_fw.bin`.
I asked the LLM for the tools and how could i extract the data from this, after a while i got what i wanted
![](attachment/96c96da8f683aee5cf1c2fe52690b8f0.png)
%%0x7e = 126%%

Found an executable `cloudsync`. Let's dive into that

![](attachment/2baa83b5f1a64a9c8552ac063c8ad1d5.png)
If nothing is suspicious, it passes us to the `sub_1a70`

  
Let's take a look at `sub_1a70` 
%%that wall of vars jumpscared me%%

scrolling through, these are noticeable:
- it reads the serial
- it reads itself
- loads something from `0x31c0` - `0x3220`
- it reads the `backup.dat` *(the backup file for syncing?)*
- it has its own reading func `sub_19b0`
- `sub_1900` and `sub_1710` were called several times (together)
- There is a XOR check loop at the end
- 128 bits = 16 bytes


###  Analyzing & guessing `sub_1900` & `sub_1710`

![](attachment/9caf464c43ebd19540f77a082b45481a.png)
![](attachment/3c0e1c9d01b02b28aa249effa2db3c5b.png)


it loads some hard coded vals, i'm curious what those were

![](attachment/f1eebc5acda0dc51cc1e55fca6f7a0f5.png)

![](attachment/de93bce2b21518445c5e6ce816f62281.png)

That code pattern appeared several more times:

![](attachment/5b63be66b22c8822439976dc61f67f64.png)
![](attachment/e52d2aecffbc90f2b1e28b7fc4bb57fb.png)

So there is a high chance the LLM was right %%(there is no chance we have a custom hashing/encrypting here, yeah?)%%

From what i have known: SHA256 has 3 parts: init, update and finalize
I derived that
- `sub_1900(state, src, len)` ~ `sha_update`
- `sub_1710(state, dest)` ~ `sha_finalize`

## Reconstructing


Now i can rewrite the first part with python 

![](attachment/4c4fd3bdb3b683b4ca9adf0fbe9c769f.png)

```
import hashlib  

sugar = bytes.fromhex("4C18217E0A6B2D72334F5561102A3C19")[::-1]

exe_bytes = open("cloudsync", "rb").read()
self_has = hashlib.sha256(exe_bytes).digest()

serial = b'ROUTER-61AAE6FC6A83FD56'
first_dish = hashlib.sha256(serial + sugar + self_has).digest()
```

The `first_dish` is our router's "signature"

it then goes to the HMAC and was checked with the tag from the `backup.dat`

```
dat = open("backup.dat", "rb").read()
tag = dat[0x19 + 39 : 0x19 + 39 + 32]

import hmac

assert hmac.new(first_dish, dat[5:0x19+39], hashlib.sha256).digest() == tag, "HMAC not ok"
print("HMAC ok")
```

I copied all the file in the same folder tested it and it said "ok" %%jackpot!%%. Our key `first_dish` is correct.

aaaaanddddddd..... did i miss something? isn't it supposed to have a decrypting fuction? (so this is the part where it was broken)

looked around and found this untouched `sub_2340`  
![](attachment/6010a3b40de629a9eaa6d15ef3512f7b.png)
![](attachment/2da0450d1dcc3ac0558f1a7957422734.png)
![](attachment/5941feed79786917da36c9b4cae1d974.png)

rewirite:
```
key = hashlib.sha256(key1 + key2 + b'\x00\x00\x00\x00').digest()
key += hashlib.sha256(key1 + key2 + b'\x01\x00\x00\x00').digest()
...
flag = xor(cipher, key)
```

### Finishing

With further inspection of the `backup.dat` and trying out the combinations (with LLM), i got the right combinations, the full script was written as below

```
import hashlib, hmac
from pwn import xor

sugar = bytes.fromhex("4C18217E0A6B2D72334F5561102A3C19")[::-1]

exe_bytes = open("cloudsync", "rb").read()
self_has = hashlib.sha256(exe_bytes).digest()

serial = b'ROUTER-61AAE6FC6A83FD56'
first_dish = hashlib.sha256(serial + sugar + self_has).digest()

dat = open("backup.dat", "rb").read()
ntwice = dat[5 : 0x15]
tag = dat[0x40:]

assert hmac.new(first_dish, dat[5:0x19+39], hashlib.sha256).digest() == tag, "HMAC not ok"
print("HMAC ok")

skibidi = dat[0x19 : 0x19 + 39]
bo_pi_xi = hashlib.sha256(first_dish[:16] + ntwice + b'\x00\x00\x00\x00').digest()
bo_pi_xi += hashlib.sha256(first_dish[:16] + ntwice + b'\x01\x00\x00\x00').digest()
print(xor(skibidi, bo_pi_xi))
```

![](attachment/9ac39208dc5f087e8c81afa381b6ef2c.png)

