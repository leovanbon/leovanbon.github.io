

![](attachment/Pasted%20image%2020261015090950.png)

i was given this task on my internship training, let's see what the binary does.

![](attachment/Pasted%20image%2020261015092542.png)

this looks friendly as it is just an encrypting module, it returns and does nothing if no args are present

![](attachment/Pasted%20image%2020261015092614.png)

![](attachment/Pasted%20image%2020261015093327.png)

The encryption module is in `sub_400A95`. Note here in `main` it calls `sub_400A95(<.svg file>, <file arr>, <file count>)`. So inside we can maps out some of the semantics

![](attachment/Pasted%20image%2020261015104333.png)

Let me begin with the encrypting engine
## sub_4073F0(file_paths, file_count, 48_bytes, .svg_thing)


![](attachment/Pasted%20image%2020261015112733.png)

Here we have 2 loops: one for encrypting, one for changing files name.

![](attachment/Pasted%20image%2020261015114243.png)

So the encrypting function `sub_406A16` gets `v14` - something with `PALID2` header, `a3` - 48 input bytes with `PRI1` header, `a4` - something derived from the `.svg`.

Inside `sub_406A16`, notice the different `(char *)`, `(_WORD *)`, `(_DWORD *)`, `(_QWORD *)` casting, we can reconstruct the offset of the encrypted files.

![](attachment/Pasted%20image%2020261015145215.png)

Now we tracking back the components: `v31..v35`.

![](attachment/Pasted%20image%2020261015145612.png)

`v31`, `v32`, `v33` are straight up rand bytes.

![](attachment/Pasted%20image%2020261015150856.png)

`v35` is SHA-256 of the file path.

upon checking `sub_406887`, `v34` is also rand bytes.

![](attachment/Pasted%20image%2020261015152411.png)

together with the `sub_406A16` params it calculates `v36` - the key used for encryption.

![](attachment/Pasted%20image%2020261015152451.png)

The algo can be implemented with python as follow

```python
salt, nonce, extra = os.urandom(16), os.urandom(12), os.urandom(8)

#sub_406887
ikm = b'PALIKM4' + struct.pack('<H', len(palid2)) + palid2 + pri1[4:] + svg_hash
#sub_406768
prk = hmac.digest(salt, ikm, 'sha256')
key = hmac.digest(prk, b'PALINFO-VAULT-v4\x01', 'sha256')

header = struct.pack('<8sBBHQQ32s16s12s8s',
					b'SBC2026\0', 2, 1, info.st_mode & 0xFFF,
					len(plaintext), len(plaintext),
					hashlib.sha256(os.fsencode(path)).digest(),
					salt, nonce, extra)
header += struct.pack('<I', zlib.crc32(header))

output = header + ChaCha20Poly1305(key).encrypt(nonce, plaintext, header)
```

Now we need to trace back the components: the `SVG` and the `PRI1`.

## Key components

Jump back to `sub_400A95`. With quick inspection of the presented functions, i mapped out the data flow:

![](attachment/Pasted%20image%2020261015165049.png)

