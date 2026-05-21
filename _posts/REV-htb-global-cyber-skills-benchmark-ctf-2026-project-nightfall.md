
# Sysprobe 

Thử thách cung cấp cho chúng ta một file ELF. 

![](attachment/Pasted%20image%2020260520140759.png)

## Stage 1 - Packer?

Khi mở bằng IDA, phần mã tại entry point không được khôi phục thành pseudocode hoàn chỉnh. Không sao hết, bởi đoạn mã khởi đầu tương đối ngắn nên vẫn có thể phân tích trực tiếp bằng assembly.

Để có thể phân tích qua asm, ta cần lưu ý về calling convention:
	
![](attachment/Pasted%20image%2020260522004942.png)


Nhìn tổng quan lại là:

![](attachment/Pasted%20image%2020260520150805.png)

Ta có thể thấy rằng chương trình thực hiện các bước đặc trưng của packer:
- Cấp phát vùng nhớ RWX
- Giải nén/giải mã dữ liệu vào vùng nhớ vừa cấp phát
- Nhảy/Gọi tới vùng nhớ đó để thực thi payload
- Kết thúc nếu quá trình cấp phát/chuyển điều khiển thất bại

Mình tiến hành dump payload để tiếp tục phân tích.

![dumped with gdb](attachment/Pasted%20image%2020260520151706.png)

## Stage 2 - VM-obfuscated

Đưa payload đã dump vào IDA, ta có thể thấy phần mã chưa bị strip.
Nhìn các tên hàm & biến, kết hợp với đọc pseudocode, ta dễ dàng nhận biết được rằng phần mã thực thi này đã bị làm rối bằng kỹ thuật VM-obfuscation.

	VM-Obfuscation là kỹ thuật chuyển Bytecode tiêu chuẩn của chương trình thành Bytecode biến dị và ngẫu nhiên, đi kèm sẽ là một bộ thông dịch (máy ảo) để chạy chỗ Bytecode biến dị đó.

![hàm `vm_run` - máy ảo được đính kèm trong challenge](attachment/Pasted%20image%2020260520152453.png)

Mình bắt đầu phân tích từ `payload_entry`.

![](attachment/Pasted%20image%2020260520161801.png)

Tại đây, bytecode của máy ảo được giải mã từ `binary_vm_bytecode_bin_start` theo công thức:

```
v1[i] = binary_vm_bytecode_bin_start[i] ^ ((i + 66) & 0xff)
```

Bytecode sau khi được giải mã:

	  01 00 00 04 0e 01 0e 03 0e 04 01 02 01 00 0f cc
	  14 00 20 88 01 00 3b 00 21 ca 01 00 64 00 21 e1
	  01 00 37 00 21 c9 01 00 2d 00 21 99 01 00 2e 00
	  21 e0 01 00 2f 00 21 d9 01 01 05 00 22 ff

Sau đó, chương trình khởi tạo bộ nhớ ban đầu của VM và chạy `vm_run(bytecode, bytecode_len, vm_memory, vm_mem_len)` .

Ta bước vào phân tích hàm `vm_run`.

### Phân tích cấu trúc máy ảo

Để đi vào phân tích, lưu ý rằng máy ảo sẽ bao gồm các thành phần chính:
- VM Entry/Exit: Cầu nối vào/ra VM, chịu trách nhiệm thiết lập và khôi phục ngữ cảnh thực thi.
- VM Loop & Dispatcher: Vòng lặp trung tâm và bộ điều phối. 
	- *VM Loop* đóng vai trò duy trì chu kỳ thực thi liên tục của máy ảo
	- Tại mỗi vòng lặp, *Dispatcher* sẽ chịu trách nhiệm đọc (fetch) opcode ảo từ bộ nhớ, giải mã (decode) và chuyển điều khiển (dispatch) đến handler tương ứng.
- Handlers: Các đoạn mã xử lý từng lệnh ảo, mô phỏng hành vi của instruction gốc như arithmetic, memory access, stack operation hoặc control flow.

Căn cứ vào đó, ta nhận diện được các thành phần của máy ảo trong hàm `vm_run`:

![](attachment/Pasted%20image%2020260521234504.png)

Sau

### Khôi phục ý nghĩa bytecode

Tiếp tục đọc, mình thấy rằng máy ảo trong file thực thi khá đầy đủ các handlers:

Nhưng bytecode có vẻ khá ngắn nên mình chỉ tìm những opcode thực sự xuất hiện & phân tích handler của nó.

![](attachment/Pasted%20image%2020260520221510.png)

Đặt breakpoint tại dispatcher, mình quan sát được các opcode sau xuất hiện:

| opcode | ý nghĩa                                                                  |
| ------ | ------------------------------------------------------------------------ |
| `0x01` | load hằng số vào thanh ghi ảo.                                           |
| `0x0e` | in các chuỗi đánh lạc hướng như “`C2 Beacon`”,...                        |
| `0x0f` | điều chỉnh program counter theo `ctx[2]`, sửa trạng thái  `ctx[7] ^= 1`. |
| `0x14` | thiết lập lại `ctx[7]` theo hằng số trong bytecode                       |
| `0x20` | khởi tạo trạng thái cho chuỗi xử lý dữ liệu                              |
| `0x21` | cập nhật trạng thái theo từng hằng số được load trước đó                 |
| `0x22` | tổng hợp trạng thái và ghi bit kết quả vào vùng nhớ VM.                  |
| `0xff` | exit                                                                     |

Bytecode có pattern rõ ràng: `0x20` khởi tạo, cặp `0x01` và `0x21` lặp lại nhiều lần để cập nhật trạng thái, sau đó `0x22` kết thúc và chuyển đổi trạng thái thành các bytes giá trị `0/1`. 

Do đó, mình có một giả thuyết rằng flag được ghi lại qua handler `0x22`.

### Khôi phục flag(?)

![](attachment/Pasted%20image%2020260521011525.png)

Handler `0x22` ghi lại tại `[rbx+0x5054]`, mình chạy VM và dump vùng kết quả.

![](attachment/Pasted%20image%2020260521013927.png)

Nhóm mỗi 8 bytes gộp lại sẽ cho ra một ký tự flag, giả thuyết đúng.

```
0 1 0 0 1 0 0 0 --> 'H'
0 1 0 1 0 1 0 0 --> 'T'
0 1 0 0 0 0 1 0 --> 'B'
...
```

## Flag

```
flag = bytearray()
for i in range(0, len(guess_dump), 8):
	v = 0
	for b in guess_dump[i:i+8]:
		v = (v << 1) | (b & 1)
		flag.append(v)

print(flag)
```

`HTB{TH15_TH3_END_0R_WH4T}`

---
# Enthiran

Ở thử thách này, ta có một file ELF. Khi thực thi, file cho ra giao diện giống một chương trình chẩn đoán hệ thống Linux:

![](attachment/Pasted%20image%2020260518095533.png)

## Phân tích ban đầu

Luồng thực thi chính chủ yếu thực hiện tính toán các điểm/thông số giả lập.
Các hàm được gọi đều không có liên hệ trực tiếp tới flag.

Do số lượng hàm trong binary không nhiều, nên mình ra soát thủ công toàn bộ danh sách hàm.

Trong quá trình rà soát, duy chỉ có `sub_2210` nổi bật với đặc điểm khá giống một hàm giải mã.

![](attachment/Pasted%20image%2020260518191403.png)

## Giải mã - Brute-force

Khi có key chính xác thì ta sẽ giải mã được flag (tất nhiên rồi), nhưng trong binary, hàm `sub_2210` không nằm trong luồng thực thi chính và cũng không có liên hệ gì tới các hàm khác.

Do vậy ta phải đoán key `a1`.

Ta lại nhận thấy từ 8 bytes đầu của `a2`, ta có thể lấy được `a1` qua công thức

```
*(double *)&a1[i] = (a2[i] ^ byte_3308[i]) / 256.0
```

Vì flag có định dạng `HTB{...}` có 4 ký tự đầu cố định nên việc brute-force 8 bytes đầu của `a2` là một ý tưởng không tồi.

Script thử các giá trị có dạng `b'HTB{' + guess`, trong đó `guess` được sinh từ tập ký tự thường gặp trong flag. Với mỗi ứng viên, script suy ra key, sinh keystream, giải mã phần còn lại và kiểm tra output có kết thúc bằng `}` hay không.

```
import itertools, struct, string

M = 0xffffffffffffffff

byte_330 = bytes.fromhex("DE AD BE EF CA FE BA BE")
byte_32C = bytes.fromhex("33 D5 F5 55 07 F8 45 17 D0 7E 23 27 4E 3C 79 EF 78")

alphabet = (
    string.ascii_letters.encode()
    + string.digits.encode()
    + b"_{}-@$!+*#%&/\\|()[]=<>?:.;,"
)

def trym(a2):
    a1 = [
        struct.unpack("<Q", struct.pack("<d", (a2[i] ^ byte_330[i]) / 256.0))[0]
        for i in range(8)
    ]

    v4 = 0x736F6D6570736575

    for i in range(8):
        v6 = (a1[i] ^ v4) & M
        v7 = ((0x9E3779B97F4A7C15 * v6) & M) ^ (((v6 << 17) | (v6 >> 47)) & M)
        v7 = ((v7 << 31) | (v7 >> 33)) & M
        v4 = (v7 ^ ((0xFF51AFD7ED558CCD * (v7 >> 33)) & M)) & M

    v14 = bytearray()
    v8 = 0

    for i in range(len(byte_32C)):
        v10 = (v8 ^ v4) & M
        v8 = (v8 + 0x6C62272E07BB0142) & M
        v11 = (0xBF58476D1CE4E5B9 * (((v10 << 13) | (v10 >> 51)) & M)) & M
        v4 = (v11 ^ (v11 >> 31)) & M
        v14.append(byte_32C[i] ^ (v4 & 0xff))

    return a2 + bytes(v14)

for guess in itertools.product(alphabet, repeat=4):
    if ord("}") in guess[:3]:
        continue

    a2 = b"HTB{" + bytes(guess)
    flag = trym(a2)

    if flag.endswith(b"}") and all(chr(c) in string.printable for c in flag):
        print(flag)
```

## Flag

*...đợi script chạy 1 lúc...* 
`HTB{n3ur4l_r3v3rs3r_1337}`
