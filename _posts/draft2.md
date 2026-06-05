
# Sysprobe 

Thử thách cung cấp cho chúng ta một file ELF. 

![](attachment/Pasted%20image%2020260520140759.png)

## Stage 1 - Packed?

Khi mở bằng IDA, phần mã tại entry point không được khôi phục thành pseudocode hoàn chỉnh. Không sao hết, bởi đoạn mã khởi đầu tương đối ngắn nên vẫn có thể phân tích trực tiếp bằng assembly.

Để hiểu đoạn này, ta cần biết calling convention và syscall convention trên Linux x86-64 truyền tham số qua các thanh ghi như thế nào:

| Loại call         | Số hiệu syscall | Arg 1 | Arg 2 | Arg 3 | Arg 4 | Arg 5 | Arg 6 | Return |
| ----------------- | --------------- | ----- | ----- | ----- | ----- | ----- | ----- | ------ |
| function call<br> | N/A             | `rdi` | `rsi` | `rdx` | `rcx` | `r8`  | `r9`  | `rax`  |
| syscall           | `rax`           | `rdi` | `rsi` | `rdx` | `r10` | `r8`  | `r9`  | `rax`  |

Dựa vào đó, ta truy ngược lại các giá trị thanh ghi trước lệnh `call` hoặc `syscall` để xác định tham số tương ứng.

![](attachment/Pasted%20image%2020260523104530.png)

Tham khảo thêm [mmap manual page](https://man7.org/linux/man-pages/man2/mmap.2.html), pseudocode dựng lại được sẽ là:

```
void _start() {
	
	void* allocated_mem = mmap(0, dword_804F4, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); 
	
	if (allocated_mem == MAP_FAILED) exit(0);
	
	int status = sub_8045B5(dword_804F80, allocated_mem, dword_804F84);
	
	if (status != 0) exit(0);
	
	void (*payload_entry)(int, char**, char**) = (void (*)(int, char**, char**))((char*)allocated_mem + dword_804F88);
	
	payload_entry(argc, argv, envp);
	
	exit(0);
}
```

Đến đây, ta thấy rằng chương trình thực hiện các bước đặc trưng của custom loader:
- Cấp phát vùng nhớ RWX
- Gọi hàm thao tác tại vùng nhớ vừa cấp phát
- Nhảy/Gọi tới vùng nhớ đó để thực thi

Mình tiến hành dump payload sau khi `sub_8045B5` chạy xong để tiếp tục phân tích:

![](attachment/Pasted%20image%2020260520151706.png)

File dump ra được là một file ELF hợp lệ.

![](attachment/Pasted%20image%2020260523113146.png)

*Tới bước này, có thể chuyển trọng tâm sang phân tích payload thay vì reverse toàn bộ loader. Chỉ khi dump lỗi hoặc payload không hợp lệ hoặc không dẫn tới flag thì mới cần quay lại phân tích loader.*

## Stage 2 - VM-obfuscated

Đưa payload đã dump vào IDA, nhìn các tên hàm & biến, kết hợp với đọc pseudocode, ta dễ dàng nhận biết được rằng logic chính của payload đã bị làm rối bằng kỹ thuật VM obfuscation.

	VM obfuscation là kỹ thuật biến đổi logic gốc của chương trình thành một tập lệnh ảo riêng. Binary sẽ chứa bytecode của tập lệnh ảo đó cùng một interpreter/VM để thực thi bytecode, khiến việc phân tích control flow gốc khó hơn.

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
	- Tại mỗi vòng lặp, *Dispatcher* sẽ chịu trách nhiệm đọc (fetch) opcode - byte xác định loại lệnh từ bộ nhớ, giải mã (decode) và chuyển điều khiển (dispatch) đến handler tương ứng.
- Handlers: Các đoạn mã xử lý từng lệnh ảo, mô phỏng hành vi của instruction gốc như tính toán, truy nhập bộ nhớ,...

Căn cứ vào đó, ta nhận diện được các thành phần cơ bản của máy ảo trong hàm `vm_run`. Từ đó, mình xác định được VM context là `v6`, bên trong có các trường đáng chú ý như `v12` - bytecode, `v11` - program counter,...

![](attachment/Pasted%20image%2020260521234504.png)

Ở đoạn sau của `vm_run`, mình thấy rằng máy ảo trong file thực thi khá đầy đủ các handlers.

*Chưa vội đi vào phân tích các handlers, để ý rằng bytecode ta giải mã được phía trên có vẻ khá ngắn & ít opcode nên mình chỉ tìm và phân tích những handler thực sự được gọi tới.*

![](attachment/Pasted%20image%2020260520221510.png)

Mình đặt breakpoint tại dispatcher, log giá trị opcode và phân tích từng handler dựa vào cấu trúc VM đã xác định trước đó.

| opcode | ý nghĩa                                                                 |
| ------ | ----------------------------------------------------------------------- |
| `0x01` | load hằng số tại `bytecode[pc+2]` vào thanh ghi ảo `v6[bytecode[pc+1]]` |
| `0x0e` | in các chuỗi đánh lạc hướng như “`C2 Beacon`”,...                       |
| `0x0f` | điều chỉnh program counter theo `v6[2]`, sửa trạng thái `v6[7] ^= 1`    |
| `0x14` | thiết lập lại `v6[7]` theo hằng số trong bytecode                       |
| `0x20` | khởi tạo trạng thái cho chuỗi xử lý dữ liệu trong bộ nhớ VM             |
| `0x21` | cập nhật trạng thái theo từng hằng số được load trước đó                |
| `0x22` | tổng hợp trạng thái và ghi bit kết quả vào vùng nhớ VM                  |
| `0xff` | exit                                                                    |

Các lệnh của máy ảo là:

```vm_instructions
	01 00 00 04
	0e 01
	0e 03
	0e 04
	01 02 01 00
	0f cc
	14 00
	20 88
	01 00 3b 00
	21 ca
	01 00 64 00
	21 e1
	01 00 37 00
	21 c9
	01 00 2d 00
	21 99
	01 00 2e 00
	21 e0
	01 00 2f 00
	21 d9
	01 01 05 00
	22
	ff
```

Bytecode có pattern rõ ràng: `0x20` khởi tạo, cặp `0x01` và `0x21` lặp lại để cập nhật trạng thái, sau đó `0x22` chuyển đổi trạng thái thành các byte có giá trị `0/1` và `0xff` kết thúc. 

Do đó, mình có một giả thuyết rằng flag được ghi lại qua handler `0x22`.

### Khôi phục flag

![](attachment/Pasted%20image%2020260521011525.png)

Handler `0x22` ghi lại tại `[rbx+0x5054]`, mình chạy file và dump vùng kết quả.

![](attachment/Pasted%20image%2020260521013927.png)

Mỗi byte trong vùng kết quả chỉ biểu diễn một bit. Khi ghép 8 giá trị liên tiếp theo thứ tự xuất hiện trong memory, ta thu được mã ASCII của từng ký tự.

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

Ở thử thách này, ta có một file ELF giả dạng công cụ chẩn đoán hệ thống.

![i use arch btw <(")](attachment/Pasted%20image%2020260518095533.png)

## Phân tích ban đầu

Hành vi ở luồng `main` khớp với giao diện của một chương trình chẩn đoán hệ thống:

In thông tin máy:

![](attachment/Pasted%20image%2020260523141914.png)

Đọc dữ liệu từ `/proc` và `/dev/urandom`, tạo các đặc trưng dạng số thực và tổng hợp vào `v76`:

![](attachment/Pasted%20image%2020260523132252.png)

Sau đó đưa các đặc trưng qua `sub_1ED0`, tiếp tục tính toán rồi in ra diagnostic score gồm 8 số thực:

![](attachment/Pasted%20image%2020260523133706.png)

Hàm `sub_1ED0(...)` nhận feature vector đầu vào và biến đổi nó thành một output vector có `a6` phần tử. Vì output này chỉ tiếp tục đi vào pipeline diagnostic score, mình chưa thấy liên hệ trực tiếp tới logic flag.

![](attachment/Pasted%20image%2020260523140203.png)

*Khi kiểm tra call graph và xref, mình không thấy luồng `main` tham chiếu trực tiếp tới các vùng dữ liệu đáng nghi, cũng không có nhánh rõ ràng dẫn tới logic kiểm tra flag. Các helper được gọi từ `main` chủ yếu chỉ phục vụ pipeline chẩn đoán.*

Quay lại, phần mô tả của challenge gợi ý rằng

> The binary does not compare, decrypt, or flag-print in any way a standard analysis tool can trace.
> Every decision is delegated to a learned model embedded in its data section.
> Understanding what the binary actually does requires moving beyond control-flow analysis into the mathematics of its internal representations.

Mình chuyển sang rà soát các hàm không được gọi trực tiếp. Trong số đó, `sub_2210` nổi bật vì thao tác với hai blob hardcoded tại `0x3308` và `0x32c0`, đồng thời có pattern giống routine giải mã: XOR, rotate, nhân với hằng số lớn và ghi ra buffer.

## Giải mã - Brute-force

Hàm `sub_2210` nhận 2 input `a1`, `a2`; lần theo 2 tham số input, thấy rằng:
- `a2` bị ghi dữ liệu giải mã vào, nên mình đoán nó là output buffer
- `a1` đóng vai key/seed, bởi nó:
	- dùng để giải mã 8 bytes đầu của `a2`.
	- dùng trong đoạn code tính seed/hash `v4` (`v4` sau đó được dùng để tính key `v14`, `v14` dùng để giải mã nốt phần còn lại của `a2`)

![](attachment/Pasted%20image%2020260518191403.png)

Khi có key `a1` chính xác thì ta sẽ giải mã được flag (tất nhiên rồi), nhưng trong binary, hàm `sub_2210` không nằm trong luồng thực thi chính và cũng không có liên hệ gì tới các hàm khác.

Mình nhận thấy từ 8 byte đầu của `a2`, ta có thể suy ra lại từng phần tử `a1[i]`.

Cụ thể, giá trị `(a2[i] ^ byte_3308[i]) / 256.0` được biểu diễn dưới dạng `double`, sau đó lấy bit-pattern 64-bit của double đó để dùng làm `a1[i]`.

Vì 4 byte đầu của `a2` đã biết là `HTB{`, nên mình nghĩ tới việc brute-force 4 byte còn thiếu của `a2`.

Script dưới đây thử các giá trị có dạng `b'HTB{' + guess`, trong đó `guess` được sinh từ tập ký tự thường gặp trong flag. Với mỗi ứng viên `a2`, script suy ra `a1`, dùng nó giải mã phần còn lại và kiểm tra output `a2` có *hợp lệ* hay không.

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
	# lấy a1
    a1 = [
        struct.unpack("<Q", struct.pack("<d", (a2[i] ^ byte_330[i]) / 256.0))[0]
        for i in range(8)
    ]
	
	# đoạn này bê nguyên logic giải mã trong IDA vào
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

# main
for guess in itertools.product(alphabet, repeat=4):
    if ord("}") in guess[:3]:
        continue

    a2 = b"HTB{" + bytes(guess)
    flag = trym(a2)

    if flag.endswith(b"}") and all(chr(c) in string.printable for c in flag):
        print(flag)
```

## Flag

Sau khi chạy brute-force, script trả về flag:
`HTB{n3ur4l_r3v3rs3r_1337}`
