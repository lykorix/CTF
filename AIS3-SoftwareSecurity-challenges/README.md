## Sysmag1c

斷點設在 `0x40143C`，查看rand()值  

![upload_0f29f476c5d42ae647d4309cce7d5287](https://github.com/lykorix/CTF-Writeups/assets/78891767/335864a3-f91c-4b20-93d0-3e5356dd67cb)

## Sysmag1c - 2 


斷點設在0x401526，將[rbp+var_4] 設為 0xDDAAh，則 `cmp     [rbp+var_4], 0DDAAh`就會相等  


![upload_a7fd17d314518423f9d720c676af0de8](https://github.com/lykorix/CTF-Writeups/assets/78891767/b21899fa-0a09-4906-a85c-57a99d7f45b7)




## ret2text

發現40個 bytes 會造成 buffer overflow  

![upload_aba7884b8375577eb4e60c1274bf3961](https://github.com/lykorix/CTF-Writeups/assets/78891767/f1914779-6025-45a2-95da-b9278d35753a)


而 win() 位在 0x4011B6   

![upload_a15ffe94be90b1606f0517bdc971f960](https://github.com/lykorix/CTF-Writeups/assets/78891767/d005a508-d57b-467c-a797-260d99bbe103)
)

- [ret2text.py](ret2text.py)


![upload_3ff2eaa431dff5d2d405e66dabbf94ad](https://github.com/lykorix/CTF-Writeups/assets/78891767/cfabd42f-e727-49aa-9ad2-fcd57a3b9b5d)


## gothijack

程式將第二個讀入的質寫入第一個輸入的位址，故可以將 puts@GOT 改為win()

![upload_31f9d68ddd4277177395cbe6ef837056](https://github.com/lykorix/CTF-Writeups/assets/78891767/3ed787bb-9a74-4bed-b682-d809e7563c9d)
)

![upload_6afed639d81608d9483e5178b042c6c8](https://github.com/lykorix/CTF-Writeups/assets/78891767/255bb6cd-0c11-4fef-8106-77936f33b0fe)
)



- [gothijack.py](gothijack.py)

![upload_ea290ca70dfa68b64856ca9f0c7ca0b4](https://github.com/lykorix/CTF-Writeups/assets/78891767/06750759-640c-48d1-b63e-c77146d1e398)



## easyrop

首先讀40個 bytes 造成 buffer overwflow

ROPgadget 找rax, rdi, rsi, rdx, mem寫入及 syscall 的指令

```
0x000000000044fcc7 : pop rax ; ret
0x0000000000401e8f : pop rdi ; ret
0x0000000000409ebe : pop rsi ; ret
0x0000000000485aeb : pop rdx ; pop rbx ; ret

0x0000000000433403 : mov qword ptr [rdi], rdx ; ret

0x0000000000401C44     syscall  
```
`mov qword ptr [rdi], rdx ; ret ` 可以將/bin/sh 直接寫入 [rdi]，故找一可寫入位址 -- 0x4c8000 存到 rdi

設 rax = 0x3b , rdi = address of "/bin/sh", rsi = 0 , rdx = 0 ， 然後 syscall

-[easyrop.py](easyrop.py)

![upload_f5ffaad256dd65d246ab5e48e9b49b70](https://github.com/lykorix/CTF-Writeups/assets/78891767/569ef3aa-5069-4f4e-9dd0-95721a55a6d9)




## ret2text_adv

40個 bytes 會造成 buffer overflow，但指令執行到do_system 調用 xmm0 時會 segment fault

![upload_7205aab50b10ba08cadf0cc8a6f83b3c](https://github.com/lykorix/CTF-Writeups/assets/78891767/ff3c18fd-1f91-4ada-bcd0-de7e2170ff0c)



https://hack543.com/16-bytes-stack-alignment-movaps-issue/  

發現是 xmm 暫存器 alignment 的問題，多呼叫一次其他位址的 ret 即可對齊 rsp

- [ret2text_adv.py](ret2text_adv.py)


![upload_98626d6c7935d0d1c3e775fdb0e41617](https://github.com/lykorix/CTF-Writeups/assets/78891767/bbcb86e6-51bb-40d2-ac37-e3577a4e0b97)


## gothijack_adv

程式是將兩個記憶體位址調換兩次，故思路是更改 got 來執行 system()

![upload_4c8f75a57836f93aff61c2bbb64031c0](https://github.com/lykorix/CTF-Writeups/assets/78891767/241af617-0d30-45f1-9750-0e6bf7e651ea)


首先把strtoll() 換成 system()，但要將 "/bin/sh" 作為參數才能取得shell

故用第三次 read() 把  "/bin/sh"作為參數，此時發現執行到system 時rdi會存一開始 read() 讀到的東西，所以可以在第一個read()讀"/bin/sh"

![upload_fe3d8dccb6aaae5e9759af23141e62ad](https://github.com/lykorix/CTF-Writeups/assets/78891767/6c41b8b6-3972-4b32-a309-701a3480b4c8)

讀到rdi，最後觸發system("/bin/sh")

- [gothijack_adv.py](gothijack_adv.py)

![upload_54e0b296b1134fcbeb685ac327baf83f](https://github.com/lykorix/CTF-Writeups/assets/78891767/bf6e65f3-52a9-446f-a492-abf8ae8c50fe)



## r3t2lib

程式會透漏輸入位址的內容，可以拿來看 puts@got ， 得到 puts() 實際位址再用 libc offset 來推 system() 的實際位址 : puts address - puts offset + system offset


![upload_6feb71719e2b1c7b7bea4067c9e3ffd9](https://github.com/lykorix/CTF-Writeups/assets/78891767/3c392a2f-3c85-427b-bc2e-dbfe558e12f4)



gets() 在輸入280 個 bytes 時會 buffer overflow，讓他跳到 system()

這題一樣有 xmm 暫存器 alignment 的問題，需要多呼叫一次其他位址的 ret

此時還需要 "/bin/sh"作為參數，發現執行到 system() 時rdi會存一開始 read()讀到的值，故可以讓第一個read()讀"/bin/sh"


![upload_5f507e0552aef36fa53861ac2c179c83](https://github.com/lykorix/CTF-Writeups/assets/78891767/e4eaff1d-2f37-4740-af66-f0e5c838d293)


最後"/bin/sh"就會在執行system()時作為參數傳入


- [r3t2lib.py](r3t2lib.py)


![upload_8fe4fb0d8d9b6d1f6bd9c4e1f0506293](https://github.com/lykorix/CTF-Writeups/assets/78891767/1de5c442-ef50-4230-9a43-44144fc00c5d)


* 在同一個程式同樣是用 libc.so.6 的情形下，kali-linux 的 offset 跟 ubuntu 不太一樣



## easyrop_adv

跟 easyrop 相似，但 read() 讀太少，無法讀整個 rop

設法再read() 一次，且能讀多個bytes

找到一個getpid function, syscall 之後 return

![upload_3ee8c3da2c36a52cc8a7013b1558ad3a](https://github.com/lykorix/CTF-Writeups/assets/78891767/362adf03-65a9-40c5-9d68-1faea1f35ea5)



設 rdx=0x400 ，此時  rax=0, rdi=0, rsi= buffer address ，執行這個syscall，read() 就能讀 0x400 個 bytes

最後將造成 overflow 的72個 bytes 跟 rop (同 easyrop )讓第二個 read() 讀入

- [easyrop_adv.py](easyrop_adv.py)

![upload_a2f55517b4e3a0305723305847177af3](https://github.com/lykorix/CTF-Writeups/assets/78891767/e2cd8202-e5f1-4c84-83d3-fb147517f18a)


## ret2plt


若跳到 main 中的 call gests 或直接跳 gets@got 都會報錯，但跳 gets@plt 不會

因為最後要傳 "/bin/sh" 作為 system() 參數，所以先呼叫一次gets()，來將"/bin/sh"寫到 memory 中

然後使用 puts(puts@got)，得出 puts() 實際位址，再用 offset 來算出 system() 位址

最後再呼叫一次 gets() 把 system() 位址寫到puts@got，然後把 "/bin/sh" 讀到 rdi ，後面接著的 puts() 就會變成system("/bin/sh")

- [ret2plt.py](ret2plt.py)

![upload_30b802c670d5fea1c4425ace3ca31052](https://github.com/lykorix/CTF-Writeups/assets/78891767/52b8a686-1407-4327-b053-c2c423ef0bb8)


