## Sysmag1c

斷點設在 `0x40143C`，查看rand()值  

![](https://hackmd.io/_uploads/H1-sqKojn.png)

## Sysmag1c - 2 


斷點設在0x401526，將[rbp+var_4] 設為 0xDDAAh，則 `cmp     [rbp+var_4], 0DDAAh`就會相等  

![](https://hackmd.io/_uploads/SydQyqssn.png)


## ret2text

發現40個 bytes 會造成 buffer overflow  

![](https://hackmd.io/_uploads/B1Bdhbho3.png)

而 win() 位在 0x4011B6   

![](https://hackmd.io/_uploads/BJCHTbhsn.png)

ret2text.py

![](https://hackmd.io/_uploads/Skw9qwz32.png)


## gothijack

程式將第二個讀入的質寫入第一個輸入的位址，故可以將 puts@GOT 改為win()

![image](https://hackmd.io/_uploads/HyBEvC3o3.png)

![image](https://hackmd.io/_uploads/rJB8PR2j3.png)



gothijack.py

![](https://hackmd.io/_uploads/SykSGufh2.png)


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

easyrop.py

![](https://hackmd.io/_uploads/Hk_gr_fh2.png)





## ret2text_adv

40個 bytes 會造成 buffer overflow，但指令執行到do_system 調用 xmm0 時會 segment fault

![](https://hackmd.io/_uploads/H1PixKMh2.png)


https://hack543.com/16-bytes-stack-alignment-movaps-issue/
發現是 xmm 暫存器 alignment 的問題，多呼叫一次其他位址的 ret 即可對齊 rsp

ret2text_adv.py

![](https://hackmd.io/_uploads/HJ-veYf2n.png)


## gothijack_adv

程式是將兩個記憶體位址調換兩次，故思路是更改 got 來執行 system()

![](https://hackmd.io/_uploads/HJFpXFMn3.png)

首先把strtoll() 換成 system()，但要將 "/bin/sh" 作為參數才能取得shell

故用第三次 read() 把  "/bin/sh"作為參數，此時發現執行到system 時rdi會存一開始 read() 讀到的東西，所以可以在第一個read()讀"/bin/sh"

![](https://hackmd.io/_uploads/Byqy0tG3n.png)
讀到rdi，最後觸發system("/bin/sh")

gothijack_adv.py

![](https://hackmd.io/_uploads/rkSkQtznh.png)


## r3t2lib

程式會透漏輸入位址的內容，可以拿來看 puts@got ， 得到 puts() 實際位址再用 libc offset 來推 system() 的實際位址 : puts address - puts offset + system offset

![](https://hackmd.io/_uploads/BkVa15M2h.png)


gets() 在輸入280 個 bytes 時會 buffer overflow，讓他跳到 system()

這題一樣有 xmm 暫存器 alignment 的問題，需要多呼叫一次其他位址的 ret

此時還需要 "/bin/sh"作為參數，發現執行到 system() 時rdi會存一開始 read()讀到的值，故可以讓第一個read()讀"/bin/sh"

![](https://hackmd.io/_uploads/H1YylcGn2.png)  

最後"/bin/sh"就會在執行system()時作為參數傳入


r3t2lib.py

![](https://hackmd.io/_uploads/SyOdPFG33.png)


* 在同一個程式同樣是用 libc.so.6 的情形下，kali-linux 的 offset 跟 ubuntu 不太一樣



## easyrop_adv

跟 easyrop 相似，但 read() 讀太少，無法讀整個 rop

設法再read() 一次，且能讀多個bytes

找到一個getpid function, syscall 之後 return

![](https://hackmd.io/_uploads/BkrHwqMnh.png)


設 rdx=0x400 ，此時  rax=0, rdi=0, rsi= buffer address ，執行這個syscall，read() 就能讀 0x400 個 bytes

最後將造成 overflow 的72個 bytes 跟 rop (同 easyrop )讓第二個 read() 讀入

easyrop_adv.py

![](https://hackmd.io/_uploads/rJzl_cG3h.png)

## ret2plt


若跳到 main 中的 call gests 或直接跳 gets@got 都會報錯，但跳 gets@plt 不會

因為最後要傳 "/bin/sh" 作為 system() 參數，所以先呼叫一次gets()，來將"/bin/sh"寫到 memory 中

然後使用 puts(puts@got)，得出 puts() 實際位址，再用 offset 來算出 system() 位址

最後再呼叫一次 gets() 把 system() 位址寫到puts@got，然後把 "/bin/sh" 讀到 rdi ，後面接著的 puts() 就會變成system("/bin/sh")

ret2plt.py

![](https://hackmd.io/_uploads/SJv8i5Gn2.png)

