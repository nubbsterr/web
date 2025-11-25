## Simple analysis on the variadic qualities of printf, and how the AMD64 System V ABI passed RAX w/ the number of float args passed to a variadic function

Below is the C code written; a very simple summation program:
```c
#include <stdio.h>

int main() {
  float x, y, z;

  printf("Enter all 3 float values, space-separated: ");
  scanf("%f%f%f", &x, &y, &z);

  printf("The sum of them is %.2f.", x+y+z);
  return 0;
}
```

We can compile this w/ `gcc -Wextra -Wall float.c`.

Now let's disassemble it w/ IDA.

We can see that there is just one big blob, which is our main function, and a final split in the graph where our main return code is processed, either leading to a good exit or `__stack_chk_fail`.

The disassembly is the following:

```asm
; Attributes: bp-based frame

; int __fastcall main(int argc, const char **argv, const char **envp)
public main
main proc near

var_14= dword ptr -14h
var_10= dword ptr -10h
var_C= dword ptr -0Ch
var_8= qword ptr -8

; __unwind {
push    rbp
mov     rbp, rsp
sub     rsp, 20h
mov     rax, fs:28h
mov     [rbp+var_8], rax
xor     eax, eax
lea     rax, format     ; "Enter all 3 float values, space-separat"...
mov     rdi, rax        ; format
mov     eax, 0
call    _printf
lea     rcx, [rbp+var_C]
lea     rdx, [rbp+var_10]
lea     rax, [rbp+var_14]
lea     rdi, aFFF       ; "%f%f%f"
mov     rsi, rax
mov     eax, 0
call    ___isoc23_scanf
movss   xmm1, [rbp+var_14]
movss   xmm0, [rbp+var_10]
addss   xmm1, xmm0
movss   xmm0, [rbp+var_C]
addss   xmm0, xmm1
pxor    xmm2, xmm2
cvtss2sd xmm2, xmm0
movq    rax, xmm2
lea     rdx, aTheSumOfThemIs ; "The sum of them is %.2f."
movq    xmm0, rax
mov     rdi, rdx        ; format
mov     eax, 1
call    _printf
mov     eax, 0
mov     rdx, [rbp+var_8]
sub     rdx, fs:28h
jz      short locret_11FA
```

We can unpack a few things:
- `__fastcall` is still being used, per the 64-bit C calling convention, which we figured out in while analyzing `clockToRev`.
- Some variables are initialized. Notice that they each are DWORD (32-bit) size, which is 4 bytes; the size of a float.
- We initialize the stack w/ rbp and rsp.
  - Subtract from rsp to allocate some space on the stack.
- printf gets called w/ the string packed in.
- **scanf gets called, and we can see 2 parameters being sent to rdi and rsi respectively, 1) the format specifier and 2) the variables to scan for, which were loaded into rcx, rdx, and rax.**
  - What happens next is really weird, and something I've never seen before, since I haven't disassembled `scanf` before, nor seen some `pxor` or `cvtss2sd` instruction lol.
  - We do see that, supposedly, our return value is stored in `rax` w/ `movq`.

What's incredibly important there though, is our final printf call, because we do see that `eax` is set to 1, since we are passing a floating-point argument, which is the sum of the 3 floats.

Afterwards, the return code is given and our program is basically done.

A simpler view of this program can be attained by inspecting the decompiled view as well:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  float v4; // [rsp+Ch] [rbp-14h] BYREF
  float v5; // [rsp+10h] [rbp-10h] BYREF
  float v6; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  printf("Enter all 3 float values, space-separated: ");
  __isoc23_scanf("%f%f%f", &v4, &v5, &v6);
  printf("The sum of them is %.2f.", (float)(v6 + (float)(v4 + v5)));
  return 0;
}
```

At first, `v7` looks really odd. We have in fact seen it previously w/ `clockToRev`.
It's main purpose is stack protection. `CyberGecko` on OALabs discord provides some good input:

```
in your disassembly, it loads a value from fs:28h into rax,
then does it's computations, in the end, subtracts the value now in fs:28h from rax.
It should result in zero, because nothing should change what's in fs:28h.
so in the last line, jz only jumps if fs:28h was not altered
```

This is essentially a form of stack protection, and it would explain why the `jz` instruction in the end will go to `__stack_chk_fail` if it is not zero, meaning that `fs:28h` had to have been overwritten/changed in some way.

Check out RE Playbook notes for a simpler summary of this.

Everything else makes perfect sense, because IDA is absolutely goated for reversing and gives us back a lot of the lost info from compiling and whatnot.
