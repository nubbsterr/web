## Analyzing the goofy clock program in [~/repos/nubbsterr/programming/C/clock.c](https://github.com/nubbsterr/nubbsterr/blob/main/programming/C/clock.c)

```c
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>

int main() {
    time_t rawtime = 0; // long int basically, which is mega big, time_t is legit meant to hold unix epoch time; seconds since jan 1 1970
    struct tm* p_time = NULL; // best practice than setting it to nothing, BUT MAKE SURE TO ASSIGN SOMETHING TO IT OTHERWISE U DEREFERENCE A NULL POINTER AND EXPLODE
    bool isRunning = true;

    while (isRunning) {
        time(&rawtime); // updated unix timestamp

        p_time = localtime(&rawtime); // return pointer to time struct of hrs/mins/secs

        // Arrow operator will deref the pointer p_time so we can then get the struct fields, if we do *p_time.field, then we get the field and then deref which is no good
        // zero pad everything so its all aligned ye
        printf("\r%02d:%02d:%02d", p_time->tm_hour, p_time->tm_min, p_time->tm_sec);
        fflush(stdout);  // to flush the output buffer, on Linux this is needed for some reason lul
        sleep(1);
    }

    printf("Here's a flag or something: John OALabs");
    return 0;
}
```

We can first see that the __fastcall calling convention is being used. Recall that for fastcall, the first 2 args passed are in ECX/EDX (rest are pushed r-->l onto stack), the callee cleans the stack, and the return value is in EAX.

The decompiled view of the program is the following:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  time_t timer; // [rsp+8h] [rbp-18h] BYREF
  struct tm *v5; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  timer = 0;
  v5 = 0;
  while ( 1 )
  {
    time(&timer);
    v5 = localtime(&timer);
    printf("\r%02d:%02d:%02d", v5->tm_hour, v5->tm_min, v5->tm_sec);
    fflush(stdout);
    sleep(1u);
  }
}
```

Which is odd, since we can't see our final print statement. I believe this is probably because we actually NEVER GET HERE WITHOUT SOME CRAZY UNDEFINED BEHAVIOUR LOL.
- Notice that we sit in the loop forever, which IDA shows nicely with the `while (1)` bit.

The graph view actually shows this "hidden code":

```asm
lea     rax, aHereSAFlagOrSo ; "Here's a flag or something: John OALabs"
mov     rdi, rax        ; format
mov     eax, 0
call    _printf
mov     eax, 0
mov     rdx, [rbp+var_8]
sub     rdx, fs:28h
jz      short locret_1245
```

In regards to the calling convention used here, the 4 bit C calling convention is used:
- Arguments are put in rdi, rsi, rdx, rex, r8, and r9.
- "If there are more than six parameters to the subroutine,
  then push the rest onto the stack in reverse order (i.e. last parameter first) -
  since the stack grows down, the first of the extra parameters (really the seventh parameter)
  parameter will be stored at the lowest address
  (this inversion of parameters was historically used to allow functions to be passed a variable number of parameters)"
- Source can be found [here](https://aaronbloomfield.github.io/pdr/book/x86-64bit-ccc-chapter.pdf)

Notice also the `mov eax,0` instructions before and after the print call.
- The one after is just the return code being given.
- The one **before** though is more interesting:
  - "When a function taking variable-arguments is called,
  %rax must be set to the total number of floating point parameters passed to the function in vector regis"
  - Src: https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
  - Basically since printf is variadic (see RE Playbook notes), we pass the 0 since we aren't giving any floating point values, just the strings.

This final "jump if zero" instruction MOST LIKELY is from checking the return code of the previous instruction, otherwise I'm unsure why it's there.

We can very easily see the full program, even if we rename `v5` to `timeStruct`, or some other name, we can very easily tell that it is a struct by the arrow operator usage, and the very simple logic in the program.
- Program gets the unix time w/ `time(&timer);`.
- Then we get localtime based on this unix time.
- Then we get the hour, minutes, and seconds by accessing the returned struct.
- Lastly we flush stdout (since on linux at least, this output is buffered for some reason?????????) and sleep for a second.

It's pretty easy to tell that this is just a clock program.

Something interesting that we can decipher from this "sample" is that examining disassembly is incredible important, on top of the decompiled view, since we may miss out on hidden information.
