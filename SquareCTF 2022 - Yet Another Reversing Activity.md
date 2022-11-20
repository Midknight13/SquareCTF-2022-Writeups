# Description
>Points: 300  
>Topics: reversing

>Supposedly [this file](https://2022.squarectf.com/static/files/yet-another-reversing-activity/flag.yarc) can recognize a flag. But what could it be?

# Background
### the heck is this file?
Downloading the file and opening it in a hex editor such as [HexEd.it](https://hexed.it) reveals that its header begins with `YARA`. This, combined with the challenge name spelling out "YARA," means that we're definitely dealing with a compiled [YARA](https://virustotal.github.io/yara/) file.

### the heck is a yara?
YARA is a language in which we can write rules for "recognizing" certain files, commonly used for identifying malware samples. For example, if we want to recognize all files containing the string "test-flag" or "another-test-flag" as flags, we can write the following rule:
```
rule flag
{
	strings:
		$a = "test-flag"
		$b = "another-test-flag"
	condition:
		$a or $b
}
```
This rule can then be compiled into `compiled.yarc` by running the command `yarac64.exe rules.txt compiled.yarc` (or the equivalent for other OS's) using the tool from the [YARA GitHub](https://github.com/VirusTotal/yara/releases). After that, we can run  `yara64.exe -C compiled.yarc testfile.txt` to determine if `testfile.txt` matches our rule. If it does, we will see the output `flag testfile.txt`.

### Wait a minute so that's all the challenge file does?
Nope, sadly. If we use a hex editor to open the `compiled.yarc` file we generated above, we'll note that the strings `test-flag` and `another-test-flag` are clearly visible in plaintext even after compilation. The same does not go for `flag.yarc`, so they're clearly doing something less trivial. And to make matters worse, I was unable to find a working decompiler online (which makes sense, as such a decompiler would trivialize this 300-point problem). So...

# It's hex time babyyyy
>My favorite part of the YARA challenge was when they said "it's hex time" and hexed all over those guys.

Let's dive deeper into the raw hex of `flag.yarc`. The specific point of interest is everything after `64 65 66 61 75 6C 74 00 66 6C 61 67` (ASCII for `default flag`. If we look at `compiled.yarc` which we made earlier, this same sequence is present there and signifies the start of the `flag` rule).

The data we see here looks like this:
```
3c 00 f0 3c 5f 3c 39 07 64 2f 0f 00 00 00 3c 01 f0 3c 33 3c 5f 07 64 01 2f 0f 00 00 00 3c 02 f0 3c f8 3c 99 07 64 01 2f 0f 00 00 00 3c 03 f0 3c 53 3c 34 07 64 01 2f 0f 00 00 00 3c 04 f0 3c f8 3c 83 07 64 01 2f 0f 00 00 00 3c 05 f0 3c 9a 3c f7 07 64 01 2f 0f 00 00 00 3c 06 f0 3c dd 3c ee 07 64 01 2f 0f 00 00 00 3c 07 f0 3c 5c 3c 6f 07 64 01 2f 0f 00 00 00 3c 08 f0 3c f9 3c 8d 07 64 01 2f 0f 00 00 00 3c 09 f0 3c f9 3c a6 07 64 01 2f 0f 00 00 00 3c 0a f0 3c c8 3c a5 07 64 01 2f 0f 00 00 00 3c 0b f0 3c 80 3c e5 07 64 01 2f 0f 00 00 00 3c 0c f0 3c 86 3c d9 07 64 01 2f 0f 00 00 00 3c 0d f0 3c 0d 3c 3c 07 64 01 2f 0f 00 00 00 3c 0e f0 3c 65 3c 0b 07 64 01 2f 0f 00 00 00 3c 0f f0 3c 77 3c 28 07 64 01 2f 0f 00 00 00 3c 10 f0 3c 8f 3c b8 07 64 01 2f 0f 00 00 00 3c 11 f0 3c 80 3c e8 07 64 01 2f 0f 00 00 00 3c 12 f0 3c aa 3c 99 07 64 01 2f 0f 00 00 00 3c 13 f0 3c 28 3c 77 07 64 01 2f 0f 00 00 00 3c 14 f0 3c 69 3c 08 07 64 01 2f 0f 00 00 00 3c 15 f0 3c 56 3c 24 07 64 01 2f 0f 00 00 00 3c 16 f0 3c a1 3c 92 07 64 01 2f 0f 00 00 00 3c 17 f0 3c 2a 3c 44 07 64 01 2f 0f 00 00 00 3c 18 f0 3c ec 3c d8 07 64 01 2f 0f 00 00 00 3c 19 f0 3c ea 3c 97 07 64
```
Ew.

Bleghhhhhhh.

But! If we stare long enough into this abyss, we start to notice structure! Specifically, it seems like the data is just `3c 00 f0 3c 5f 3c 39 07 64 2f 0f 00 00 00` repeating over and over again with minor differences each time. Let's format it to be a little more human-readable.

```
00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 <- COLUMN NUMBER, NOT DATA

3c 00 f0 3c 5f 3c 39 07 64 [] 2f 0f 00 00 00
3c 01 f0 3c 33 3c 5f 07 64 01 2f 0f 00 00 00
3c 02 f0 3c f8 3c 99 07 64 01 2f 0f 00 00 00
3c 03 f0 3c 53 3c 34 07 64 01 2f 0f 00 00 00
3c 04 f0 3c f8 3c 83 07 64 01 2f 0f 00 00 00
3c 05 f0 3c 9a 3c f7 07 64 01 2f 0f 00 00 00
3c 06 f0 3c dd 3c ee 07 64 01 2f 0f 00 00 00
3c 07 f0 3c 5c 3c 6f 07 64 01 2f 0f 00 00 00
3c 08 f0 3c f9 3c 8d 07 64 01 2f 0f 00 00 00
3c 09 f0 3c f9 3c a6 07 64 01 2f 0f 00 00 00
3c 0a f0 3c c8 3c a5 07 64 01 2f 0f 00 00 00
3c 0b f0 3c 80 3c e5 07 64 01 2f 0f 00 00 00
3c 0c f0 3c 86 3c d9 07 64 01 2f 0f 00 00 00
3c 0d f0 3c 0d 3c 3c 07 64 01 2f 0f 00 00 00
3c 0e f0 3c 65 3c 0b 07 64 01 2f 0f 00 00 00
3c 0f f0 3c 77 3c 28 07 64 01 2f 0f 00 00 00
3c 10 f0 3c 8f 3c b8 07 64 01 2f 0f 00 00 00
3c 11 f0 3c 80 3c e8 07 64 01 2f 0f 00 00 00
3c 12 f0 3c aa 3c 99 07 64 01 2f 0f 00 00 00
3c 13 f0 3c 28 3c 77 07 64 01 2f 0f 00 00 00
3c 14 f0 3c 69 3c 08 07 64 01 2f 0f 00 00 00
3c 15 f0 3c 56 3c 24 07 64 01 2f 0f 00 00 00
3c 16 f0 3c a1 3c 92 07 64 01 2f 0f 00 00 00
3c 17 f0 3c 2a 3c 44 07 64 01 2f 0f 00 00 00
3c 18 f0 3c ec 3c d8 07 64 01 2f 0f 00 00 00
3c 19 f0 3c ea 3c 97 07 64
```
Columns `00, 02, 03, 05, 07, 09, 10, 11, 12, 13, 14` remain constant. Column `01` is just a hex index which is increasing by 1. The only other two columns are `04` and `06`, which seem to have arbitrary bytes in them (everything from `0b` to `f9`).

# Checkpoint Reached
Let's take a bit to summarize what we know so far:
- We have a compiled YARA rule which will match a file which contains whatever the flag is.
- The way they check this is less trivial than simply checking if the file contains the flag as a string.
- The compiled rule seems to consist of 26 extremely similar "operations," the only changes between which are two bytes.

This last one is extremely important. If we want to detect a string that looks something like `flag{some-random-data-here}` by only using roughly 25 extremely similar and short operations, what's the easiest way to do that? Just check each letter of the file one by one! e.g.
```
// pseudocode
if file[0] == 'f' and file[1] == 'l' and file[2] == 'a' and file[3] == 'g' and file[4] == '{' and etc.
	match()
```

### How would we do this in YARA?
Surfing the worldwide web eventually dumps us on the shores of [this documentation](https://yara.readthedocs.io/en/stable/writingrules.html#accessing-data-at-a-given-position). If we want to check the first four bytes of our file (recall that an ASCII character is just a byte value), we can write
```
rule test
{
	condition:
		int8(0) == 0x66 and
		int8(1) == 0x6c and
		int8(2) == 0x61 and
		int8(3) == 0x67
}
```
or alternatively:
```
rule test
{
	condition:
		int16(0) == 0x666c and
		int16(2) == 0x6167
}
```
(we can also use `int32` or some of the other types of `int8/16` but let's focus on these for now)

Let's compile both of these rules to see what they look like. In the `int8` example, the rule itself gets compiled to the bytes 
```
3c 00 f0 3c 66 64 2f 0c 00 00 00
3c 01 f0 3c 6c 64 01 2f 0c 00 00 00
3c 02 f0 3c 61 64 01 2f 0c 00 00 00
3c 03 f0 3c 67 64
```
In the `int16` example, we get
```
3c 00 f1 3d 6c 66 64 2f 0d 00 00 00
3c 02 f1 3d 67 61 64
```
Both of these looks pretty close to `flag.yarc`! We're on the right track. Let's compare a line from `flag.yarc`:
```
3c 01 f0 3c 33 3c 5f 07 64 01 2f 0f 00 00 00
```
The third and fourth columns are `f0 3c`. Based on the fact that our `int8` code compiled with `f0 3c` in columns 3/4 and `int16` compiled to `f1 3d`, we can make an educated guess that **seeing an `f0 3c` indicates that we're dealing with `int8` data** (this also matches up with the fact that column 2 — what I termed the "index" — counts up in steps of 1 instead of steps of 2 in `flag.yarc`. We can guess that that is the offset, in bytes).

### What's the difference between what we did and `flag.yarc`?
```
3c 01 f0 3c 6c          64 01 2f 0c 00 00 00    |   Our test file
3c 01 f0 3c 33 3c 5f 07 64 01 2f 0f 00 00 00    |   flag.yarc
```
The operations in `flag.yarc` contain three extra bytes. We saw earlier that the `3c` and `07` bytes remain constant in each operation, while the column which here contains `5f` can contain any arbitrary byte. So this line of bytecode represents comparing one byte from the file being tested with two bytes of our choosing.

What are some reasonable ways to compare one byte to two bytes? The easiest is just comparing a byte to the sum of the other two, i.e. `int8(0) == 0x13 + 0x37`. A full YARA rule would look something like
```
rule test
{
	condition:
		int8(0) == 0x10 + 0x20 and
		int8(1) == 0x11 + 0x21 and
		int8(2) == 0x12 + 0x22 and
		int8(3) == 0x13 + 0x23
}
```
This compiles to
```
3c 00 f0 3c 10 3c 20 6a 64 2f 0f 00 00 00
3c 01 f0 3c 11 3c 21 6a 64 01 2f 0f 00 00 00
3c 02 f0 3c 12 3c 22 6a 64 01 2f 0f 00 00 00
3c 03 f0 3c 13 3c 23 6a 64
```
We're so close!! If we compare a line from this to a line from `flag.yarc`:
```
3c 01 f0 3c 11 3c 21 6a 64 01 2f 0f 00 00 00    |   Our test file
3c 01 f0 3c 33 3c 5f 07 64 01 2f 0f 00 00 00    |   flag.yarc
```
The only differences are in:
- Columns 5 and 7, which is where the bytes we're adding together are stored
- Column 8, where our test file consistently has `6a` while `flag.yarc` has `07`
We can make an educated guess that the value in Column 8 represents what operation is being performed on the two bytes we're comparing to. `6a` must represent addition. All that's left is to go through the operations in YARA, a list of which can be found [here](https://yara.readthedocs.io/en/stable/writingrules.html#conditions).

Eventually, we find that the operation which gives `07` is XOR. **We've successfully reverse-engineered the whole program!** The decompiled code would look something like:
```
rule flag
{
	condition:
		int8(0) == 0x[][] ^ 0x[][] and
		int8(1) == 0x[][] ^ 0x[][] and
		etc.
}
```
We recall that the specific bytes we're XORing together are just columns 5 and 7 of `flag.yarc`:
```
5f 33 f8 53 f8 9a dd 5c f9 f9 c8 80 86 0d 65 77 8f 80 aa 28 69 56 a1 2a ec ea

39 5f 99 34 83 f7 ee 6f 8d a6 a5 e5 d9 3c 0b 28 b8 e8 99 77 08 24 92 44 d8 97
```
We can now XOR each these columns together and decode the result as ASCII to get the flag:
`flag{m33t_me_1n_7h3_ar3n4}`

# the heck did we just do??
TL;DR:
- We were given a file with compiled YARA rules. We were told that this file is capable of detecting the flag for this challenge.
- We looked at the structure of the compiled rules and noticed that it's probably checking each letter one by one.
- We compiled some test scripts which also check letters one by one, to see how their structure compares to that of `flag.yarc`.
- We noticed that `flag.yarc` compares one byte (int8) to two bytes. This made us suspect that those bytes are first thrown into a binary operation like addition, and then the result is what we're comparing to.
- We went through all the binary operations in YARA until we found one with the right opcode (XOR, opcode `07`).
- We XOR'd together each of the pairs of bytes that the script compares bytes of the flag file to. This gave us the sequence of bytes that the script was expecting the file to match, i.e. the flag.
