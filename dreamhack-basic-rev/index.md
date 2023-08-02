# [dreamhack.io] Basic Reversing Challenges


<!--more-->

## rev-basic-4

The challenge is too easy to explain so... here is my code:

```cpp
#include <iostream>
#include <map>
using namespace std;

int main() {
    map<uint8_t, char> memory;
    for (uint8_t i = 0x20; i < 0x7f; i++) {
        memory[(i * 16) | (i >> 4)] = char(i);
    }
    uint8_t flag[28] = {0x24, 0x27, 0x13, 0xC6, 0xC6, 0x13, 0x16, 0xE6, 0x47, 0xF5, 0x26, 0x96, 0x47, 0x0F5, 0x46, 0x27, 0x13, 0x26, 0x26, 0x0C6, 0x56, 0xF5, 0xC3, 0xC3, 0xF5, 0xE3, 0xE3};
    for (int i = 0; i < 28; i++) {
        cout << memory[flag[i]];
    }
    cout << '\n';
}
```

{{< admonition warning >}}
The only thing you need to be careful with is the `uint8_t`.
{{< /admonition >}}

## rev-basic-5

At first, I tried a brute-force approach. Howerver, it was quite challenging to see the flag.

```cpp
#include <iostream>
#include <map>
using namespace std;

int main() {
    uint8_t flag_enc[23] = {173, 216, 203, 203, 157, 151, 203, 196, 146, 161, 210, 215, 210, 214, 168, 165, 220, 199, 173, 163, 161, 152, 76};
    char flag_dec[24];
    for (char fi = 0x20; fi < 0x7e; fi++) {
        flag_dec[0] = fi;
        for (int i = 1; i < 24; i++) {
            flag_dec[i] = flag_enc[i - 1] - flag_dec[i - 1];
        }
        for (int i = 0; i < 24; i++) {
            cout << flag_dec[i];
        }
        cout << '\n';
    }
    cout << '\n';
}
```

Later, I saw the flag and reliazed...

```bash
?njaj3dg]5lfqau3rj]PSNJ  
@mk`k2ef^4mer`v2si^OTMK  
All_l1fe_3nds_w1th_NULL  
Bkm^m0gd`2oct^x0ug`MVKM�  
Cjn]n/hca1pbu]y/vfaLWJN�  
```

To print only the valid flag, we can use this code snippet:
```cpp
if (flag_dec[23] == 0) {
    cout << flag_dec << '\n';
}
```

Alternatively, a better approach would be:

```cpp
#include <iostream>
using namespace std;

int main() {
    int flag_enc[23] = {173, 216, 203, 203, 157, 151, 203, 196, 146, 161, 210, 215, 210, 214, 168, 165, 220, 199, 173, 163, 161, 152, 76};
    int flag_dec[24];
    flag_dec[23] = 0;
    for (int i = 22; i >= 0; i--) {
        flag_dec[i] = flag_enc[i] - flag_dec[i + 1];
    }
    for (int i = 0; i < 24; i++) {
        cout << char(flag_dec[i]);
    }
    cout << '\n';
}
```

## rev-basic-6

After disassembling the file, you will easily see that the flag checker part is:

```cpp
__int64 __fastcall sub_140001000(__int64 a1)
{
  int i; // [rsp+0h] [rbp-18h]

  for ( i = 0; (unsigned __int64)i < 0x12; ++i )
  {
    if ( byte_140003020[*(unsigned __int8 *)(a1 + i)] != byte_140003000[i] )
      return 0i64;
  }
  return 1i64;
}
```

You can take a look at the memory at `byte_140003020`:

```bash
0000000140003020  63 7C 77 7B F2 6B 6F C5  30 01 67 2B FE D7 AB 76
0000000140003030  CA 82 C9 7D FA 59 47 F0  AD D4 A2 AF 9C A4 72 C0
0000000140003040  B7 FD 93 26 36 3F F7 CC  34 A5 E5 F1 71 D8 31 15
0000000140003050  04 C7 23 C3 18 96 05 9A  07 12 80 E2 EB 27 B2 75
0000000140003060  09 83 2C 1A 1B 6E 5A A0  52 3B D6 B3 29 E3 2F 84
0000000140003070  53 D1 00 ED 20 FC B1 5B  6A CB BE 39 4A 4C 58 CF
0000000140003080  D0 EF AA FB 43 4D 33 85  45 F9 02 7F 50 3C 9F A8
0000000140003090  51 A3 40 8F 92 9D 38 F5  BC B6 DA 21 10 FF F3 D2
00000001400030A0  CD 0C 13 EC 5F 97 44 17  C4 A7 7E 3D 64 5D 19 73
00000001400030B0  60 81 4F DC 22 2A 90 88  46 EE B8 14 DE 5E 0B DB
00000001400030C0  E0 32 3A 0A 49 06 24 5C  C2 D3 AC 62 91 95 E4 79
00000001400030D0  E7 C8 37 6D 8D D5 4E A9  6C 56 F4 EA 65 7A AE 08
00000001400030E0  BA 78 25 2E 1C A6 B4 C6  E8 DD 74 1F 4B BD 8B 8A
00000001400030F0  70 3E B5 66 48 03 F6 0E  61 35 57 B9 86 C1 1D 9E
0000000140003100  E1 F8 98 11 69 D9 8E 94  9B 1E 87 E9 CE 55 28 DF
0000000140003110  8C A1 89 0D BF E6 42 68  41 99 2D 0F B0 54 BB 16
```

Now, let's write the script to decrypt the flag:

```python
from pwn import *

with open('../bin/chall6.exe', 'rb') as f:
    file_data = f.read()
    start_pos = file_data.find(b'\x63\x7C\x77\x7B\xF2\x6B\x6F\xC5')

table = file_data[start_pos : start_pos + 128]
flag = [0x0, 0x4D, 0x51, 0x50, 0x0EF, 0x0FB, 0x0C3, 0x0CF, 0x92, 0x45, 0x4D, 0x0CF, 0x0F5, 0x4, 0x40, 0x50, 0x43, 0x63]

reverse = dict()
for i in range(128):
    reverse[table[i]] = i

print(''.join([chr(reverse[i]) for i in flag])[:-1]) # [:-1] to remove \x00 at the end
```

## rev-basic -7

### IDA

After disassembling with IDA, I noticed a function called `__ROL1__()` (which seems unfamiliar to me):
```cpp
__int64 __fastcall sub_140001000(__int64 a1)
{
  int i; // [rsp+0h] [rbp-18h]

  for ( i = 0; (unsigned __int64)i < 31; ++i )
  {
    if ( (i ^ (unsigned __int8)__ROL1__(*(_BYTE *)(a1 + i), i & 7)) != byte_140003000[i] )
      return 0i64;
  }
  return 1i64;
}
```
Open `[your_ida_dir]\plugins\hexrays_sdk\include\defs.h` and you will see the implementation and the purpose of this function:
```cpp
// rotate left
template<class T> T __ROL__(T value, int count)
{
  const uint nbits = sizeof(T) * 8;

  if ( count > 0 )
  {
    count %= nbits;
    T high = value >> (nbits - count);
    if ( T(-1) < 0 ) // signed value
      high &= ~((T(-1) << count));
    value <<= count;
    value |= high;
  }
  else
  {
    count = -count % nbits;
    T low = value << (nbits - count);
    value >>= count;
    value |= low;
  }
  return value;
}

inline uint8  __ROL1__(uint8  value, int count) { return __ROL__((uint8)value, count); }
inline uint16 __ROL2__(uint16 value, int count) { return __ROL__((uint16)value, count); }
inline uint32 __ROL4__(uint32 value, int count) { return __ROL__((uint32)value, count); }
inline uint64 __ROL8__(uint64 value, int count) { return __ROL__((uint64)value, count); }
inline uint8  __ROR1__(uint8  value, int count) { return __ROL__((uint8)value, -count); }
inline uint16 __ROR2__(uint16 value, int count) { return __ROL__((uint16)value, -count); }
inline uint32 __ROR4__(uint32 value, int count) { return __ROL__((uint32)value, -count); }
inline uint64 __ROR8__(uint64 value, int count) { return __ROL__((uint64)value, -count); }
```
{{< admonition note >}}
The function `__ROL1__()` rotates the `unsigned __int8` value by `count` bits to the left.
{{< /admonition >}}
So just use the function `__ROR1__()` to reverse the flag from `byte_140003000`:
```cpp
#include <iostream>
using namespace std;

template<class T> T __ROL__(T value, int count)
{
  const uint nbits = sizeof(T) * 8;

  if ( count > 0 )
  {
    count %= nbits;
    T high = value >> (nbits - count);
    if ( T(-1) < 0 ) // signed value
      high &= ~((T(-1) << count));
    value <<= count;
    value |= high;
  }
  else
  {
    count = -count % nbits;
    T low = value << (nbits - count);
    value >>= count;
    value |= low;
  }
  return value;
}

inline uint8_t  __ROL1__(uint8_t  value, int count) { return __ROL__((uint8_t)value, count); }
inline uint8_t  __ROR1__(uint8_t  value, int count) { return __ROL__((uint8_t)value, -count); }

int main() {
    uint8_t flag[32] = {0x52, 0xDF, 0xB3, 0x60, 0xF1, 0x8B, 0x1C, 0xB5, 0x57, 0xD1, 0x9F, 0x38, 0x4B, 0x29, 0xD9, 0x26, 0x7F, 0xC9, 0xA3, 0xE9, 0x53, 0x18, 0x4F, 0xB8, 0x6A, 0xCB, 0x87, 0x58, 0x5B, 0x39, 0x1E, 0x00};
    for (int i = 0; i < 31; i++) {
        flag[i] = char(__ROR1__(flag[i] ^ i, i & 7));
    }
    cout << flag << '\n';
}
```

### Ghidra

If you disassemble with Ghidra, you will get:

```cpp
undefined8 FUN_140001000(longlong param_1)

{
  byte bVar1;
  uint local_18;
  
  local_18 = 0;
  while( true ) {
    if (30 < local_18) {
      return 1;
    }
    bVar1 = (byte)local_18 & 7;
    if (((byte)(*(byte *)(param_1 + (int)local_18) << bVar1 |
               *(byte *)(param_1 + (int)local_18) >> 8 - bVar1) ^ local_18) !=
        (uint)(byte)(&DAT_140003000)[(int)local_18]) break;
    local_18 = local_18 + 1;
  }
  return 0;
}
```

Here is my reverse for this:

```cpp
#include <iostream>
using namespace std;

int main() {
    uint8_t flag[32] = {0x52, 0xDF, 0xB3, 0x60, 0xF1, 0x8B, 0x1C, 0xB5, 0x57, 0xD1, 0x9F, 0x38, 0x4B, 0x29, 0xD9, 0x26, 0x7F, 0xC9, 0xA3, 0xE9, 0x53, 0x18, 0x4F, 0xB8, 0x6A, 0xCB, 0x87, 0x58, 0x5B, 0x39, 0x1E, 0x00};
    for (int i = 0; i < 31; i++) {
        uint8_t j = i & 7, x = flag[i] ^ i;
        flag[i] = (x >> j) | (x << (8 - j));
    }
    cout << flag << '\n';
}
```

