# Learning z3 with me


<!--more-->

{{< admonition quote >}}
z3 seem like magic to me. The harder it is, the more I want to learn it.
{{< /admonition >}}

## What is z3

{{< admonition info >}}
"Z3 is an efficient Satisfiability Modulo Theories (SMT) solver from Microsoft Research. Z3 is a solver for symbolic logic, a foundation for many software engineering tools. SMT solvers rely on a tight integration of specialized engines of proof. Each engine owns a piece of the global puzzle and implements specialized algorithms."
{{< /admonition >}}

## An easy examples

Suppose I have this crack-me, and you want to crack it. How can you do that?  

```cpp
#include <stdio.h>
using namespace std;

int main() {
	long long num;
	printf("num = ");
	scanf("%lld", &num);
	int digitSum = 0, len = 0;
	while (num > 0) {
		digitSum += num % 10;
		num /= 10;
		len++;
	}
	if (len == 17 && digitSum == 123) {
		puts("Correct!");
	}
	else {
		puts("Wrong!");
	}
}
```

The condition are straightforward, so you can break it through manual condition.  
However, let's use this as a starting example. You can solve it using z3, like this:

```python
# Import the z3 library
from z3 import *

# Optimize API provides methods for solving using
# objective functions and weighted soft constraints
opt = Optimize()

# Given the condition from line 17 of the code above we know that `len` = 17
# The list `digits` will store all the num_{i} for i in [0, 17)
# where num_{i} represents the i-th digit of `num`
digits = []

# Loop through all digits
for i in range(17):

    # Create the lable num_{i} with an integer type
    num_i = Int(f'num_{i}')

    # Add conditions for this lable
    # Each digit will have value in [0, 9]
    # except the first one, which will have a value in (0, 9]
    if i == 0:
        opt.add(num_i > 0)
    else:
        opt.add(num_i >= 0)
    opt.add(num_i <= 9)

    # Save the lable to the list
    digits.append(num_i)

# Create the label digitSum, which equal the sum of all digits
digitSum = Int('digitSum')
opt.add(digitSum == sum(digits))

# Add the condition digitSum == 123, as we decuded from the code above
opt.add(digitSum == 123)

# Check if a model that satisfies the condition is solvable
if opt.check() == sat:
    # Print the answer from the model
    model = opt.model()
    print('Answer:', end=' ')
    print(''.join([chr(model[i].as_long() + ord('0')) for i in digits]))

else:
    # When there is no answer
    print('No answer!')
```

Upon running the script, you'll obtain the answer:

```bash
Answer: 99996999999199800
```

Testing this with the crack-me:

```bash
num = 99996999999199800
Correct!
```

## Apply it to a CTF Task
Now let's solve the `collision` task on pwnable.kr.  
I initially solved it through manual calculation, but now let's have some fun with z3.

The problem statement:

{{< admonition info >}}
Daddy told me about cool MD5 hash collision today.  
I wanna do something like that too!

ssh col@pwnable.kr -p2222 (pw:guest)
{{< /admonition >}}

Okay let's connect to the server and retrive the source code:

```bash
allforest01@Kiese ~ » (base) ssh col@pwnable.kr -p2222
col@pwnable.kr's password:
 ____  __    __  ____    ____  ____   _        ___      __  _  ____
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    /
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|

- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Wed Aug  2 09:51:46 2023 from 171.225.250.124
col@pwnable:~$ ls
col  col.c  flag
col@pwnable:~$ cat col.c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
col@pwnable:~$ _
```

We will focus on this section of the source code:

```cpp
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}
```

This function converts `char*` to `int*`, requiring us to convert 4-byte chars to int when calculating.  
And yeah this problem bears resemblance to the one we disscussed earlier. Let's use z3 to compute the password.

```python
from z3 import *

# This function converts 4 consecutive bytes to an int
def four_char_to_int(arr):

    # The arr must be 4 bytes in length
    assert len(arr) == 4

    # Just perform a base conversion
    ret = 0
    for i in reversed(range(4)):
        ret = ret * 256 + arr[i]
    
    return ret

opt = Optimize()

# This list stores the resulting lables
result = []

for i in range(20):

    char_i = Int(f'char_{i}')

    # Character condition
    opt.add(char_i >= 0x20)
    opt.add(char_i  < 0x7f)

    result.append(char_i)

# This list stores all the converted numbers
numbers = []

for i in range(0, 20, 4):

    # Convert 4 consecutive bytes to an int
    number = four_char_to_int(result[i : i + 4])
    numbers.append(number)

mySum = Int('mySum')

# Attention: Integer overflow !!!
opt.add(mySum == sum(numbers) % 0x100000000)

# Add the task condition
opt.add(mySum == 0x21DD09EC)

if opt.check() == sat:
    model = opt.model()
    print('Password:', end=' ')
    print(''.join([chr(model[i].as_long()) for i in result]))

else:
    print('No answer!')
```

Upon running this script, you'll get the password:

```bash
Password: ex;oYe~q<8[tt{Jp~x}\
```

Now, let's retrive the flag using this password:

{{< admonition tip >}}
You will need to replace `;`, `<`, `\` with `\;`, `\<`, `\\`.
{{< /admonition >}}

```bash
col@pwnable:~$ ./col ex\;oYe~q\<8[tt{Jp~x}\\
daddy! I just managed to create a hash collision :)
col@pwnable:~$ _
```

[This posts is currently being updated...]

