# ApoorvCTF 2025
## Cryptography
1. Genjutsu Labyrinth

Đề bài cho ta đoạn code mã hóa như sau:
```
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randbytes

def main():
    key = randbytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    flag = b'apoorvctf{fake_flag_123}'

    print("Welcome to the ECB Oracle challenge!")
    print("Enter your input in hex format.")

    try:
        while True:
            print("Enter your input: ", end="", flush=True)
            userinput = sys.stdin.readline().strip()

            if not userinput:
                break

            try:
                userinput = bytes.fromhex(userinput)
                ciphertext = cipher.encrypt(pad(userinput + flag + userinput, 16))
                print("Ciphertext:", ciphertext.hex())

            except Exception as e:
                print(f"Error: {str(e)}")

    except KeyboardInterrupt:
        print("Server shutting down.")

if __name__ == "__main__":
    main()
```

Phân tích đoạn code mã hóa, ta nhận ra đây là dạng AES ECB Oracle, AES ECB có một điểm yếu là cùng một khối plaintext sẽ luôn tạo ra cùng một khối ciphertext khi sử dụng cùng một khóa. 
Đầu tiên ta xác định khoảng độ dài của flag bằng cách thử gửi độ dài của chuỗi input.

```
from Crypto.Util.number import *
from pwn import *

r = remote("chals1.apoorvctf.xyz", 4001)
print(r.recvline())
print(r.recvline())
print(r.recvuntil(b'input: '))

send = b'a' * 16
r.sendline(send)
print(r.recvuntil(b'text: '))
data = r.recvline().decode()
data = bytes.fromhex(data)
print(len(data))

r.interactive()
```

Sau một hồi thử thì nhận ra chuỗi flag có độ dài <= 32 do khi gửi chuỗi input có độ dài là 16 thì ciphertext nhận được có độ dài 64 (do 64 - 16 * 2 = 32). Ta thực hiện bruteforce lấy flag

```
from Crypto.Util.number import *
from pwn import *

r = remote("chals1.apoorvctf.xyz", 4001)
print(r.recvline())
print(r.recvline())
print(r.recvuntil(b'input: '))

flag = ''
for i in range(32):
    send = b'a' * (63 -  i)
    r.sendline((send.hex()).encode())
    r.recvuntil(b'text: ')
    data = r.recvline().decode()
    data1 = bytes.fromhex(data)
    for x in string.printable:
        send = b'a' * (63 -  i) + flag.encode() +  x.encode()
        r.sendline((send.hex()).encode())
        r.recvuntil(b'text: ')
        data = r.recvline().decode()
        data2 = bytes.fromhex(data)
        if(data1[:64] == data2[:64]):
            flag += x
            break
    print(flag)
r.interactive()
```

2. Finding Goku

Đề bài cho ta 2 tấm ảnh như sau:
![image](https://github.com/user-attachments/assets/c57e21f5-5736-4d44-a05b-ca089da9f1d8)
![image](https://github.com/user-attachments/assets/7d788898-985c-4a77-b4dd-f8607f8fc210)

Với mô tả của đề bài là: "In the age of the samurai, a forbidden scroll was split into two layers to conceal its secret. Only a warrior with keen vision can reunite them and reveal the truth".  Ta nghĩ ngay đến việc cộng từng pixel của 2 ảnh với nhau.

```
from PIL import Image
import numpy as np

img1 = Image.open("part1.png").convert("RGB")
img2 = Image.open("part2.png").convert("RGB")
arr1 = np.array(img1)
arr2 = np.array(img2)
result = arr1 + arr2
result_img = Image.fromarray(result)
result_img.save("output.png")
```

Sau khi lưu file output.png ta được kết quả như sau.
![output](https://github.com/user-attachments/assets/d9b48b9d-810e-4fc8-8552-7262a503f108)

Ta thực hiện phóng to ảnh để tìm ra flag ở giữa bức ảnh
![image](https://github.com/user-attachments/assets/e1ece703-8f6f-4ee9-991a-915a5f6bc6a6)

3. Finding Goku

Đề bài cho một đoạn code thực hiện kiểm tra hash của 2 input đầu vào khác nhau và so sánh hash của 2 input đó. Nếu hash của 2 input đó bằng nhau thì ta lấy được flag

```
import hashlib

def check_hex_data(hex1, hex2, start_string):
    if hex1 == hex2:
        return "Error: Even a Saiyan warrior knows that true strength lies in difference! The two inputs must not be identical."

    try:
        data1 = bytes.fromhex(hex1)
        data2 = bytes.fromhex(hex2)
    except ValueError:
        return "Error: Looks like you misfired a Ki blast! Invalid hex input detected."

    start_bytes = start_string.encode()

    if not (data1.startswith(start_bytes) and data2.startswith(start_bytes)):
        return "Error: These aren't true warriors! Both inputs must start with the legendary sign of 'GOKU' to proceed."

    def md5_hash(data):
        hasher = hashlib.md5()
        hasher.update(data)
        return hasher.hexdigest()

    hash1 = md5_hash(data1)
    hash2 = md5_hash(data2)

    if hash1 != hash2:
        return "Error: These warriors are impostors! They wear the same armor but their Ki signatures (MD5 hashes) don't match."

    try:
        with open("flag.txt", "r") as flag_file:
            flag = flag_file.read().strip()
        return f"🔥 You have found the real Goku! Your flag is: {flag}"
    except FileNotFoundError:
        return "Error: The Dragon Balls couldn't summon the flag! 'flag.txt' is missing."

if __name__ == "__main__":
    start_string = "GOKU"
    hex1 = input("Enter first hex data: ")
    hex2 = input("Enter second hex data: ")
    print(check_hex_data(hex1, hex2, start_string))
```

Ta phát hiện được lỗi khi so sánh hex1 và hex2 của code. Khi so sánh thì vẫn đang ở dạng chuỗi chưa được cắt khoảng trắng ở đầu và cuối. Vì thế ta nghĩ đến cách truyền vào 2 input có mã hex giống nhau, hex2 chỉ khác hex1 ở dấu " " ở cuối cùng. Vầ cuối cùng là bypass thành công.

```
from Crypto.Util.number import *
from pwn import *

r = remote("chals1.apoorvctf.xyz", 5002)
data = b'GOKU'
print(r.recvuntil(b'data: '))
r.sendline(data.hex().encode())
print(r.recvuntil(b'data: '))
r.sendline((data.hex() + " ").encode())
r.interactive()
```

Bài này có một cách khác là có thể tìm tool để liệt kê ra 2 chuỗi khác nhau mà có cùng hash, vì phát hiện ra lỗi so sánh của 2 input ban đầu nên mình không làm theo cách này nữa. Một số tool có thể tham khảo để làm theo cách này là https://github.com/cr-marcstevens/hashclash hoặc https://github.com/zhijieshi/md5collgen

4. Rigged_Roulette (tham khảo)

Đề bài cho một hệ rsa với p được tách nhỏ và thực hiện random nhiều lần trên các phần của số p đó. Đề bài cho biết với mỗi seed thì random tại các vị trí [0, 1, 2, 227, 228, 229]. 
```
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import random

flag = b"apoorvctf{fake_flag}"

def secret(p):
    prime_bytes = p.to_bytes(64, byteorder='big')  
    keys = [bytes_to_long(prime_bytes[i:i+4]) for i in range(0, 64, 4)] 
    enc_p = []
    for key in keys:
        tp = []
        random.seed(key)
        indexes = [0, 1, 2, 227, 228, 229]
        random_arr = [random.getrandbits(32) for _ in range(624)] 
        for j in indexes:
            tp.append(random_arr[j])
        enc_p.append(tp) 
    return enc_p

def encrypt():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = 65537
    c = pow(bytes_to_long(flag), e, n)
    trash = secret(p)  
    return n, c, trash  

def decrypt(n,p,c):
    q = n//p
    if p*q != n:
        print("Invalid n")
        return
    phi = (p-1)*(q-1)
    d = pow(65537,-1,phi)
    return long_to_bytes(pow(c,d,n))

n, c, trash = encrypt() 
print("n:", n)
print("c:", c)
print("trash:", trash)
```

file output.txt
```
n: 49812271074113996748256581712467459366588082361636023630564068214612994986892561558381532475755791032675276115848189703815816792642128355747597878537909137779400571814063186968473486503116149991224538115188352954146019052922869981051351571158735260001333011582577193684810211363872980264620807599594086051449
c: 20002117200090813595564977137423791696740924182449971750083551897250822585677154362121434423203173839416183117315744314791189230613149517277553117748654242567572304526577870897931051487912585476465888459445398180637679760443084368095041311696478979083217579778239459905993548371792893219935514397751847671981
trash: [[4094835185, 356762106, 3366297177, 3623603908, 2373193877, 3203846780], [3406548083, 4062546425, 1376818797, 394516489, 3907909298, 3898652639], [1287222167, 2995584073, 1693598779, 811229118, 1707629246, 3304354912], [1243120984, 3460569159, 2340013171, 172985849, 3180767622, 1551040428], [800057846, 2682940396, 123193243, 3036600707, 3794295715, 2393381294], [892967018, 2206189721, 2843934106, 1056160791, 2522099700, 1152632788], [2774545485, 3977855291, 4203604373, 3669198182, 3583908975, 1060491729], [4112967206, 3535798795, 3120649323, 25986165, 2427485753, 1350615610], [318330051, 2236838130, 2496969378, 3525774414, 4069600592, 2282092160], [563544583, 2592975485, 935828735, 2978557025, 2012930992, 995780339], [3460985768, 3379763321, 2949965528, 1505018344, 2512823468, 1021031395], [3394216535, 2529203380, 2768254272, 236994372, 1634295888, 1133018765], [2866010958, 1712165916, 1348052226, 1280486865, 3780769383, 2391071461], [3641791377, 3432968590, 3350590316, 1048613032, 3540539809, 2649316279], [1923548320, 656195356, 4041871255, 2963016066, 3551386262, 3046838184], [2069834435, 1706541602, 4050137025, 857681424, 2381793628, 2665835243]]
#Hint
1st seed starts with 2
2nd seed starts with 1
3rd seed starts with 3
4th seed starts with 1
5th seed starts with 2
6th seed starts with 3
7th seed starts with 2
8th seed starts with 3
9th seed starts with 6
10th seed starts with 1
11th seed starts with 3
12th seed starts with 7
13th seed starts with 3
14th seed starts with 2
15th seed starts with 2
16th seed starts with 2
```

Tìm kiếm cách crack seed random in python thì có một trang web như sau https://stackered.com/blog/python-random-prediction/. Với random số int 32 bit thì chỉ cần 6 số random tại lần lượt 6 vị trí [0, 1, 2, 227, 228, 229] là có thể tìm được 2 seed phù hợp với random đó. Dựa vào hint seed bắt đầu với số nào thì ta có thể xác định chính xác seed ban đầu và tìm ra được p. Dưới đây là cách khai thác.

```
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

def init_genrand(seed):
        MT = [0] * 624
        MT[0] = seed & 0xffffffff
        for i in range(1, 623+1): 
            MT[i] = ((0x6c078965 * (MT[i-1] ^ (MT[i-1] >> 30))) + i) & 0xffffffff
        return MT

def invertStep(si, si227):
    X = si ^ si227
    mti1 = (X & 0x80000000) >> 31
    if mti1:
        X ^= 0x9908b0df
    X <<= 1
    mti = X & 0x80000000
    mti1 += X & 0x7FFFFFFF
    return mti, mti1

def unshiftRight(x, shift):
    res = x
    for i in range(32):
        res = x ^ res >> shift
    return res

def unshiftLeft(x, shift, mask):
    res = x
    for i in range(32):
        res = x ^ (res << shift & mask)
    return res

def untemper(v):
    v = unshiftRight(v, 18)
    v = unshiftLeft(v, 15, 0xefc60000)
    v = unshiftLeft(v, 7, 0x9d2c5680)
    v = unshiftRight(v, 11)
    return v

def recover_Ji_from_Ii(Ii, Ii1, i):
    ji = (Ii + i) ^ ((Ii1 ^ (Ii1 >> 30)) * 1566083941)
    ji &= 0xffffffff
    return ji

def recover_kj_from_Ji(ji, ji1, i):
    const = init_genrand(19650218)
    key = ji - (const[i] ^ ((ji1 ^ (ji1 >> 30))*1664525))
    key &= 0xffffffff
    return key

def recover_Kj_from_Ii(Ii, Ii1, Ii2, i):
    Ji = recover_Ji_from_Ii(Ii, Ii1, i)
    Ji1 = recover_Ji_from_Ii(Ii1, Ii2, i-1)
    return recover_kj_from_Ji(Ji, Ji1, i)

def solve(arr, start):
    for i in range(6):
        arr[i] = untemper(arr[i])
    I_227_, I_228 = invertStep(arr[0], arr[3])
    I_228_, I_229 = invertStep(arr[1], arr[4])
    I_229_, I_230 = invertStep(arr[2], arr[5])

    I_228 += I_228_
    I_229 += I_229_

    seed1 = recover_Kj_from_Ii(I_230, I_229, I_228, 230)
    seed2 = recover_Kj_from_Ii(I_230+0x80000000, I_229, I_228, 230)
    
    if(str(seed1)[0] == str(start)[0]): 
        return seed1
    return seed2

def decrypt(n,p,c):
    q = n//p
    if p*q != n:
        print("Invalid n")
        return
    phi = (p-1)*(q-1)
    d = pow(65537,-1,phi)
    return long_to_bytes(pow(c,d,n))

n = 49812271074113996748256581712467459366588082361636023630564068214612994986892561558381532475755791032675276115848189703815816792642128355747597878537909137779400571814063186968473486503116149991224538115188352954146019052922869981051351571158735260001333011582577193684810211363872980264620807599594086051449
c = 20002117200090813595564977137423791696740924182449971750083551897250822585677154362121434423203173839416183117315744314791189230613149517277553117748654242567572304526577870897931051487912585476465888459445398180637679760443084368095041311696478979083217579778239459905993548371792893219935514397751847671981
trash = [[4094835185, 356762106, 3366297177, 3623603908, 2373193877, 3203846780], [3406548083, 4062546425, 1376818797, 394516489, 3907909298, 3898652639], [1287222167, 2995584073, 1693598779, 811229118, 1707629246, 3304354912], [1243120984, 3460569159, 2340013171, 172985849, 3180767622, 1551040428], [800057846, 2682940396, 123193243, 3036600707, 3794295715, 2393381294], [892967018, 2206189721, 2843934106, 1056160791, 2522099700, 1152632788], [2774545485, 3977855291, 4203604373, 3669198182, 3583908975, 1060491729], [4112967206, 3535798795, 3120649323, 25986165, 2427485753, 1350615610], [318330051, 2236838130, 2496969378, 3525774414, 4069600592, 2282092160], [563544583, 2592975485, 935828735, 2978557025, 2012930992, 995780339], [3460985768, 3379763321, 2949965528, 1505018344, 2512823468, 1021031395], [3394216535, 2529203380, 2768254272, 236994372, 1634295888, 1133018765], [2866010958, 1712165916, 1348052226, 1280486865, 3780769383, 2391071461], [3641791377, 3432968590, 3350590316, 1048613032, 3540539809, 2649316279], [1923548320, 656195356, 4041871255, 2963016066, 3551386262, 3046838184], [2069834435, 1706541602, 4050137025, 857681424, 2381793628, 2665835243]]
hint = [2,1,3,1,2,3,2,3,6,1,3,7,3,2,2,2]

res = []
for i in range(16):
    res.append(solve(trash[i], hint[i]))

p = b''
for x in res:
    p += long_to_bytes(x)
p = bytes_to_long(p)
print(decrypt(n, p, c))
```

