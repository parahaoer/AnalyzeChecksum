# 求checksum 方法一
a = 0x01
b = 0x00 + a << 8
print('{:d} --->  {:x}'.format(b, b))  # 256 --->  100

# 0800 + 0000 + 0001 + 0001 + 6162 + 6364 + 6566 + 6768 + 696a + 6b6c +6d6e + 6f70 + 7172 + 7374 + 7576 + 7761 + 6263 + 6465 + 6667 + 6869

arr = [0x0008, 0x0000, 0x0100, 0x0100, 0x6261, 0x6463, 0x6665, 0x6867, 0x6a69, 0x6c6b, 0x6e6d, 0x706f, 0x7271, 0x7473, 0x7675, 0x6177, 0x6362, 0x6564, 0x6766, 0x6968]
sum = 0
for item in arr:
    sum += item
print(sum)
sum = (sum >> 16) + (sum & 0xffff)
sum += (sum >> 16)  #如果还有高于16位，将继续与低16位相加
answer = ~sum & 0xffff  #对sum取反(返回的是十进制)
#主机字节序转网络字节序列（参考小端序转大端序）
answer = answer >> 8 | (answer << 8 & 0xff00)
print('{:d} --->  {:x}'.format(answer, answer))