# 求checksum 方法一（详细）：
sum = 435628
print('{:d} --->  {:x}'.format(sum, sum))    # 435628 --->  6a5ac
high = sum >> 16
print('{:d} --->  {:x}'.format(high, high))  # 6 --->  6
low = sum & 0xffff
print('{:d} --->  {:x}'.format(low, low))  # 42412 --->  a5ac
sum = low + high
print('{:d} --->  {:x}'.format(sum, sum))  # 42418 --->  a5b2
sum += sum >> 16
print('{:d} --->  {:x}'.format(sum, sum))  # 42418 --->  a5b2
print('{:d} --->  {:x}'.format(~sum, ~sum))  # -42419 --->  -a5b3
print('{:d} --->  {:x}'.format(~sum & 0xffff, ~sum & 0xffff))  # 23117 --->  5a4d