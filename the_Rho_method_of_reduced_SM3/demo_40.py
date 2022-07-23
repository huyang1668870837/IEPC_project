import random
from gmssl import sm3, func
import time
start = time.time()

def encrypt_fun(strs):
    str_b = bytes(strs, encoding='utf-8')
    result = sm3.sm3_hash(func.bytes_to_list(str_b))
    return result
n=10 #碰撞的比特数除以4
result_list=[]
str_1=str((hex(random.randint(0,pow(2,n*4)))))
flag=0
str_1=encrypt_fun(str_1)
while(flag==0):
    result_list.append(str_1[-n:])
    str_1=encrypt_fun(str_1[-n:])
    if str_1[-n:] in result_list:
        print("消息1：",result_list[result_list.index(str_1[-n:])-1])
        print("sm3对消息1加密后的值：",encrypt_fun(result_list[result_list.index(str_1[-n:])-1]))
        print("sm3对消息1加密后的值后40bit：",encrypt_fun(result_list[result_list.index(str_1[-n:])-1])[-n:])
        print("消息2:",result_list[-1])
        print("sm3对消息2加密后的值：",encrypt_fun(result_list[-1]))
        print("sm3对消息2加密后的值后40bit：",encrypt_fun(result_list[-1])[-n:])
        flag=1
end = time.time()
print("程序运行时间：",end-start)