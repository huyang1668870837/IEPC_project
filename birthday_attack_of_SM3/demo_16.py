import random
from gmssl import sm3, func
import time
start = time.time()

def encrypt_fun(strs):
    str_b = bytes(strs, encoding='utf-8')
    result = sm3.sm3_hash(func.bytes_to_list(str_b))
    return result
collision_list=[]
n=4 #n等于碰撞的比特数除以4
flag=0
while(flag==0):
    message_list=[]#随机生成的消息列表
    result_list=[]#利用sm3加密后的值
    while(len(message_list)<int(1.177*pow(2,8))):
        str_1 = str(random.randint(0, pow(2,16)))
        if str_1 not in message_list:
            message_list.append(str_1)
    for str_1 in message_list:
        result_1=encrypt_fun(str_1)
        if result_1[-n:] in result_list:
            print("找到的两个碰撞：")
            print("第一个值：",message_list[result_list.index(result_1[-n:])])
            print("第一个值的sm3加密的结果：",encrypt_fun(message_list[result_list.index(result_1[-n:])]))
            print("第二个值：",str_1)
            print("第二个值的sm3加密的结果：",encrypt_fun(str_1))
            flag=1
            break
        else:
            result_list.append(result_1[-n:])

end = time.time()
print("程序运行时间：",end-start)