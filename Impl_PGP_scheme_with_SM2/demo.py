'''
该部分代码为实现PGP的三种工作模式，主要由自己书写
'''
import random
from gmssl import sm3, func
from gmssl import sm2
import base64
import SM2
import DES
from binascii import hexlify, unhexlify

def hash_sm3(strs):#使用sm3作为hash函数,生成消息散列值
    str_1 = bytes(strs, encoding='utf-8')
    result = sm3.sm3_hash(func.bytes_to_list(str_1))
    return result

def base64_encode(strs):#base64加密
    strs=strs.encode()
    str_2 = base64.b64encode(strs)
    return str_2.decode()

def base64_decode(strs):#base64解密
    strs = strs.encode()
    str_3 = base64.b64decode(strs)
    return str_3.decode()

def exp_SM2_str(plaintext):#将明文转换成字节
    plaintext_bytes = bytes(plaintext, encoding="utf8")
    return plaintext_bytes

def gen_key():  #生成SM2即接收方的公私钥对，并写入到文件中，然后在读取出来
    SM2.write_key()
    sf = open("d_B.txt")
    sk = (sf.read())
    f = open("P_B.txt")
    pk = (f.read())
    return sk,pk

def padding(m):#将数据的位数扩展16的倍数并切分为16位长的字符段以便使用TDEA，即3DES数据进行加密
    m=m+"20"*((16-len(m)%16)//2)
    m_list=[]
    for i in range(len(m)//16):  #将数据分割成16位的十六进制
        m_list.append("0x"+m[16*i:16*(i+1)])
    return m_list

#第一种工作模式：认证
def Sender(message):#认证模式下的消息发送方
    message_hash=hash_sm3(message)#发送方使用SM3，生成消息的散列值
    MAC = hexlify(sm2_crypt.encrypt(exp_SM2_str(message_hash))).decode()#用SM2对散列值进行加密，得到MAC（为了后续更好处理这里转成16进制数）
    result=base64_encode(str(MAC)+str(message))#将MAC和消息拼合在一起，进行Base-64转换
    return result

def Receiver(result):#认证模式下的消息接收方
    MAC_message=base64_decode(result)#接收方将消息进行逆Base-64转换
    MAC_1=MAC_message[0:320]
    message_1=MAC_message[320:]#以上两行是将MAC和消息分离
    hash_message=sm2_crypt.decrypt(unhexlify(MAC_1.encode()))#通过SM2解密MAC，得到消息的散列值
    print("接收方收到信息中附带的散列值:",hash_message.decode())
    print("接收方通过收到信息中附带消息生成的散列值:",hash_sm3(message_1))
    if hash_message.decode()==hash_sm3(message_1):#对比两个散列值，验证是否相等
        print("认证成功，消息完整且发送方属实.")
    else:
        print("认证不成功。")

# 第二种工作模式：加密
def Sender_1(message):#认证模式下的消息发送方
    k_1 = hex(random.randint(pow(2, 63), pow(2, 64)))#TDEA加密的三个密钥
    k_2 = hex(random.randint(pow(2, 63), pow(2, 64)))
    k_3 = hex(random.randint(pow(2, 63), pow(2, 64)))
    message=hexlify(bytes(message, encoding="utf8")).decode() #将消息转成字节类型然后转成十六进制
    message_list=padding(message)#将消息进行填充并切分为16位长的字符段
    cipher_list=[]#存储加密消息得到的密文段
    cipher=""#最后消息加密得到的密文
    for i in message_list:#对消息使用TDEA进行加密
        cipher_list.append(DES.TDEA_enc(k_1,k_2,k_3,i))
    for i in cipher_list: #合并密文段
        cipher+=str(i[2:])
    key=str(k_1)[2:]+str(k_2)[2:]+str(k_3)[2:]#合并密钥以便进行加密
    key = exp_SM2_str(key)
    key_cipher=hexlify(sm2_crypt.encrypt(key)).decode()#对密钥使用SM2进行加密处理
    result=base64_encode(str(key_cipher)+cipher)#将加密和的密钥和消息密文合并并进行base64转换
    return result

def Receiver_1(result):#接收方
    keycipher_messagecipher = base64_decode(result)#进行逆base64转换
    keycipher=keycipher_messagecipher[0:288]
    messagecipher=keycipher_messagecipher[288:]#将密钥和消息密文进行分离
    key = sm2_crypt.decrypt(unhexlify(keycipher.encode())).decode()#用SM2进行解密得到TDEA的密钥
    k_1="0x"+key[0:16]#分离密钥
    k_2="0x"+key[16:32]
    k_3="0x"+key[32:48]
    message_list=[]#存储消息段
    messagecipher_list=[]#存储消息密文段
    message=""#消息
    for i in range(len(messagecipher)//16):#将消息密文拆分位16位长的十六进制密文段，以便解密
        messagecipher_list.append("0x"+messagecipher[16*i:16*(i+1)])
    for i in messagecipher_list:#对密文段进行解密得到消息段
        message_list.append(DES.TDEA_dec(k_1,k_2,k_3,i))
    for i in message_list:#对消息段进行合并
        message+=str(i[2:])
    print("接收方通过解密得到的消息为：",unhexlify(message.encode()).decode().strip())#还原消息

#第三种工作模式：认证并加密
def Sender_2(message):#发送方
    message_hash = hash_sm3(message)  # 发送方使用SM3，生成消息的散列值
    MAC = hexlify(sm2_crypt.encrypt(exp_SM2_str(message_hash))).decode()#用SM2对散列值进行加密，得到MAC（为了后续更好处理这里转成16进制数）
    message = hexlify(bytes(message, encoding="utf8")).decode()#将消息转成字节类型然后转成十六进制
    MAC_message=str(MAC)+str(message)#合并MAC和消息
    k_1 = hex(random.randint(pow(2, 63), pow(2, 64)))#TDEA加密的三个密钥
    k_2 = hex(random.randint(pow(2, 63), pow(2, 64)))
    k_3 = hex(random.randint(pow(2, 63), pow(2, 64)))
    MACmessage_list=padding(MAC_message)#对MAC和消息的组合进行填充拆分
    cipher_list=[]#存储密文段
    cipher=""#加密后的密文
    for i in MACmessage_list:#对MAC和消息的组合进行加密
        cipher_list.append(DES.TDEA_enc(k_1,k_2,k_3,i))
    for i in cipher_list:#合并密文
        cipher+=str(i[2:])
    key=str(k_1)[2:]+str(k_2)[2:]+str(k_3)[2:]#合并TDEA的三个密钥
    key = exp_SM2_str(key)
    key_cipher=hexlify(sm2_crypt.encrypt(key)).decode()#使用SM2对密钥进行加密
    result = base64_encode(str(key_cipher) + cipher)#将加密后的密钥和加密后的MAC、消息进行合并，并进行base64转换
    return result

def Receiver_2(result):#接收方
    keycipher_MACcipher_messagecipher = base64_decode(result)#进行逆base64转换
    keycipher=keycipher_MACcipher_messagecipher[0:288]#将密文提出成密钥密文和MAC、消息组合密文
    MACmessagecipher=keycipher_MACcipher_messagecipher[288:]
    key = sm2_crypt.decrypt(unhexlify(keycipher.encode())).decode()#使用SM2进行解密得到TDEA的密钥
    k_1 = "0x" + key[0:16]#分离TDEA的三个密钥
    k_2 = "0x" + key[16:32]
    k_3 = "0x" + key[32:48]
    MAC_message_list = []#MAC和消息组合的明文段
    MAC_messagecipher_list = []#MAC和消息组合的密文段
    MAC_message = ""#MAC和消息的组合题
    for i in range(len(MACmessagecipher) // 16):#对MAC和消息的组合拆分
        MAC_messagecipher_list.append("0x" + MACmessagecipher[16 * i:16 * (i + 1)])
    for i in MAC_messagecipher_list:#对MAC和消息的组合解密
        MAC_message_list.append(DES.TDEA_dec(k_1, k_2, k_3, i))
    for i in MAC_message_list:#得到MAC和消息原文
        MAC_message += str(i[2:])
    MAC=MAC_message[0:320]#分离MAC和消息
    message=unhexlify(MAC_message[320:].encode()).decode().strip()#得到发送的消息原文
    print("接收方通过解密得到的消息为：",message)
    hash_message=sm2_crypt.decrypt(unhexlify(MAC.encode()))#利用SM2解密MAC得到散列值
    print("接收方收到信息中附带的散列值:",hash_message.decode())
    print("接收方通过收到信息中附带消息生成的散列值:",hash_sm3(message))
    if hash_message.decode()==hash_sm3(message):#完成认证过程
        print("认证成功，消息完整且发送方属实.")
    else:
        print("认证不成功。")

sk,pk=gen_key()#接收方的公私钥
sm2_crypt = sm2.CryptSM2(public_key=pk, private_key=sk)
message=input("请输入发送消息内容：")
print("第一种工作模式（认证）测试：")
result_1=Sender(message)#发送方
Receiver(result_1)#接收方
print("第二种工作模式（加密）测试：")
result_2=Sender_1(message)#发送方
Receiver_1(result_2)#接收方
print("第三种工作模式（认证并加密）测试：")
result_3=Sender_2(message)#发送方
Receiver_2(result_3)#接收方
