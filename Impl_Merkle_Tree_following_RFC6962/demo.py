import random
from hashlib import sha256

def Generate_data(data_len):#按照0-data_len的顺序生成数据
    data=[]
    for i in range(data_len):
        data.append(str(i))
    return data

def hash_sha256(x):#对数据进行hash处理
    return sha256(x.encode()).hexdigest()

def leaf_1(x):#对树倒数第一层结点进行的hash处理
    return hash_sha256("0x00"+x)

def leaf_2(x_1,x_2):#对树中间结点构建进行的hash处理
    return hash_sha256("0x01" + x_1+x_2)

def create_merkeltree(data):#构建merkel tree
    data_len=len(data)
    merkletree = [[]]#用于存储树的每一层
    for i in range(data_len):#树的最后一层
        merkletree[0].append(leaf_1(data[i]))
    tree_depth=1
    while(len(merkletree[-1])!=1):#构建中间的结点
        node=[]#父结点
        for i in range(int(len(merkletree[tree_depth-1])/2)):#对于有两个叶结点的父结点处理后添加到父结点那一层
            node.append(leaf_2(merkletree[tree_depth-1][i*2],merkletree[tree_depth-1][i*2+1]))
        merkletree.append(node)
        if len(merkletree[tree_depth-1])%2 == 1:#对于只有一个叶结点的父结点将该叶结点直接添加到父结点那一层
            node.append(merkletree[tree_depth-1][-1])
        merkletree.append(node)
        tree_depth+=1#统计树层数
    return merkletree

def verification(m,tree):#验证数据是否在树中
    hash_m = leaf_1(m) #对要验证的数据进行hash处理
    if hash_m in tree[0]: #验证数据hash后的值是否处于最后一层
        print("该数据存在与构建的Merkel_tree.")
    else:
        print("该数据不存在与构建的Merkel_tree.")

data=Generate_data(100000)#进行数据的生成
merkle_tree=create_merkeltree(data)#完成树的建立
if len(merkle_tree[0])==len(data):
    print("100000个数据的树构建完成。")
verification("1",merkle_tree) #完成验证
verification("200000",merkle_tree)