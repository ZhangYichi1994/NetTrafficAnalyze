from scapy.all import *
from scapy.utils import wrpcap
import pandas as pd
import struct
import math


"""将十进制转化为浮点型"""
def ReadFloat(*args, reverse=False):
    for n, m in args:
        n, m = '%04x' % n, '%04x' % m
    if reverse:
        v = n + m
    else:
        v = m + n
    y_bytes = bytes.fromhex(v)
    y = struct.unpack('!f', y_bytes)[0]
    y = round(y, 6)
    return y


"""将浮点型转化为十进制"""
def WriteFloat(value, reverse=False):
    y_bytes = struct.pack('!f', value)
    y_hex = ''.join(['%02x' % i for i in y_bytes])
    n, m = y_hex[:-4], y_hex[-4:]
    n, m = int(n, 16), int(m, 16)
    if reverse:
        v = [n, m]
    else:
        v = [m, n]
    return v


def bytes2code(byt):  # 输入为bytes型数据
    cod = []
    for i in range(len(byt)):
        cod.append(byt[i])
    return cod


def data_ana(lis):
    temp = []
    for i in range(len(lis)):
        temp1 = hex(lis[i])
        temp2 = temp1.split('0x')
        if temp2[1] == '0':
            temp2[1] = '00'
        elif temp2[1] == '1':
            temp2[1] = '01'
        elif temp2[1] == '2':
            temp2[1] = '02'
        elif temp2[1] == '3':
            temp2[1] = '03'
        elif temp2[1] == '4':
            temp2[1] = '04'
        elif temp2[1] == '5':
            temp2[1] = '05'
        elif temp2[1] == '6':
            temp2[1] = '06'
        elif temp2[1] == '7':
            temp2[1] = '07'
        elif temp2[1] == '8':
            temp2[1] = '08'
        elif temp2[1] == '9':
            temp2[1] = '09'

        temp.append(temp2[1])

    temp2 = []
    if len(temp) % 4 == 0:
        for j in range(0, len(temp), 4):
            m = int('0x' + temp[j+2] + temp[j+3], 16)  # 低位
            n = int('0x' + temp[j+0] + temp[j+1], 16)  # 高位
            temp2.append(ReadFloat((m, n)))
    else:
        print('存在补位现象...')

    return temp2

if __name__ == '__main__':

    for time in range(0, 10):
        time  = 9
        print('')
        print('-------------开始进行实时抓包并进行解析，当前为第', time+1, '轮分析-------------')

        # """抓包"""
        # pcap = sniff(count=1000, filter='tcp')
        # pcap_filename = 'sample' + str(time) + '.pcap'
        # wrpcap(pcap_filename, pcap)  # 保存pcap包到本地
        # # pcap = rdpcap('demo4.pcap')  # 读取本地pcap包
        pcap = rdpcap('sample9.pcap')  # 读取本地pcap包

        """解析"""
        flag = 1
        i = 0
        result = []
        while flag:
            instance = []

            if len(pcap[i]) == 85:  # 属于s7comm，请求包长度为85
                id_i = pcap[i]['TCP'].ack  # 找出第i个包的ack身份证号
                for j in range(i+1, len(pcap)):  # 从i包的下一个数据包开始遍历     *********************  （1）
                    if j >= len(pcap)-1:  # 如果i已经是最后一个包了，j=i+1已经超出范围，标志位置0，准备跳出循环
                        # flag = 0
                        pass
                    else:
                        id_j = pcap[j]['TCP'].seq  # 找出第j个包的身份证号
                        if id_i == id_j:  # 证明响应包与数据包匹配，
                            instance.append(pcap[i].time)       # 请求包发送时间
                            instance.append(pcap[j].time)       # 响应包返回时间
                            instance.append(pcap[i]['IP'].src)  # 第i个数据包的IP地址，请求地址
                            instance.append(pcap[j]['IP'].src)  # 第j个数据包的IP地址，响应地址
                            instance.append(pcap[i]['Ether'].dst)  # 第i个数据包的MAC地址
                            instance.append(pcap[j]['Ether'].dst)  # 第j个数据包的MAC地址
                            instance.append(pcap[i]['IP'].len)  # 第i个数据包的IP协议长度
                            instance.append(pcap[j]['IP'].len)  # 第j个数据包的IP协议长度
                            load_i = bytes2code(pcap[i]['Raw'].load)
                            load_j = bytes2code(pcap[j]['Raw'].load)
                            instance.append(load_i[2] * pow(16, 2) + load_i[3])  # 第i个数据包的包长度，即TPKT长度
                            instance.append(load_j[2] * pow(16, 2) + load_j[3])  # 第i个数据包的包长度，即TPKT长度
                            instance.append(load_i[17])  # 第i个数据包的功能码
                            instance.append(load_j[19])  # 第j个数据包的功能码，响应包的表头比请求包多两个字
                            instance.append(load_i[23] * pow(16, 2) + load_i[24])  # 第i个数据包的读写寄存器长度
                            instance.append(load_i[25] * pow(16, 2) + load_i[26])  # 第i个数据包的读写DB号
                            instance.append(load_i[27])  # 第i个数据包的读写DB地址区域
                            instance.append((load_j[23] * pow(16, 2) + load_j[24])/8)  # 第j个数据包的数据长度

                            data = data_ana(load_j[25: len(load_j)])
                            instance.append(data)

                            print('No.', time+1, '轮，第', i+1, '和第', j+1, '个包组成的匹配包解析完成')

                            break  # 能找到匹配的就跳出循环    ***********************（1）
                        else:
                            print('Warning: No.', time+1, '轮，第', i+1, '和第', j+1, '个包不匹配，继续向下遍历...')
                            continue  # 不匹配就继续往下找，循环继续    ***********************（1）
                if j == (len(pcap) - 1):
                    i = i + 1
                else:
                    i = j + 1
                
                if i >= len(pcap)-1:
                    flag = 0
            else:
                i = i + 1
                if i >= len(pcap)-1:
                    flag = 0

            if instance != []:
                result.append(instance)

        temp = pd.DataFrame(result)
        filename = str(time)+'result.csv'
        temp.to_csv(filename)
    print('-------------网络流量实时分析完成-------------')



# from scapy.all import *
# from scapy.utils import wrpcap
# import pandas as pd
# import struct
# import math
#
#
# """将十进制转化为浮点型"""
# def ReadFloat(*args, reverse=False):
#     for n, m in args:
#         n, m = '%04x' % n, '%04x' % m
#     if reverse:
#         v = n + m
#     else:
#         v = m + n
#     y_bytes = bytes.fromhex(v)
#     y = struct.unpack('!f', y_bytes)[0]
#     y = round(y, 6)
#     return y
#
#
# """将浮点型转化为十进制"""
# def WriteFloat(value, reverse=False):
#     y_bytes = struct.pack('!f', value)
#     y_hex = ''.join(['%02x' % i for i in y_bytes])
#     n, m = y_hex[:-4], y_hex[-4:]
#     n, m = int(n, 16), int(m, 16)
#     if reverse:
#         v = [n, m]
#     else:
#         v = [m, n]
#     return v
#
#
# def bytes2code(byt):  # 输入为bytes型数据
#     cod = []
#     for i in range(len(byt)):
#         cod.append(byt[i])
#     return cod
#
#
# def data_ana(lis):
#     temp = []
#     for i in range(len(lis)):
#         temp1 = hex(lis[i])
#         temp2 = temp1.split('0x')
#         if temp2[1] == '0':
#             temp2[1] = '00'
#         elif temp2[1] == '1':
#             temp2[1] = '01'
#         elif temp2[1] == '2':
#             temp2[1] = '02'
#         elif temp2[1] == '3':
#             temp2[1] = '03'
#         elif temp2[1] == '4':
#             temp2[1] = '04'
#         elif temp2[1] == '5':
#             temp2[1] = '05'
#         elif temp2[1] == '6':
#             temp2[1] = '06'
#         elif temp2[1] == '7':
#             temp2[1] = '07'
#         elif temp2[1] == '8':
#             temp2[1] = '08'
#         elif temp2[1] == '9':
#             temp2[1] = '09'
#
#         temp.append(temp2[1])
#
#     temp2 = []
#     if len(temp) % 4 == 0:
#         for j in range(0, len(temp), 4):
#             m = int('0x' + temp[j+2] + temp[j+3], 16)  # 低位
#             n = int('0x' + temp[j+0] + temp[j+1], 16)  # 高位
#             temp2.append(ReadFloat((m, n)))
#     else:
#         print('存在补位现象...')
#
#     return temp2
#
# if __name__ == '__main__':
#
#     for time in range(0, 100):
#         """抓包"""
#         pcap = sniff(count=1000, filter='tcp')
#         # wrpcap('demo4.pcap', pcap)
#         # pcap = rdpcap('demo4.pcap')
#         """解析"""
#         flag = 1
#         i = 0
#         result = []
#         while flag:
#             instance = []
#             if len(pcap[i]) > 60 and (pcap[i]['TCP'].sport == 102 or pcap[i]['TCP'].sport == 65232):  # 属于s7comm
#                 id_i = pcap[i]['TCP'].ack  # ack代表i包指定响应包的ID，第i个包的ack
#                 for j in range(i+1, len(pcap)):  # 从i包的下一个数据包开始遍历，找到指定的响应数据包
#                     if j > len(pcap):
#                         flag = 0
#                     else:
#                         id_j = pcap[j]['TCP'].seq  # seq代表紧跟随的数据包的ID，第j个包的seq
#                         if id_i == id_j:  # 证明响应包与数据包匹配
#                             instance.append(pcap[i]['IP'].src)  # 第i个数据包的IP地址
#                             instance.append(pcap[j]['IP'].src)  # 在seq与ack匹配的情况下，确定两包匹配，第j个数据包的IP地址
#                             instance.append(pcap[i]['Ether'].dst)  # 第i个数据包的MAC地址
#                             instance.append(pcap[j]['Ether'].dst)  # 第j个数据包的MAC地址
#                             instance.append(pcap[i]['IP'].len)  # 第i个数据包的IP协议长度
#                             instance.append(pcap[j]['IP'].len)  # 第j个数据包的IP协议长度
#
#                             load_i = bytes2code(pcap[i]['Raw'].load)
#                             load_j = bytes2code(pcap[j]['Raw'].load)
#                             instance.append(load_i[2] * pow(16, 2) + load_i[3])  # 第i个数据包的包长度，即TPKT长度
#                             instance.append(load_j[2] * pow(16, 2) + load_j[3])  # 第i个数据包的包长度，即TPKT长度
#                             instance.append(load_i[17])  # 第i个数据包的功能码
#                             instance.append(load_j[19])  # 第j个数据包的功能码，响应包的表头比请求包多两个字
#                             instance.append(load_i[23] * pow(16, 2) + load_i[24])  # 第i个数据包的读写寄存器长度
#                             instance.append(load_i[25] * pow(16, 2) + load_i[26])  # 第i个数据包的读写DB号
#                             instance.append(load_i[27])  # 第i个数据包的读写DB地址区域
#
#                             instance.append((load_j[23] * pow(16, 2) + load_j[24])/8)  # 第j个数据包的数据长度
#                             data = data_ana(load_j[25: len(load_j)])
#                             instance.append(data)
#
#                             print('第', i+1, '和第', j+1, '个包解析完成')
#                             break  # 能找到匹配的就跳出循环
#                         else:
#                             print('当前第', i+1, '和第', j+1, '个包不匹配，继续向下遍历...')
#                             continue  # 不匹配就继续往下找
#                 i = j + 1
#                 if i >= len(pcap):
#                     flag = 0
#                 print('time=', time, 'i=', i, 'j=', j)
#
#             else:
#                 i = i + 1
#                 if i >= len(pcap):
#                     flag = 0
#
#             if instance != []:
#                 result.append(instance)
#
#         temp = pd.DataFrame(result)
#         filename = str(time)+'result'
#         temp.to_csv('filename.csv')
#
#
#
