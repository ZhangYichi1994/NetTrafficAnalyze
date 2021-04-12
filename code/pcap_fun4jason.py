import json
import struct
import pandas as pd


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


"""
pcap文件解析，针对s7comm协议
"""


def pcap_s7_analysis(json_data):
    instance = []
    group_num = int(len(json_data) / 2)  # 数据包总长度
    result = []
    for i in range(group_num):
        comm = json_data[i * 2 + 0]
        resp = json_data[i * 2 + 1]
        # 1、time_interval
        instance.append(resp['_source']['layers']['frame']['frame.time_delta_displayed'])
        # 2、command_address
        instance.append(comm['_source']['layers']['ip']['ip.src'])
        # 3、respond_address
        instance.append(resp['_source']['layers']['ip']['ip.src'])
        # 4、command_memory_count
        instance.append(comm['_source']['layers']['s7comm']['s7comm.header']['s7comm.header.datlg'])
        # 5、respond_memory_count
        instance.append(resp['_source']['layers']['s7comm']['s7comm.header']['s7comm.header.datlg'])
        # 6、command_length
        instance.append(comm['_source']['layers']['frame']['frame.len'])
        # 7、respond_length
        instance.append(resp['_source']['layers']['frame']['frame.len'])
        # 8、command_TCP_checksum
        instance.append(str(int(comm['_source']['layers']['tcp']['tcp.checksum'], 16)))
        # 9、respond_TCP_checksum
        instance.append(str(int(resp['_source']['layers']['tcp']['tcp.checksum'], 16)))
        # 10、command_function_code
        instance.append(str(int(comm['_source']['layers']['s7comm']['s7comm.param']['s7comm.param.func'], 16)))
        # 11、respond_function_code
        instance.append(str(int(resp['_source']['layers']['s7comm']['s7comm.param']['s7comm.param.func'], 16)))
        # 12、measurement
        temp = resp['_source']['layers']['s7comm']['s7comm.data']['s7comm.data.item']['s7comm.resp.data']
        temp = temp.split(":")
        data = []
        if len(temp) % 4 == 0:  # 判断modbus寄存器数据字长度是否为偶数
            for j in range(int(len(temp) / 4)):
                a = temp[j * 4: (j + 1) * 4]
                m = int(''.join((a[2], a[3])), 16)
                n = int(''.join((a[0], a[1])), 16)
                data.append(ReadFloat((m, n)))
            instance.append(data)
            result.append(instance)
            instance = []
        else:
            for j in range(int(len(temp) / 4)):
                a = temp[j * 4: (j + 1) * 4]
                m = int(''.join((a[2], a[3])), 16)
                n = int(''.join((a[0], a[1])), 16)
                data.append(ReadFloat((m, n)))
            m = 0  # 单独数据字典补一位
            a = temp[j * 4: len(temp)]
            n = int(''.join((a[0], a[1])), 16)
            data.append(ReadFloat((m, n)))
            instance.append(data)
            result.append(instance)
            instance = []
    return result


"""
pcap文件解析，针对modbus协议
"""


def pcap_modbus_analysis(json_data):
    instance = []
    group_num = int(len(json_data) / 2)  # 数据包总长度
    result = []
    for i in range(group_num):
        comm = json_data[i * 2 + 0]
        resp = json_data[i * 2 + 1]
        # 1、time_interval
        instance.append(resp['_source']['layers']['frame']['frame.time_delta_displayed'])
        # 2、command_address
        instance.append(comm['_source']['layers']['ip']['ip.src'])
        # 3、respond_address
        instance.append(resp['_source']['layers']['ip']['ip.src'])
        # 4、command_memory
        instance.append(comm['_source']['layers']['modbus']['modbus.reference_num'])
        # 5、respond_memory
        temp = [value for key, value in resp['_source']['layers']['modbus'].items()]
        instance.append(temp[4]['modbus.regnum16'])
        # 6、command_memory_count
        instance.append(str(int(comm['_source']['layers']['modbus']['modbus.word_cnt']) * 2))
        # 7、respond_memory_count
        instance.append(resp['_source']['layers']['modbus']['modbus.byte_cnt'])
        # 8、command_length
        instance.append(comm['_source']['layers']['frame']['frame.len'])
        # 9、respond_length
        instance.append(resp['_source']['layers']['frame']['frame.len'])
        # 10、command_TCP_checksum
        instance.append(str(int(comm['_source']['layers']['tcp']['tcp.checksum'], 16)))
        # 11、respond_TCP_checksum
        instance.append(str(int(resp['_source']['layers']['tcp']['tcp.checksum'], 16)))
        # 12、command_function_code
        instance.append(comm['_source']['layers']['modbus']['modbus.func_code'])
        # 13、respond_function_code
        instance.append(resp['_source']['layers']['modbus']['modbus.func_code'])
        # 14、measurement
        le = int(resp['_source']['layers']['modbus']['modbus.byte_cnt']) / 2  # 152/2=76
        temp = [value for key, value in resp['_source']['layers']['modbus'].items()]
        temp = temp[4:len(temp)]
        data = []
        if int(le) % 2 == 0:  # 判断modbus寄存器数据字长度是否为偶数
            for j in range(int(le / 2)):  # 数据字典两个组成一位
                a = temp[j * 2: (j + 1) * 2]
                m = int(a[0]['modbus.regval_uint16'])
                n = int(a[1]['modbus.regval_uint16'])
                data.append(ReadFloat((m, n)))
            instance.append(data)
            result.append(instance)
            instance = []
        else:
            for j in range(int(le / 2)):  # 数据字典两个组成一位
                a = temp[j * 2: (j + 1) * 2]
                m = int(a[0]['modbus.regval_uint16'])
                n = int(a[1]['modbus.regval_uint16'])
                data.append(ReadFloat((m, n)))
            m = 0  # 单独数据字典补一位
            n = int(temp[len(temp) - 1]['modbus.regval_uint16'])
            data.append(ReadFloat((m, n)))
            instance.append(data)
            result.append(instance)
            instance = []
    return result


def to_file(result, type):
    if type == 'modbus':
        name = ['time_interval', 'command_address', 'respond_address', 'command_memory',
                'respond_memory', 'command_memory_count', 'respond_memory_count',
                'command_length', 'respond_length', 'command_TCP_checksum', 'respond_TCP_checksum',
                'command_function_code', 'respond_function_code', 'measurement']
        temp = pd.DataFrame(columns=name, data=result)
        temp.index += 1
        temp.to_csv('pcap_analysis.csv')
    elif type == 's7comm':
        name = ['time_interval', 'command_address', 'respond_address', 'command_memory_count', 'respond_memory_count',
                'command_length', 'respond_length', 'command_TCP_checksum', 'respond_TCP_checksum',
                'command_function_code', 'respond_function_code', 'measurement']
        temp = pd.DataFrame(columns=name, data=result)
        temp.index += 1
        temp.to_csv('pcap_analysis.csv')


if __name__ == '__main__':
    """读取json格式包数据，modbus协议类型"""
    with open('modbus.json', 'r', encoding='utf8') as fp:
        json_data = json.load(fp)
    result_modbus = pcap_modbus_analysis(json_data)
    to_file(result_modbus, 'modbus')

    # with open('s7comm.json', 'r', encoding='utf8') as fp:
    #     json_data = json.load(fp)
    # result_s7 = pcap_s7_analysis(json_data)
    # to_file(result_s7, 's7comm')

    print('文件解析完成。')
