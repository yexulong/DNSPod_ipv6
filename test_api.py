import requests
import datetime
import random
import hmac
import base64
import subprocess
import re
import configparser
import os
from hashlib import sha256


SecretId = 'xxx'
SecretKey = 'xxx'
domain = 'xxx'
    
def make_common_param(fun_host, fun_url, **fun_param):
    '''构造公共参数'''
    common_param = {
        'SecretId': SecretId,
        'SignatureMethod': 'HmacSHA256',
        'Nonce': int(random.random() * 10000),
        'Timestamp': int(datetime.datetime.now().timestamp())
    }
    for i,j in fun_param.items():
        common_param[i] = j
    param_order = sorted(common_param.items(), key=lambda x:x[0], reverse=False)
    s = 'GET' + fun_host + fun_url + '?' + '&'.join([str(i[0]) + '=' + str(i[1]) for i in param_order])
    signature = cal_signature(s, SecretKey)
    common_param['Signature'] = signature
    return common_param

  
def get_api_response(r_host, r_url, **r_param):
    r_param = make_common_param(r_host, r_url, **r_param)
    request_url = 'https://' + r_host + r_url
    r = requests.get(url=request_url, params=r_param)
    # print(data)
    # print(r.json())
    return r.json()['data']


def cal_signature(src_str, secretKey):
    '''计算签名值'''
    return base64.b64encode(hmac.new(secretKey.encode('utf8'), src_str.encode('utf8'), digestmod=sha256).digest()).decode('utf8')
    

def get_record_list():
    '''获取解析记录列表'''
    host = 'cns.api.qcloud.com'
    url = '/v2/index.php'
    param = {
        'Action': 'RecordList',
        'offset': 0,
        'length': 20,
        'domain': domain
    }
    return get_api_response(host, url, **param)
    

def modify_record(record_id, sub_domain, record_value):
    '''修改解析记录'''
    host = 'cns.api.qcloud.com'
    url = '/v2/index.php'
    param = {
        'Action': 'RecordModify',
        'recordId': record_id,
        'recordType': 'AAAA',
        'subDomain': sub_domain,
        'domain': domain,
        'recordLine': '默认',
        'value': record_value
    }
    return get_api_response(host, url, **param)
    
  
def get_Local_ipv6_address():
    '''获取本地IPv6地址'''
    getIPV6_process = subprocess.Popen("ipconfig", stdout = subprocess.PIPE)
    output = (getIPV6_process.stdout.read())
    ipv6_pattern='(([0-9]{2}[a-f0-9]{0,2}:){1}([a-f0-9]{1,4}:){6}[a-f0-9]{1,4})'
    m = re.search(ipv6_pattern, str(output))
    if m is not None:
       return m.group()
    else:
       return None
 
def getConfig(file_name, section, key):
    '''获取config配置文件'''
    config = configparser.ConfigParser()
    path = os.path.split(os.path.realpath(__file__))[0] + '/' + file_name
    config.read(path)
    return config.get(section, key)    
    
def setConfig(file_name, section, key, modify_value):
    '''设置config配置文件'''
    config = configparser.ConfigParser()
    path = os.path.split(os.path.realpath(__file__))[0] + '/' + file_name
    config.read(path)
    
    config.set(section, key, modify_value)
    #保存修改
    with open(path, "w") as fw:
        config.write(fw) # 使用write将修改内容写到文件中，替换原来config文件中内容
        
if __name__ == '__main__':
    ini_name = 'ip.ini'
    now_ipv6_addr = get_Local_ipv6_address()
    print('现在IP为:' + now_ipv6_addr)
    last_ipv6_addr = getConfig(ini_name, 'IP', 'IPv6')
    print('上次IP为:' + last_ipv6_addr)
    if now_ipv6_addr == last_ipv6_addr:
        print('IP没有发生变化:'+ last_ipv6_addr)
        pass
    else:
        setConfig(ini_name, 'IP', 'IPv6', now_ipv6_addr)
        records = get_record_list()['records']
        for record in records:
            # print(record['type'])
            if record['type'] == 'AAAA':
                r = modify_record(record['id'], record['name'], now_ipv6_addr)
                print(r)
