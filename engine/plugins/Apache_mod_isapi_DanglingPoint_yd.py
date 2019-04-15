# -*- coding: utf-8 -*-
'''
Apache mod_isapi模块悬挂指针漏洞
author: lidq
created: 20170119
'''

# 导入url请求公用库
from engine.engine_utils.InjectUrlLib import returnInjectResult

from engine.engine_utils.common import *
from engine.engine_utils.yd_http import request

# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.DictData import headerDictDefault


def run_domain(http, config):
    # 重新组织请求的参数
    server = config.get('server')
    if server in ['nginx', 'iis']:
        return []

    scanInfo = {}
    scanInfo['siteId'] = config['siteId']
    scanInfo['ip'] = config['ip']
    scanInfo['scheme'] = config['scheme']
    scanInfo['domain'] = config['domain']
    scanInfo['level'] = config['level']
    scanInfo['vulId'] = config['vulId']
    headers = headerDictDefault
    headers['cookie'] = config['cookie']
    headers['Host'] = config['domain']
    source_ip = config.get('source_ip')
    responseList = []
    try:
        # 使用单引号测试是否存在SQL报错，有则存在漏洞
        payload = "'"
        if source_ip:
            url = scanInfo['scheme'] + "://" + source_ip
        else:
            url = scanInfo['scheme'] + "://" + scanInfo['domain']
        response = request(url=url, headers=headers, method="GET")
        if response['httpcode'] == 200:
            server = ''
            if response['response_headers'].has_key('server'):
                server = response['response_headers']['server']
            if response['response_headers'].has_key('Server'):
                server = response['response_headers']['Server']
            server = server.lower()
            if server and server.find("apache") != -1:
                version = server.split(' ')[0].split('/')[1]
                if version > '2.2.0' and version < '2.3.0' and version != '2.2.15':
                    injectInfo = returnInjectResult(url=url, confirm=1, detail="Apache mod_isapi模块悬挂指针漏洞",
                                                    response=response)
                    responseList.append(getRecord2(scanInfo, injectInfo))
                    return responseList

    except Exception, e:
        logger.exception(e)
    return responseList
