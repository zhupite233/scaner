# -*- coding: utf-8 -*-
'''
本插件针对 Elasticsearch 1.2 版本及以下的命令执行漏洞
author: lidq
created: 20170103
'''

import json

# 导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
# 导入url请求公用库
from engine.engine_utils.InjectUrlLib import *
from engine.engine_utils.common import *
# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.DictData import headerDictDefault


def run_domain(http, config):
    '''
    重写 run_url 函数，实现检测 SQL 注入的功能
    有异常时，直接输出异常
    无异常时，以 list 类型返回检测结果记录
    '''

    # 重新组织请求的参数
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
        if source_ip:
            url = scanInfo['scheme'] + "://" + source_ip
        else:
            url = scanInfo['scheme'] + "://" + scanInfo['domain']

        response = request(url=url, headers=headers, method="GET")
        if response['httpcode'] == 200:
            try:
                jsonData = json.loads(response['response_body'])
                if jsonData['version']['number'] < '1.2.1':
                    injectInfo = returnInjectResult(url=url, confirm=1, detail="Elasticsearch 1.2 及以下版本存在命令执行漏洞",
                                                    response=response)
                    responseList.append(getRecord2(scanInfo, injectInfo))
                    return responseList
            except Exception, e:
                logger.info(url + " cant return a valid json format string")
                return responseList

    except Exception, e:
        logger.exception(e)
    return responseList
