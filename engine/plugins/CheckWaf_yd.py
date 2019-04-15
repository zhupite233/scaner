# -*- coding: utf-8 -*-
'''
Web 应用防火墙被检测到，当扫描IPS / IDS / WAF保护的服务器时，您可能会收到错误/不完整的结果。
author: lidq
created: 20170105
'''

import sys
import json
import urllib
import hashlib

# 导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
from engine.engine_utils.InjectSql import InjectSql
# 导入url请求公用库
from engine.engine_utils.InjectUrlLib import *
from engine.engine_utils.common import *
# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.DictData import headerDictDefault
from engine.engine_utils.params import post_all_query2dict
from engine.engine_utils.params import db_params2dict
import urlparse

def run_domain(http, config):
    '''
    重写run_url函数，实现检测SQL注入的功能
    有异常时，直接输出异常
    无异常时，以list类型返回检测结果记录
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
        # 使用单引号测试是否存在SQL报错，有则存在漏洞
        payload = "'"
        if source_ip:
            scanInfo['domain'] = source_ip
        urlBase = scanInfo['scheme'] + "://" + scanInfo['domain']

        # 第一种方式，header头检测
        url = urlBase
        response = request(url=url, headers=headers, method="GET")
        if response['httpcode'] == 200:
            if response['response_headers'].has_key('Server') and response['response_headers']["Server"].lower().find(
                    'waf'):
                injectInfo = returnInjectResult(url=url, confirm=1, detail="Web应用防火墙被检测到，扫描被保护的系统，会导致不准确的报告",
                                                response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))
                return responseList

        # 第二种方式，不合法的参数请求，返回403则表示被保护
        url = urlBase + '?param=-1+UNION+SELECT+GROUP_CONCAT(table_name)+FROM+information_schema.tables'
        response = request(url=url, headers=headers, method="GET")
        if response['httpcode'] == 403 or response['httpcode'] == 461:
            injectInfo = returnInjectResult(url=url, confirm=1, detail="Web应用防火墙被检测到，扫描被保护的系统，会导致不准确的报告",
                                            response=response)
            responseList.append(getRecord2(scanInfo, injectInfo))
            return responseList

    except Exception, e:
        logger.exception(e)
    return responseList
