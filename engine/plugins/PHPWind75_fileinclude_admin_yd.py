# -*- coding: utf-8 -*-
'''
本插件针对 PHPWind7.5 的  hack/rate/admin.php 任何包含文件漏检测
author: lidq
created: 20161219
'''

# 导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
# 导入url请求公用库
from engine.engine_utils.InjectUrlLib import returnInjectResult

from engine.engine_utils.common import *
from engine.engine_utils.yd_http import request

# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.DictData import headerDictDefault


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
    headers['Host'] = scanInfo['domain']
    headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    headers['Accept-Language'] = 'en-US,en;q=0.5'
    headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0'
    headers['cookie'] = config['cookie']
    headers['Host'] = config['domain']
    source_ip = config.get('source_ip')
    responseList = []
    try:
        # 使用单引号测试是否存在SQL报错，有则存在漏洞
        payload = "'"
        if source_ip:
            urlBase = scanInfo['scheme'] + "://" + source_ip
        else:
            urlBase = scanInfo['scheme'] + "://" + scanInfo['domain']
        urlTrue = urlBase + '/admin.php?adminjob=hack&hackset=rate&typeid=100&job=ajax'
        urlFalse = urlBase + "/admin.php?adminjob=hack&hackset=rate&typeid=100&job=testerfileinclude"
        responseTrue = request(url=urlTrue, headers=headers)
        responseFalse = request(url=urlFalse, headers=headers)
        if responseTrue['httpcode'] == 200 and responseFalse['httpcode'] == 200:
            if responseTrue['response_body'].find("ajax") != -1 and responseTrue['response_body'].find(
                    "adminjob=hack") != -1 and responseFalse['response_body'] == '':
                injectInfo = returnInjectResult(url=urlFalse, confirm=1,
                                                detail="PHPWind7.5 的 hack/rate/admin.php 任何包含文件漏洞",
                                                response=responseFalse)
                responseList.append(getRecord2(scanInfo, injectInfo))
                return responseList

    except Exception, e:
        logger.error("File:PHPWind75_fileinclude_admin.py:" + str(e))
    return responseList
