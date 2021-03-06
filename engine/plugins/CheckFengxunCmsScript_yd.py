# -*- coding: utf-8 -*-
'''
本插件检查 检测到风讯CMS 
author: lidq
created: 20170118
'''

#导入url请求公用库
from engine.engine_utils.InjectUrlLib import *

from engine.engine_utils.common import *
#导入日志处理句柄
from engine.logger import scanLogger as logger
#导入默认的header头
from engine.engine_utils.DictData import headerDictDefault


def run_domain(http, config):

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
        if source_ip:
            url = scanInfo['scheme'] + "://" + source_ip
        else:
            url = scanInfo['scheme'] + "://" + scanInfo['domain']

        response = request(url=url, headers=headers, method="GET")
        if response['httpcode'] == 200:
	    if response['response_body'].find('foosun') != -1:
                injectInfo = returnInjectResult(url=url, confirm=1, detail="检测到风讯CMS", response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))
                return responseList

    except Exception,e:
        logger.exception(e)
    return responseList

