# -*- coding: utf-8 -*-
'''
本插件检查 eWebEditor 在线编辑器，此编辑器一般会有默认后台及默认密码
author: lidq
created: 20170104
'''

import sys
import urllib
import hashlib

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

def run_url(http, config, item):
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
        url = item['url']
        url_parse = urlparse.urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query

        if source_ip:
            domain = source_ip
        if query:
            url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            url = "%s://%s%s" % (scheme, domain, path)
        path = urlparse.urlparse(url)[2]
        if path[-3:] == '.js' or path[-4:] == '.css':
            response = request(url=url, headers=headers, method="GET")
            if response['httpcode'] == 200:
                if response['response_body'].find('eWebEditor') != -1:
                    injectInfo = returnInjectResult(url=url, confirm=1, detail="检测到eWebEditor，此编辑器一般会有默认后台及默认密码",
                                                    response=response)
                    responseList.append(getRecord2(scanInfo, injectInfo))
                    return responseList

    except Exception, e:
        logger.exception("ScanEWebEditor_yd" + e.message)
    return responseList
