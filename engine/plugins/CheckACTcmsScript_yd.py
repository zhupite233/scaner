# -*- coding: utf-8 -*-
'''
本插件检查 ACTCMS 内容管理系统 
author: lidq
created: 20170104
'''

# 导入url请求公用库
from engine.engine_utils.InjectUrlLib import *

from engine.engine_utils.common import *
# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.DictData import headerDictDefault
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
            new_url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            new_url = "%s://%s%s" % (scheme, domain, path)
        response = request(url=new_url, headers=headers, method="GET")
        if response['httpcode'] == 200:
            if response['response_body'].find('actcms') != -1:
                injectInfo = returnInjectResult(url=new_url, confirm=1, detail="检测到 ACTCMS 内容管理系统", response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))
                return responseList

    except Exception, e:
        logger.exception("CheckACTcmsScript_yd" + e.message)
    return responseList
