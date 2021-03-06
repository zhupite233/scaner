# -*- coding: utf-8 -*-
'''
jquery低版本存在XSS攻击漏洞，建议升级高版本
author: lidq
created: 20161229
'''

import sys
import urllib
import hashlib

# 导入url请求公用库
from engine.engine_utils.InjectUrlLib import returnInjectResult
from engine.engine_utils.yd_http import request
from engine.engine_utils.common import *
# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.DictData import headerDictDefault
from engine.engine_utils.params import post_all_query2dict
from engine.engine_utils.params import db_params2dict
import urlparse

def run_url(http, config, item):
    '''
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
        path = urlparse.urlparse(url)[2]
        if path[-3:] == '.js':
            response = request(url=new_url, headers=headers, method="GET")
            if response['httpcode'] == 200:
                patternCompress = re.compile(r'jQuery\s*v(\d{1,2}\.\d{1,2}\.\d{1,2})\s')
                patternUncompress = re.compile(r'jQuery\sJavaScript\sLibrary\sv(\d{1,2}\.\d{1,2}\.\d{1,2})')
                matchesCompress = patternCompress.findall(response['response_body'])
                matchesUncompress = patternUncompress.findall(response['response_body'])
                version = None
                if matchesCompress:
                    version = matchesCompress[0]
                if matchesUncompress:
                    version = matchesUncompress[0]
                # if version and version < '1.119.0':
                if version and version < '1.11.3':
                    injectInfo = returnInjectResult(url=url, confirm=1, detail="jquery 低版本易导致xss攻击", response=response)
                    responseList.append(getRecord2(scanInfo, injectInfo))
                    return responseList

    except Exception, e:
        logger.exception(e)
    return responseList
