# -*- coding: utf-8 -*-
'''
本插件为常规 SQL 注入型插件
目前插件仅支持 header 方式请求的 SQL 注入检测
author: lidq
created: 20161123
'''
# 导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
from engine.engine_utils.InjectSql import InjectSql
# 导入url请求公用库
# from engine.engine_utils.InjectUrlLib import *
from engine.engine_utils.common import *
# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.DictData import headerDictDefault
import urlparse

def run_url(http, config, item):
    '''
    重写run_url函数，实现检测SQL注入的功能
    有异常时，直接输出异常
    无异常时，以list类型返回检测结果记录
    '''

    # 重新组织请求的参数
    scanInfo = {}
    scanInfo['siteId'] = config['siteId']
    scanInfo['ip'] = config['ip']
    scanInfo['domain'] = config['domain']
    scanInfo['level'] = config['level']
    scanInfo['vulId'] = config['vulId']
    headers = headerDictDefault
    headers['cookie'] = config['cookie'] if config['cookie'] else ''
    headers['Host'] = config['domain']
    source_ip = config.get('source_ip')
    responseList = []
    try:
        # 格式化待测试的urlItem，不符合要求则直接返回空
        urlItem = item
        url = urlItem['url']
        if re.search(r'docs/jndi-datasource-examples-howto.html', url, re.I):
            return responseList
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
        # 实例化SQL注入对象
        injectSql = InjectSql()
        # header注入检测
        results = injectSql.checkFirstForHeader(url=url, headers=headers)
        if results:
            # 如果有漏洞，则格式化输出
            responseList.append(getRecord2(scanInfo, results[0]))
            return responseList
    except Exception, e:
        logger.error("File:sql_inject_common_header.py:" + str(e))
    return responseList
