# -*- coding: utf-8 -*-
'''
本插件为常规SQL注入型插件
目前插件仅支持GET方式请求的SQL注入检测
author: lidq
created: 20161123
'''

import sys
# 导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
from engine.engine_utils.InjectSql import InjectSql
# 导入 url 请求公用库
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
    headers['cookie'] = config['cookie']
    headers['Host'] = config['domain']
    source_ip = config.get('source_ip')
    responseList = []
    try:
        # 格式化待测试的urlItem，不符合要求则直接返回空
        urlItem = formatUrlItem(item)
        if not urlItem:
            return responseList

        # 实例化SQL注入对象
        injectSql = InjectSql()

        # 构造所需要的参数
        url = urlItem['url']
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
        if urlItem['method'] == 'get':
            urlBase = url
            queryDict = urlItem['queryDict']
            bodyDict = {}
        else:
            # post请求
            urlBase, queryDict = post_all_query2dict(url)
            bodyDict = db_params2dict(item['params'])

        # 逐个参数进行测试
        keys = []
        keys.extend(queryDict.keys())
        keys.extend(bodyDict.keys())
        for key in keys:
            results = injectSql.checkFirst(url=urlBase, queryDict=queryDict, bodyDict=bodyDict, headers=headers,
                                           theKey=key, method=urlItem['method'])
            if results:
                responseList.append(getRecord2(scanInfo, results[0]))
                return responseList

    except Exception, e:
        logger.exception(e)
    return responseList
