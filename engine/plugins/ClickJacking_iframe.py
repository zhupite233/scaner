#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
点击劫持检测插件，iframe 形式
检测条件：当页面中的 iframe 引用的页面与网站当前域名不一致时，则报疑似风险
'''

import re
import urlparse

from engine.engine_utils.DictData import headerDictDefault
from engine.engine_utils.InjectUrlLib import returnInjectResult

from engine.engine_utils.common import getRecord2
from engine.engine_utils.params import dict2query, db_params2dict, post_all_query2dict
from engine.engine_utils.yd_http import request
from engine.logger import scanLogger as logger
def run_url(http, config, item):
    '''
    重写run_url函数，实现检测SQL注入的功能
    有异常时，直接输出异常
    无异常时，以list类型返回检测结果记录
    '''
    try:
        #重新组织请求的参数
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
        if item['method'].lower() == 'get':             #get
            url = "%s?%s" % (new_url, item['params'])
            bodyDict={}
        else:                   #post
            url = new_url
            bodyDict = db_params2dict(item['params'])

        urlBase, queryDict = post_all_query2dict(item['url'])
        response = request(url=url, body=dict2query(bodyDict), headers=headers, method=item['method']) 
        pattern = r'<iframe.*?src="(.*?)"'
        matches = re.findall(pattern, response['response_body'])
        for row in matches:
            parse = urlparse.urlparse(row) 
            if scanInfo['domain'] != parse.netloc:
                injectInfo = returnInjectResult(url=url, confirm=0, detail='点击劫持，iframe连接到了外站', response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))
                return responseList
            else:
                print scanInfo['domain'], parse.netloc
    except Exception,e:
        logger.error("File:ClickJacking_iframe.py, run_url function :%s" % (str(e)))
        return []


