#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
耗费太多资源，未启用
资源文件可预测
检测条件：当前域名根目录下对应的文件名
'''

from engine.engine_utils.DictData import headerDictDefault
from engine.engine_utils.InjectUrlLib import returnInjectResult
from resource_dict import resourceDict

from engine.engine_utils.common import getRecord2
from engine.engine_utils.yd_http import request
from engine.logger import scanLogger as logger


def run_domain(http, config):
    '''
    重写run_domain函数，实现检测资源文件是否存在
    有异常时，直接输出异常
    无异常时，以list类型返回检测结果记录
    '''
    try:
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
        accessPaths = resourceDict['access']['list']

        if source_ip:
            urlBase = scanInfo['scheme'] + "://" + source_ip
        else:
            urlBase = scanInfo['scheme'] + "://" + scanInfo['domain']
        for path in accessPaths:
            currentUrl = urlBase + path
            print currentUrl
            response = request(url=currentUrl) 
            if response['httpcode'] == 200:
                injectInfo = returnInjectResult(url=currentUrl, confirm=1, detail=resourceDict['access']['detail'], response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))
                return responseList
    except Exception,e:
        logger.error("File:resource_access.py, run_domain function :%s" % (str(e)))
        return []

