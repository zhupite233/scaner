# -*- coding: utf-8 -*-
'''
本插件检查 kindeditor 编辑器
author: lidq
created: 20170118
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

    responseList = []
    try:
        # 使用单引号测试是否存在SQL报错，有则存在漏洞
        url = item['url']
        path = urlparse.urlparse(url)[2]

        if path.find('kindeditor'):
            level = 'MED'
            detail = '检测到kindeditor编辑器'
            request = ''
            response = ''
            responseList.append(getRecord(scanInfo, url, 'MED', detail, request, response))
            return responseList

    except Exception, e:
        logger.exception(e)
    return responseList
