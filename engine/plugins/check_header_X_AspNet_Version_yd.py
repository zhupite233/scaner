# -*- coding: utf-8 -*-
'''
响应头中 X-AspNet-Version 由Visual Studio使用，以确定哪些的 ASP.NET 版本正在使用中。对生产站点不是必要的，它应当被禁用
author: lidq
created: 20170105
'''

import json

#导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
#导入url请求公用库
from engine.engine_utils.InjectUrlLib import *
from engine.engine_utils.common import *
#导入日志处理句柄
from engine.logger import scanLogger as logger
#导入默认的header头
from engine.engine_utils.DictData import headerDictDefault


def run_domain(http, ob):
    '''
    重写run_url函数，实现检测SQL注入的功能
    有异常时，直接输出异常
    无异常时，以list类型返回检测结果记录
    靶站 http://www.zhangjiang.gov.cn
    '''

    #重新组织请求的参数
    # scanInfo = {}
    # scanInfo['siteId'] = config['siteId']
    # scanInfo['ip'] = config['ip']
    # scanInfo['scheme'] = config['scheme']
    # scanInfo['domain'] = config['domain']
    # scanInfo['level'] = config['level']
    # scanInfo['vulId'] = config['vulId']
    # headers = headerDictDefault
    # headers['cookie'] = config['cookie']
    # headers['Host'] = scanInfo['domain']
    # source_ip = config.get('source_ip')
    # if source_ip:
    #     scanInfo['domain'] = source_ip
    # responseList = []
    # try:
    #     #使用单引号测试是否存在SQL报错，有则存在漏洞
    #     payload = "'"
    #     urlBase = scanInfo['scheme'] + "://" + scanInfo['domain']
    #     url = urlBase
    #     response = request(url=url, headers=headers, method="GET")
    #     if response['httpcode'] == 200:
    #         if json.dumps(response['response_headers']).find("x-aspnet-version"):
    #             injectInfo = returnInjectResult(url=url, confirm=1, detail="响应头中 X-AspNet-Version 由Visual Studio使用，以确定哪些的 ASP.NET 版本正在使用中。生产环境应禁用此项", response=response)
    #             responseList.append(getRecord2(scanInfo, injectInfo))
    #             return responseList
    #
    # except Exception,e:
    #     logger.exception(e)
    # return responseList
    result_list = []
    try:
        scheme = ob.get('scheme')
        domain = ob.get('domain')
        new_header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s/" % (scheme, domain)
        res, content = http.request(new_url, "HEAD", headers=new_header)
        aspnet_version = res.get('x-aspnet-version')
        if aspnet_version:
            detail = "响应头检测到x-aspnet-version字段，可能泄露敏感信息: %s" % aspnet_version
            request = getRequest(new_url, new_header, domain=ob['domain'])
            response = getResponse(res)
            result_list.append(getRecord(ob, new_url, ob['level'], detail, request, response, output=""))
            return result_list
    except Exception,e:
        logger.error("File:check_header_X_AspNet_Version_yd.py, run_domain function :%s" % (str(e)))
        return []