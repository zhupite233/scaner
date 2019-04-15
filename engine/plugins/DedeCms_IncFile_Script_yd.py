#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar

def run_domain(http,ob):
    '''
    插件名称：检测到DeDeCMS 存在日志文件
    :param http:
    :param ob:
    :return:
    '''
    result = []
    try:
        frame = ob.get('siteType')
        if frame and frame in ['asp', 'aspx', 'jsp']:
            return []

        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        result = []

        inj_path_list = [
            "/data/mysql_error_trace.inc",

            "/dede/data/mysql_error_trace.inc"
            ]

        for inj_path in inj_path_list:
            new_url = "%s://%s%s" % (scheme, domain, inj_path)
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.get('status') == '200' and content:
                if page_similar(res.get('status'), content, ob.get('404_page')):
                    continue
                if page_similar(res.get('status'), content, ob.get('waf_page')):
                    continue
                detail = '检测到织梦CMS数据库日志文件'
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res,content)
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:DedeCms_IncFile_Script_yd.py, run_domain function :%s" % (str(e)))

    return result

