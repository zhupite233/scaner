#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from urlparse import urlparse
from engine.engine_utils.rule_result_judge import page_similar


def run_url(http,ob,item):
    result = []
    try:
        frame = ob.get('siteType')
        if frame and frame in ['jsp', 'asp', 'aspx']:
            return []

        url = item['url']
        result = []
        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        if re.search(r'/dede\b', url):
            path = urlparse(url)['path']
            base_path = path.split('/dede')[0]
            new_path = base_path + '/dede/login.php'
            new_url = "%s://%s%s" % (scheme,domain,new_path)
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.get('status') == '200' and content:
                if page_similar(res.get('status'), content, ob.get('waf_page')):
                    return []
                detail = '检测到织梦CMS后台管理路径'
                result.append(getRecord(ob, url, ob['level'], detail, request=url, response=''))

    except Exception, e:
        logger.error("File:FindDedeCmsScript_yd.py, run_url function :%s" % (str(e)))

    return result
