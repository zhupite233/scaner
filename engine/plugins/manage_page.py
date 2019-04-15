# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar
'''
此插件用于检测网站后台管理页面
'''
inj_path_list = [
    'ad',
    'admin',
    'admin_login',
    'administrator',
    'Console',
    'cgi_bin/admin',
    'wp_admin',
    'dede',
    'manager',
    'Manage',
    'management',
    'sys',
    'system',
    'houtai',
    'houtaiguanli',
    ]


def run_domain(http,ob):
    result = []
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        cookie = ob['cookie']
        header = {'Host': domain, 'Cookie': cookie}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        for inj_path in inj_path_list:
            new_url = "%s://%s/%s" % (scheme, domain, inj_path)
            try:
                res, content = http.request(new_url, method='HEAD', headers=header)
                if res and res.get('status') == '200':
                    res2, content2 = http.request(new_url, method='GET', headers=header)
                    if res2 and res2.get('status') == '200' and content2:
                        if page_similar(res2.get('status'), content2, ob.get('404_page')):
                            continue
                        detail = "检测到后台管理路径"
                        request = getRequest(new_url, domain=ob['domain'])
                        response = getResponse(res2, content2)
                        result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                        break
            except Exception, e:
                pass

    except Exception, e:
        logger.error("File:manage_page.py, run_domain function :%s" % (str(e)))

    return result