#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    result = []
    try:
        result = []
        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        input_path = ob['path']
        safe_version = '3.2.6.4'  # 目前比较安全的版本，如果爆出漏洞，需要修改此参数值
        inj_path_list = [
            "/fckeditor/editor/dialog/fck_about.html",
            "/FCKeditor/_whatsnew.html"
            # "/upload/common/lib/fckeditor/editor/dialog/fck_about.html",
            # "/upload/common/lib/FCKeditor/_whatsnew.html"
        ]
        for inj_path in inj_path_list:
            url = "%s://%s%s" % (scheme,domain,inj_path)
            res, content = http.request(url, 'GET', headers=header)
            if res and res.get('status') == '200':
                if page_similar(res['status'], content, ob.get('404_page')):
                    continue
                if page_similar(res['status'], content, ob.get('waf_page')):
                    continue
                version = re.search(r'\b[1-4]\.[\d]{1,2}\.[\d]{1,2}(\.[\d]{1,2})?\b', content)
                for version_str in version.group():
                    if version_str and version_str < safe_version:
                        detail = "FCKeditor当前版本过低，请及时升级到CKEditor最新版本"
                        request = getRequest(url, domain=ob['domain'])
                        response = getResponse(res,content)
                        result.append(getRecord(ob,url,ob['level'],detail,request,response))

    except Exception,e:
        logger.error("File:FCKeditorVersion_yd.py, run_domain function :%s" % (str(e)))

    return result



