#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http, ob):
    try:
        webserver = ob.get('webServer')
        if webserver and webserver in ['apache', 'nginx']:
            return []
        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        result = []
        # chars = string.ascii_letters + string.digits
        url = "%s://%s/%s" % (scheme, domain, '*~1*/')
        res, content = http.request(url, 'GET', headers=header)
        if re.search(r'Error Code 0x00000000', content, re.I):
            response = getResponse(res, content)
            request = getRequest(url, domain=ob['domain'])
            detail = "存在IIS短文件和文件夹泄漏漏洞"
            result.append(getRecord(ob, url, ob['level'], detail, request, response))
        else:
            url = "%s://%s/%s" % (scheme, domain, 'Ydun*~1.*/')
            res, content = http.request(url, 'GET', headers=header)
            if re.search(r'Error Code 0x80070002', content, re.I):
                response = getResponse(res, content)
                request = getRequest(url, domain=ob['domain'])
                detail = "存在IIS短文件和文件夹泄漏漏洞"
                result.append(getRecord(ob, url, ob['level'], detail, request, response))
            else:
                payloads = (
                    ('*~1*/.aspx', 'Ydun*~1.*/x.aspx'),
                    ('*~1*', 'Ydun*~1.*'),
                    # ('*~1*/', '%2FYdun*~1.*/'),

                )
                for valid_path, invalid_path in payloads:
                    valid_url = "%s://%s/%s" % (scheme, domain, valid_path)
                    invalid_url = "%s://%s/%s" % (scheme, domain, invalid_path)
                    res1, content1 = http.request(valid_url, 'GET', headers=header)
                    res2, content2 = http.request(invalid_url, 'GET', headers=header)
                    if res1.get('status') == '404' and res2.get('status') == '400':
                        response = getResponse(res1, content1)
                        request = getRequest(valid_url, domain=ob['domain'])
                        detail = "存在IIS短文件和文件夹泄漏漏洞"
                        result.append(getRecord(ob, valid_url, ob['level'], detail, request, response))
                        response = getResponse(res2, content2)
                        request = getRequest(invalid_url, domain=ob['domain'])
                        detail = "存在IIS短文件和文件夹泄漏漏洞"
                        result.append(getRecord(ob, invalid_url, ob['level'], detail, request, response))
                        break
        return result

    except Exception, e:
        logger.error("File:IISFileDisclosureScript_yd.py, run_domain function :%s" % (str(e)))
        return []
