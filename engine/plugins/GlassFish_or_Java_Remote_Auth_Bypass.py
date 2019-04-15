# --*-- coding: utf-8 --*--
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
import re
'''
Oracle Sun GlassFish/Java System Application Server Remote Authentication Bypass Vulnerability
漏洞简述：1、Oracle GlassFish Server管理控制台绕过漏洞；2、Oracle GlassFish Server验证绕过漏洞。 发布日期：2011-05-11

影响版本：Oracle GlassFish Server 3.0.1 、 Sun GlassFish Enterprise Server 2.1.1 、Sun GlassFish Enterprise Server 2.1
Sun Java System Application Server Platform Edition 9.1
不影响版本：Oracle GlassFish Server 3.1 、 Contact Oracle for patches for other GlassFish versions
Cache-Control:no-cache
Content-Type:text/html;charset=UTF-8
Date:Thu, 27 Jul 2017 09:45:07 GMT
Expires:Wed, 31 Dec 1969 23:59:59 GMT
Pragma:no-cache
Server:Sun GlassFish Enterprise Server v2.1.1
Transfer-Encoding:chunked
X-Powered-By:JSP/2.1
'''


def run_domain(http, ob):
    try:
        result = []
        web_server = ob.get('webServer')

        scheme = ob['scheme']
        domain = ob['domain']
        if re.search('Sun\s{0,5}GlassFish|Java System Application', web_server, re.I):
            version = re.search('.*(?:\s|V)(\d\.\d(?:\.\d)?)', web_server, re.I).groups()[0]
            if str(version) in ['3.0.1', '2.1.1', '2.1', '9.1']:

                url = "%s://%s" % (scheme, domain)
                response = ''
                request = ''
                detail = "%s版本管理控制台验证绕过漏洞" % web_server
                result.append(getRecord(ob, url, ob['level'], detail, request, response))

        return result

    except Exception, e:
        logger.error("GlassFish_or_Java_Remote_Auth_Bypass.py, run_domain function :%s" % (str(e)))
        return []












