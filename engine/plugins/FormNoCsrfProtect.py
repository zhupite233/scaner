#!/usr/bin/python
# -*- coding: utf-8 -*-
import urlparse

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

_form = None
_name = None
_hide = None


def formNoCsrfProtect(content):
    try:
        global _form, _name, _hide
        if _form is None:
            _form = re.compile(r"<(\s*)form(.+?)>(.+?)<(\s*)/(\s*)form(\s*)>", re.I | re.DOTALL)
        match = _form.findall(content)
        if _name is None:
            _name = re.compile(r"name(\s*)=(\s*)('|\")(.+?)(\3)", re.I)
        if _hide is None:
            _hide = re.compile(r"hidden(.+?)(value(\s*)=(\s*)('|\")(.+?)('|\")|value(\s*)=(\s*)(.+?)(\s|/|$))", re.I)
        for row in match:
            if _name.search(row[2]) and not _hide.search(row[2]):
                return True
                # end if
                # end for
    except Exception, e:
        logger.error("File:FormNoCsrfProtect.py, formNoCsrfProtect function :%s" % str(e))


_thereForm = None


def run_url(http, ob, item):
    result = []
    try:
        detail = u"该页面表单容易受到CSRF攻击，请检查该页面所有表单。"
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        url = item['url']
        url_parse = urlparse.urlparse(url)
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
        if item['params'] != "":
            return result
        if item['method'] == 'get':
            global _thereForm
            if _thereForm is None:
                _thereForm = re.compile(r"<(\s*)form(.+?)>", re.I | re.DOTALL)
            res, content = http.request(url, 'GET', headers=header)
            if res['status'] == '200' and _thereForm.search(content) and formNoCsrfProtect(content):
                request = getRequest(url, domain=ob['domain'])
                response = getResponse(res)
                result.append(getRecord(ob, url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:FormNoCsrfProtect.py, run_url function :%s" % (str(e)))

    return result

