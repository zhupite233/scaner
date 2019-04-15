#!/usr/bin/env python
# -*- coding: utf-8 -*-


import httplib2
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
import urlparse

class Blindsqlclass:
    def __init__(self, http, url, ob):
        try:
            self.vuldict = {}
            self.url = url
            self.http = httplib2.Http()
            self.ob = ob
            self.header = {"Host": self.ob.get('domain')}
            self.responseinit, self.contentinit = self.http.request(self.url, headers=self.header)
            self.leninit = len(self.contentinit)

        except Exception, e:
            logger.error("File:SqlBlindScript.py, Blindsqlclass.__init__:" + str(e))

    def auditint(self, url):
        try:

            firststr = "%20AnD%202121=2121"
            firsturl = "%s%s" % (url, firststr)

            response, content = self.http.request(firsturl, headers=self.header)
            firstlen = len(content)

            secstr = "%20AnD%202121=2122"
            securl = "%s%s" % (url, secstr)
            r, c = self.http.request(securl, headers=self.header)
            seclen = len(c)
            getkey = self.GetKey(c)
            if getkey:
                if content.find(getkey) >= 0 and c.find(getkey) < 0 and response['status'] == '200' and (
                                r['status'] == '200' or r['status'] == '500'):
                    if firstlen > seclen:
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                return False

        except Exception, e:
            logger.error("File:SqlBlindScript.py, Blindsqlclass.auditint:" + str(e) + "URL:" + self.url)
            return False

    def auditstr(self, url):
        try:

            firststr = "%27AnD%272121%27=%272121"
            firsturl = "%s%s" % (url, firststr)

            response, content = self.http.request(firsturl, headers=self.header)
            firstlen = len(content)

            secstr = "%27AnD%272121%27=%272122"
            securl = "%s%s" % (url, secstr)
            r, c = self.http.request(securl, headers=self.header)
            seclen = len(c)
            getkey = self.GetKey(c)
            if getkey:
                if content.find(getkey) >= 0 and c.find(getkey) < 0 and response['status'] == '200' and (
                                r['status'] == '200' or r['status'] == '500'):
                    if firstlen > seclen:
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                return False
        except Exception, e:
            logger.error("File:SqlBlindScript.py, Blindsqlclass.auditstr:" + str(e) + "URL:" + self.url)
            return False

    def audit(self, url):
        detail = ""
        try:
            if self.auditint(url):
                logger.debug("blind sqlinj for int type")
                request = getRequest("%s and 1=1" % (url), domain=ob['domain'])
                response = getResponse(self.responseinit)
                detail = "此注入类型数字型盲注"
                self.vuldict = {'url': url, 'detail': "存在注入的URL:%s\n此注入类型数字型盲注" % (url), 'request': request,
                                'response': response}
                return self.vuldict
            elif self.auditstr(url):
                detail = "此注入类型字符型盲注"
                logger.debug("blind sqlinj for str type")
                request = getRequest("%s'and'1'='1" % (url), domain=ob['domain'])
                response = getResponse(self.responseinit)
                self.vuldict = {'url': url, 'detail': "存在注入的URL:%s\n此注入类型字符型盲注" % (url), 'request': request,
                                'response': response}
                return self.vuldict
            else:
                logger.debug("dont find sqlinj")

        except Exception, e:
            logger.error("File:SqlBlindScript.py, Blindsqlclass.audit:" + str(e) + "URL:" + self.url)
        return self.vuldict

    def GetKey(self, contenterror):
        try:
            listkey = []
            contentlist = self.contentinit.split("\r\n")
            for i in contentlist:
                if contenterror.find(i) < 0:
                    listkey.append(i)
                    if len(listkey) >= 2:
                        return listkey[1]
                    if len(listkey) == 1:
                        return listkey[0]

        except Exception, e:
            logger.error("File:SqlBlindScript.py, Blindsqlclass.GetKey:" + str(e) + "URL:" + self.url)
            return None
            # end def


def run_url(http, ob, item):
    res = []
    try:
        list = []
        isstart = '0'
        responsedetail = ''
        if item['params'] == "":
            return list
        if item['method'] == 'get' and item['params'].find("=") < 0:
            return list
        # end if
        parse = urlparse.urlparse(item['url'])
        path = parse.path
        if path == "" or path == "/":
            return list
        path = path.lower()
        if path.find(".css") >= 0 or path.find(".doc") >= 0 or path.find(".txt") >= 0 or path.find(".pdf") >= 0:
            return list
        if item['method'] == 'get':
            url_list = []
            params = changeParams(item['params'])
            url = item['url']
            url_parse = urlparse.urlparse(url)
            scheme = url_parse.scheme
            domain = url_parse.netloc
            path = url_parse.path
            query = url_parse.query
            source_ip = ob.get('source_ip')
            if source_ip:
                domain = source_ip
            if query:
                url = "%s://%s%s?%s" % (scheme, domain, path, query)
            else:
                url = "%s://%s%s" % (scheme, domain, path)
            for row in params:
                url = "%s?%s" % (url, row)
                # print url
                bindsql = Blindsqlclass(http, url, ob)
                print
                ret = bindsql.audit(url)
                if ret:
                    res.append(getRecord(ob, url, ob['level'], ret['detail'], ret['request'], ret['response']))

    except Exception, e:
        logger.error("File:SqlBlindScript.py, Blindsqlclass.GetKey:" + str(e))
    return res


if __name__ == '__main__':
    item = {"url":"http://demo.aisec.cn/demo/aisec/html_link.php", "params":"id=2",
            "method": "GET", "source_ip":"182.48.105.212"}