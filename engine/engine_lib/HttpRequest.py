#!/usr/bin/env python
#-*-encoding:UTF-8-*-
import httplib2

class HttpRequest:
    def __init__(self, cnf):
        try:
            self.timeout = 30
            self.follow_redirects = True
            self.cookie = ''
            self.domain = cnf.get('domain')
            if cnf.has_key('timeout'):
                self.timeout = cnf['timeout']
            #end if
            if cnf.has_key('follow_redirects'):
                self.follow_redirects = cnf['follow_redirects']
            #end if
            if cnf.has_key('cookie'):
                self.cookie = cnf['cookie']
            #end if

            self.http = httplib2.Http(disable_ssl_certificate_validation = True)
            self.http.timeout = self.timeout
            self.http.follow_redirects = self.follow_redirects
            self.headers = self.initHeaders()

        except Exception, e:
            raise
        #end try
    #end def

    def initHeaders(self):
        try:
            headers = {}
            headers['Accept-Encoding'] = 'identity'
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:47.0) Gecko/20100101 Firefox/47.0'
            headers['Cookie'] = '' if not self.cookie else self.cookie
            #headers['Host'] = self.domain
            headers['Accept-Language'] = 'zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3'

            return headers
        except Exception, e:
            raise

    def updateHeaders(self, headers):
        try:
            for k in self.headers:
                if headers.has_key(k):
                    continue
                #end if
                headers[k] = self.headers[k]
            #end for

            return headers
        except Exception, e:
            raise
        #end try
    #end def

    def request(self, url, method="GET", body=None, headers=None, redirections=5, connection_type=None):
        try:
            if headers is None:
                headers = self.headers
            else:
                headers = self.updateHeaders(headers)
            #end if

            return self.http.request(url, method, body, headers, redirections, connection_type)
        except Exception, e:
            raise
        #end try
    #end def
#end class


