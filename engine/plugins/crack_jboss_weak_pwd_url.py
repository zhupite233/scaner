#!/usr/bin/python
# -*- coding: utf-8 -*-
import base64

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_url(http, ob, item):
    header = {
        "Host": ob['domain'],
        "Connection": "keep-alive",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "Referer": item['refer'],
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        # "Cookie": ob.get('cookie')
    }
    try:
        result = []
        path = item['url']
        timeout = ob.get('webTimeout')
        pattern = r'(/jmx-console|/console/App.html)'
        if not re.search(pattern, path, re.I):
            pass
        else:
            error_i = 0
            flag_list=['>jboss.j2ee</a>','JBoss JMX Management Console','HtmlAdaptor?action=displayMBeans','<title>JBoss Management']
            user_list=['admin','manager','jboss','root']
            password_list = ['administrator', 'abcd1234', '111111', '666666', '888888', '000000', '123456',
                             '654321', '222222', '123123',
                             '321321', '123321', '012345', 'abc123', '123abc', 'aaaaaa', 'abcdef', 'admin000',
                             'admin', '123', '321', 'test', 'demo', '1234', '12345', 'manage', 'pass',
                             '00000000', '11111111', '66666666', '88888888', '12345678', '87654321', '01234567',
                             '76543210',
                             '09876543', 'jboss','1','root','1234567890','test1234','password','abcd1234']
            for user in user_list:
                for password in password_list:
                    try:
                        login_url = path
                        request = urllib2.Request(login_url)
                        auth_str_temp=user+':'+password
                        auth_str=base64.b64encode(auth_str_temp)
                        request.add_header('Authorization', 'Basic '+auth_str)
                        res = urllib2.urlopen(request,timeout=timeout)
                        res_code = res.code
                        res_html = res.read()
                    except urllib2.HTTPError,e:
                        res_code = e.code
                        res_html = e.read()
                    except urllib2.URLError,e:
                        error_i+=1
                        if error_i >= 3:
                            return
                        continue
                    if int(res_code) == 404:
                        break
                    if int(res_code) == 401:
                        continue
                    for flag in flag_list:
                        if re.search(flag, res_html, re.I):
                            detail = u'Jboss弱口令，用户名：%s，密码：%s'%(user,password)
                            request = getRequest(path, domain=ob['domain'])
                            res = {'status': '200','content-location': path,  "content-type": 'text/html;charset=utf-8'}
                            response = getResponse(res, res_html, keywords=flag)
                            result.append(getRecord(ob, path, ob['level'], detail, request, response))
                            break

        pattern2 = r'(/admin-console/login.seam)'
        if not re.search(pattern2, path, re.I):
            pass
        else:
            for user in user_list:
                for password in password_list:
                    try:
                        login_url = path
                        res_html = urllib2.urlopen(login_url).read()
                        flag1 = '"http://jboss.org/embjopr/"'
                        if re.search(flag1, res_html, re.I):
                            key_str=re.search('javax.faces.ViewState\" value=\"(.*?)\"',res_html)
                            key_hash=urllib.quote(key_str.group(1))
                            PostStr="login_form=login_form&login_form:name=%s&login_form:password=%s&login_form:submit=Login&javax.faces.ViewState=%s"%(user,password,key_hash)
                            request = urllib2.Request(login_url,PostStr)
                            res = urllib2.urlopen(request,timeout=timeout)
                            flag2 = 'admin-console/secure/summary.seam'
                            if re.search(flag2, res.read(), re.I):
                                detail = u'Jboss弱口令，用户名：%s，密码：%s'%(user,password)
                                request = getRequest(path, domain=ob['domain'])
                                res = {'status': '200','content-location': path,  "content-type": 'text/html;charset=utf-8'}
                                response = getResponse(res, res_html, keywords=flag)
                                result.append(getRecord(ob, path, ob['level'], detail, request, response))
                                break
                    except:
                        pass

        return result

    except Exception, e:
        logger.error("File:crack_jboss_weak_pwd_url.py, run_url function :%s" % (str(e)))
        return result


