#!/usr/bin/env python
# -*- coding: utf-8 -*-

# header = {'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3', 'Accept-Encoding': 'gzip, deflate',
#           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
#           'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0',
#           'Host': 'msxx.lsldjyw.com', 'Cookie': '', 'Cache-Control': 'no-cache',
#           'Content-Type': 'application/x-www-form-urlencoded'}
# url = 'http://www.easternmiles.com'

# try:
#     res, con = http.request(url, 'GET', body=None, headers=None, redirections=5, connection_type=None)
#     print res['status']
# except Exception, e:
#     print e
import json
import urlparse

import httplib2
import urllib

http = httplib2.Http()
header = {'token': 'wbsllmigfa4ct0zp4gdd4hx2umpijg4e','Content-Type': 'application/x-www-form-urlencoded'}
postData = {
    'start_urls':'http://www.xd-ad.com.cn',
    'type':'spider',
    'limit_depth':10,
    'limit_total':300,
    'limit_time':1200,
    'limit_image':0,
    'limit_subdomain':0,
    'limit_js':1,
    'url_unique_mode':'url-query',
    'notify_url':'http://192.168.3.85',
    'source_ip':'192.168.3.85',
    'proxies':'192.168.3.85',
    'crontab':''
}
# body = urllib.urlencode(postData)
# res, con = http.request('http://192.168.3.74:9022/task/save', 'POST', body=body, headers=header)
# print con,  con

res, con = http.request('http://192.168.3.74:9022/execute/urlsbyid/1468', 'GET', headers=header)
print con,  res



