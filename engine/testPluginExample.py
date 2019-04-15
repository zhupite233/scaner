# -*- coding: utf-8 -*-
import sys
import json
import httplib2
import urlparse
import MySQLdb
import MySQLdb.cursors  
from engineConfig import *
from engine_lib.HttpRequest import HttpRequest

#组织数据
#定义请求的参数
url = "http://target.safety.local.com:8504/sqli_mysql_error.php"
item = {"url":"http://target.safety.local.com:8504/sqli_mysql_error.php","params":"id=1","method":"get","refer":""}
urlData = urlparse.urlparse(url)
config = {}
config['siteId'] = 1
config['vulId'] = 1
config['ip'] = '127.0.0.1'
config['cookie'] = ''
config['isstart'] = 1
config['webTimeout'] = 30
config['scheme'] = urlData[0]
config['domain'] = urlData[1]
config['level'] = "LOW"

#引入书写的插件
from plugins.YundunSql import *
#构造http句柄
http = HttpRequest({'timeout':config['webTimeout'], 'follow_redirects':True,'cookie':config['cookie']})
#执行检测
list = run_url(http, config, item)
#输出扫描结果
print list
#以json格式输出
print json.dumps(list)

#从数据库中查询单条URL进行扫描
#row = getOneBySpiderurlid(14218)
#print row
def getOneBySpiderurlid(urlid=None):
    urlid = int(urlid)
    sql = "select * from spider_url where id=%d" % urlid
    db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass = MySQLdb.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute(sql)
    row = cursor.fetchone()
    db.close()
    return row

