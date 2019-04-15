# -*- coding: utf-8 -*-
import sys
import json
import httplib2
import urlparse
import MySQLdb
import MySQLdb.cursors  
from engineConfig import *
from engine_lib.HttpRequest import HttpRequest

#从数据库中查询单条URL进行扫描
#row = getOneBySpiderurlid(14218)
def getOneBySpiderurlid(urlid=None):
    urlid = int(urlid)
    sql = "select * from spider_url where id=%d" % urlid
    db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass = MySQLdb.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute(sql)
    row = cursor.fetchone()
    db.close()
    return row

#组织数据
urlid=216037
item = getOneBySpiderurlid(urlid)

config = {}
url = item['url']
urlData= urlparse.urlparse(url)

config['siteId'] = 1
config['ip'] = '127.0.0.1'
config['level'] = 'Low'
config['vulId'] = '1'
config['cookie'] = 'PHPSESSID=p1a6ml3htp4d65v9pek07vj6l0;security=low'
config['isstart'] = 1
config['webTimeout'] = 30
config['scheme'] = urlData[0]
config['domain'] = urlData[1]
config['level'] = 'HIGH' #'HIGH|MED|LOW'
config['path'] = '/'
config['taskId'] =240
print config,item

#扫描
#from plugins.dir_traversal_win_url import *
#from plugins.SqlInjectionScript import *
from plugins.sql_inject_common_get import *
http = HttpRequest({'timeout':config['webTimeout'], 'follow_redirects':True,'cookie':config['cookie']})
list = run_url(http, config, item)
print list
#print json.dumps(list[0])

