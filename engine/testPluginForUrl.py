# -*- coding: utf-8 -*-
import sys
import httplib2
import MySQLdb
import MySQLdb.cursors  
from engineConfig import *
from engine_lib.HttpRequest import HttpRequest


#exec("from plugins.%s import *" % (self.script))
from plugins.CheckJqueryVersion import *
#from plugins.SqlInjectionScript import *

# select concat('{"url":"',url,'","params":"',params,'","method":"',method,'","refer":"',refer,'"}') as json from spider_url

config = {}
config['webTimeout'] = 30
config['cookie'] = ''
config['isstart'] = 1
config['taskId'] = 1
config['assetTaskId'] = 0 
config['siteId'] = 0
config['vulId'] = 0
#config['ip'] = scanCnf['ip']
config['ip'] = '127.0.0.1'
config['scheme'] = "http"
config['domain'] = "www.yundun.com"
#config['path'] = scanCnf['path']
config['endTime'] = "2016-10-21 10:10:10"
config['maxTimeoutCount'] =  3
#config['level'] = scanCnf['level']
config['level'] = 'HIGH'
#config['script'] = scanCnf['script']
config['webTimeout'] =  100
#config['urlQueue'] = scanCnf['queue']
#config['excludeUrl'] = scanCnf['excludeUrl']

http = HttpRequest({'timeout':config['webTimeout'], 'follow_redirects':True,'cookie':config['cookie']})

#item = {"url":"http://www.ifeng.com", "params":{}, "method":"get", "refer":""}
#item = {"url":"http://dvwa.52harry.org/","params":{},"method":"get","refer":"http://dvwa.52harry.org/"}
#item = {"url":"http://www.sina.com.cn/mid/search.shtml","params":"q=纪念刘华清诞辰","method":"get","refer":"http://www.sina.com.cn/"}
item = {"url":"http://auto.sina.com.cn/js/jq172.js","params":"","method":"get","refer":"http://jquery.com"}


list = run_url(http, config, item)
print list


#ob['level'],ret['detail'],ret['request'],ret['response']


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
