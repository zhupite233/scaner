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
# plugins.dir_traversal_win_url
#url="http://192.168.3.51/dvwa/vulnerabilities/fi/"
#params = json.dumps([{"type":"submit","name":"seclev_submit","value":"Submit"},{"type":"text","name":"page","value":"high"}])
#item = {"url":url,"params":params,"method":"post","refer":""}

# plugins.dir_traversal_win_url
url = "http://target.safety.local.com:8504/sqli_mysql_error.php"
queryDict = {"id":"1"}
item = {"url":url,"params":json.dumps(queryDict),"method":"get","refer":""}

# plugins.check_login_script
url = "https://www.yundun.com/login"
queryDict = {}
item = {"url":url,"params":json.dumps(queryDict),"method":"get","refer":""}

# plugins.CheckSvnScript_yd
url = "https://www.yundun.com/a/.svn/index.html.svn-base"
queryDict = {}
item = {"url":url,"params":json.dumps(queryDict),"method":"get","refer":""}

# plugins.CheckGitScript_yd
url = "https://www.yundun.com/a/.git/index"
queryDict = {}
item = {"url":url,"params":json.dumps(queryDict),"method":"get","refer":""}

# plugins.CheckGitScript_yd
url = "http://www.ewebeditor.net/plugin/onlineservice/2010/blue/qqcs.js"
queryDict = {}
item = {"url":url,"params":json.dumps(queryDict),"method":"get","refer":""}

# plugins.CheckVodCmsScript_yd
url = "http://vod.phpvod.com/"
queryDict = {}
item = {"url":url,"params":json.dumps(queryDict),"method":"get","refer":""}

# plugins.CheckACTcmsScript_yd
url = "http://www.actcms.com/"
queryDict = {}
item = {"url":url,"params":json.dumps(queryDict),"method":"get","refer":""}

# plugins.CheckJqueryVersion
#url = "http://www.mbraunchina.com/js/jquery_new.js"
url = "https://www.yundun.com/static/assets-1.0/js/jquery_1.10.2.js"
queryDict = {}
item = {"url":url, "params":json.dumps(queryDict), "method":"get", "refer":""}

# plugins.sql_inject_common import *
url = "http://jkzx.lishui.gov.cn/bqsm/"
queryDict = [{"type":"text","name":"textfield","value":""},{"type":"submit","name":"Submit","value":"搜索"},{"type":"select","name":"select","value":""}]
item = {"url":url, "params":json.dumps(queryDict), "method":"post", "refer":""}

# plugins.CheckACTcmsScript_yd
url = "http://www.yundun.com/admin/test.php"
queryDict = {}
item = {"url":url,"params":json.dumps(queryDict),"method":"get","refer":""}

config = {}
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
#print config,item

#扫描
#from plugins.dir_traversal_win_url import *
#from plugins.SqlInjectionScript import *
#from plugins.check_login_script import *
#from plugins.CheckSvnScript_yd import *
#from plugins.CheckGitScript_yd import *
#from plugins.ScanEWebEditor_yd import *
#from plugins.CheckVodCmsScript_yd import *
#from plugins.CheckACTcmsScript_yd import *
#from plugins.CheckJqueryVersion import *
#from plugins.sql_inject_common import *
from plugins.CheckTestScript_yd import *
http = HttpRequest({'timeout':config['webTimeout'], 'follow_redirects':True, 'cookie':config['cookie']})
list = run_url(http, config, item)
print list
#print json.dumps(list[0])

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

