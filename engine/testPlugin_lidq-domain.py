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
config = {}
#url = "http://www.fzipo.gov.cn/WholeSiteSearch/WholeSiteSearch_AllList.aspx?keyword=d%27&id=9"
#item = {"url":"http://www.fzipo.gov.cn/WholeSiteSearch/WholeSiteSearch_AllList.aspx","params":"keyword=d&id=9","method":"get","refer":""}
#url = "http://target.safety.local.com:8504/sqli_mysql_error.php"
#url = "http://target.safety.local.com:8504/sqli_mysql_error_header.php"
#item = {"url":"http://target.safety.local.com:8504/sqli_mysql_error_header.php","params":"","method":"get","refer":""}

#url="http://www.cnblogs.com/polk6/archive/2013/05/24/3097430.html"
#url="http://discuzx15.target.safety.local.com/forum.php"
#url="http://discuz72.target.safety.local.com/forumdisplay.php?fid=2"
#url="http://discuzx15.target.safety.local.com/forum.php"
#url="http://discuz6.target.safety.local.com/forum.php"
#url="http://discuzx32.target.safety.local.com/forum.php"
#url="http://discuzx32.target.safety.local.com/forum.php"
#cookie = '9nII_2132_auth=6feeYFaU%2BSWWYrimX3WmHxLJQ2WhAvGunJvEBYo%2FkWYHQQP3FryzAeMSfIwhsFXfOQxG4CaV%2BZLQElcFuBKo; 9nII_2132_lastvisit=1481611136; 9nII_2132_sid=dmY6U3; 9nII_2132_lastact=1481617207%09misc.php%09stat; 9nII_2132_ulastactivity=89efLVoBzc8xPIxF5rUhm4QMBgm4ntoFzNQ9J8t2G2XjDNrEOFqE'

#url = "http://phpwind75.target.safety.local.com/admin.php?adminjob=hack&hackset=rate&typeid=100&job=ajax"
#url = 'http://elastic01.yundun.com:9201'
#url = 'http://www.sojump.com/'
#url = 'http://www.jhlib.com/?param=-1+UNION+SELECT+GROUP_CONCAT(table_name)+FROM+information_schema.tables'
#url = 'http://www.foosun.net/html/class/rjdzal/index.html'
#url = 'http://www.apache.org/'
url = 'http://pma.local.com/'

cookie = 'd41d8_lastvisit=155%091482115136%09%2Findex.php; d41d8_lastpos=index; d41d8_ol_offset=97; d41d8_ipstate=1482114981; d41d8_AdminUser=AFELU1UAU1IGUT9XXFoMWzwFBQFRUQUAW1NRVwAEXlNTU1cDAVEKVlFTAQQEXFIAAD4%3D'
item = {"url":url, "params":"", "method":"get", "refer":""}
urlData = urlparse.urlparse(url)
config['siteId'] = 1
config['vulId'] = 1
config['ip'] = '127.0.0.1'
config['cookie'] = cookie
config['isstart'] = 1
config['webTimeout'] = 30
config['scheme'] = urlData[0]
config['domain'] = urlData[1]
config['level'] = "LOW"
#print config,item

#扫描
#from plugins.resource_probe import *
#from plugins.DiscuzX15_notify_credit_yd import *
#from plugins.Discuz7_xss_showmessage_yd import *
#from plugins.DiscuzX15_xss_bbcode_yd import *
#from plugins.DiscuzX_sql_get_misc_yd import *
#from plugins.DiscuzX15_xss_ucserver_iframe_yd import *
#from plugins.Discuz6_xss_eccredit_uid_yd import *
#from plugins.Discuz_plugin_doconline_readfile_yd import *
#from plugins.Discuz7_sql_faq_yd import *
#from plugins.PHPWind75_fileinclude_admin import *
#from plugins.ElasticsearchCmdScript_yd import *
#from plugins.check_header_X_AspNet_Version_yd import *
#from plugins.CheckWaf_yd import *
#from plugins.CheckFengxunCmsScript_yd import *
#from plugins.Apache_mod_isapi_DanglingPoint_yd import *
from plugins.PhpParseString2float_yd import *
http = HttpRequest({'timeout':config['webTimeout'], 'follow_redirects':True,'cookie':config['cookie']})
list = run_domain(http, config)
print list

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

#return {'siteId':ob['siteId'],'url':url,'ip':ob['ip'],'domain':ob['domain'],'level':level,'vulId':ob['vulId'],'request':request,'response':response,'detail':detail,'output':output}

