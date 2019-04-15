# --*-- coding: utf-8 --*--
import urlparse

import MySQLdb
import MySQLdb.cursors
from engine.engineConfig import *
from engine.engine_lib import HttpRequest
from httplib2 import Http

from engine.engine_utils.params import post_params2str


def init_header(item):
    header = {
                "Connection": "keep-alive",
                "Pragma": "no-cache",
                "Cache-Control": "no-cache",
                "Referer": item['refer'],
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                "Accept-Encoding": "gzip, deflate",
                # "Cookie": item['cookie']
    }
    return header


def test_http(item, header):
    http = Http(timeout=3)
    # params = 'username=admin&password=password'
    params = item.get('params')
    if 'post' == item.get('method'):
        params = post_params2str(params)
    print params
    res, content = http.request(item.get('url'), item.get('method').upper(), params, header)
    print res


def test_http2(item, header):
    http = HttpRequest({'follow_redirects':True})
    res, content = http.request(item.get('url'), item.get('method').upper(), item.get('params'), header)
    print res


def get_spider_url(url_id=None):
    sql = "select * from spider_url where id=%d" % url_id
    db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass=MySQLdb.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute(sql)
    item = cursor.fetchone()
    db.close()
    return item

# if __name__ == '__main__':
#     item = get_spider_url(114016)
#     header = init_header(item)
#     test_http(item, header)

import re
def path_inject(path,inj_value,inj_way="append"):
    if path:
        # 替换模式
        if inj_way == "replace":
            if inj_value[0] == "/":
                new_path = inj_value
            else:
                new_path = "/" + inj_value
        # append、add模式都是追加，其他非法输入也按append模式
        else:
            # 注入值以/开头
            if inj_value[0] == "/":
                # 路径以/结尾，去掉重复的/
                if path[-1] == "/":
                    new_path = path[0:-1] + inj_value
                # 路径以非/结尾
                else:
                    p = path.split("/")
                    # 最后一段中包含点，去掉最后带点的部分。例如 /test/index.php  去掉index.php
                    if re.search("\.",p[-1]):
                        n = len(p[-1]) # 通过字符串长度实现，出于性能考虑
                        path_1 = path[0:-(n+1)]   # 删除最后一段路径以及最后一个/
                        new_path = path_1 + inj_value
                    # 最后一段路径中不包含点
                    else:
                        new_path = path + inj_value
            # 注入值非/开头
            else:
                # 路径以/结尾
                if path[-1] == "/":
                    new_path = path + inj_value
                # 路径以非/结尾
                else:
                    p = path.split("/")
                    # 最后一段中包含点，去掉最后带点的部分。例如 /test/index.php  去掉index.php
                    if re.search("\.",p[-1]):
                        n = len(p[-1])
                        path_1 = path[0:-n]
                        new_path = path_1 + inj_value
                    else:
                        new_path = path + "/" + inj_value
    # path 为空
    else:
        if inj_value[0] == "/":
            new_path = inj_value
        else:
            new_path = "/" + inj_value
    return new_path

print path_inject("","est.php")

from engine.engine_lib.HttpRequest import HttpRequest
config = {}
url = '''http://www.zjyhxx.com'''
url_parse = urlparse.urlparse(url)
http = HttpRequest({'domain': url_parse.netloc, 'timeout': 20, 'follow_redirects':True})
url_404 = "%s://%s/%s.abc" % (url_parse.scheme, url_parse.netloc, 'xgegoighig321hihi')  # 用当前时间戳和随机数构成不存在的url，后缀.abc
header_404 = {'Host': url_parse.netloc}
# http = HttpRequest({'domain': url_parse.netloc, 'timeout': 20, 'follow_redirects':False})
try:
    http=Http()
    http.follow_redirects=False
    res, config['404_content'] = http.request(url_404, redirections=5, headers=header_404)
    config['404_status'] = int(res.get('status', 0))
except Exception, e:
    print e
    config['404_status'] = 200