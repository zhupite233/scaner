# --*-- coding:utf-8 --*--
import re
import sys
import urllib
import httplib2
import MySQLdb
import MySQLdb.cursors
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME

sys.exit(0)

# URL = "http://127.0.0.1:8091/rules"
URL = "http://115.238.233.208:8091/rules"


def addRule(family='', rulename='', path='', params=''):
    data = dict(
        # rule_name=rulename.encode('utf-8'),
        rule_name=rulename,
        # rule_family=family.encode('utf-8'),
        rule_family=family,
        rule_tag=None,
        if_head=None,
        run_mode='domain',
        inj_area='path',
        inj_way='append',
        inj_point='',
        inj_value="%s" % path,
        code_mode='equal',
        judge_code1='200',
        judge_code2='',
        judge_keyword='',
        content_mode='',
        judge_content='',
        similar_mode='',
        similar='',
        describe='',
        judge=None
    )

    body = urllib.urlencode(data)
    requestHeaders = {"Content-Type": "application/x-www-form-urlencoded"}

    http = httplib2.Http()
    headers, body = http.request(URL, "POST", body, headers=requestHeaders)
    if headers.has_key('status') and headers['status'] == '200':
        return True
    return False


def getRules():
    family = '信息泄露'

    sql = "SELECT id,vul_name FROM web_vul_list_copy where scan_type=3 and family=%s and vul_name like %s"
    params = [family, '发现%可利用的页面信息泄露%']
    rules = dbQuery(sql, params)

    errorList = []
    totalOk = 0
    for rule in rules:
        matches = re.findall(ur'发现(.*?)可利用', rule['vul_name'])
        if not matches:
            continue
        rulename = "%s-%s" % (rule['id'], rule['vul_name'])
        result = addRule(family, rulename, matches[0])
        if result:
            totalOk += 1
        else:
            print "error:", rulename
    print 'OK:', totalOk


def sendRules():
    rules = [
        # {'id':'5882', 'family':'配置不当','path':'/php.ini', 'vul_name':'发现/php.ini文件'},
    ]

    errorList = []
    totalOk = 0
    for rule in rules:
        family = rule['family']
        rulename = "%s-%s" % (rule['id'], rule['vul_name'])
        path = rule['path']
        result = addRule(family, rulename, path)
        if result:
            totalOk += 1
        else:
            print "error:", rulename
    print 'OK:', totalOk


def dbQuery(sql=None, params=None):
    db = MySQLdb.connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, cursorclass=MySQLdb.cursors.DictCursor, charset="utf8")
    cursor = db.cursor()
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    db.close()
    return rows


if __name__ == "__main__":
    # getRules()
    sendRules()
