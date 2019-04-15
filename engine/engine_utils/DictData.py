#!/usr/bin/env python
# -*-encoding:UTF-8-*-
import sys
import re
import httplib2
from InjectUrlLib import *

'''
定义错误信息字典
字典支持两种类型的文字检索：
    普通字符串(type=normalfind), 检查方式为 str.find(msg)，此种方式默认error等同于要检索的字符串，默认为空
    正则搜索(type=regular)，检索方式为re.search(pattern, body)，此种方式需要确定定义error
'''
#定义错误信息字典
sqlErrorDict = {
    'mysql':[
        {"type":"normal", "search":"You have an error in your SQL syntax", "error":""},
        {"type":"normal", "search":"supplied argument is not a valid MySQL", "error":""},
    ],
    'access':[
        {"type":"normal", "search":'Microsoft JET Database Engine', "error":""},
        {"type":"normal", "search":'[Microsoft][ODBC Microsoft Access Driver]', "error":""},
    ],
    'mssql':[
        {"type":"normal", "search":'Microsoft OLE DB Provider for SQL Server', "error":""},
        {"type":"normal", "search":'System.Data.SqlClient.SqlException', "error":""},
        {"type":"normal", "search":'System.Data.SqlClient.SqlConnection', "error":""},
        {"type":"normal", "search":'System.Data.OleDb.OleDbException', "error":""},
        {"type":"normal", "search":'[Microsoft][ODBC SQL Server Driver]', "error":""},
        {"type":"normal", "search":'Microsoft OLE DB Provider for ODBC Drivers', "error":""},
    ],
    'oracle':[
        {"type":"normal", "search":'java.sql.SQLException: Syntax error or access violation', "error":""},
        {"type":"regular", "search":'ORA-[0-9]{4,}', "error":"ORA"},
    ],
    'PostgreSQL':[
        {"type":"normal", "search":'PostgreSQL query failed: ERROR: parser:', "error":""},
        {"type":"normal", "search":'invalid input syntax for', "error":""},
    ],
    'XPath':[
        {"type":"normal", "search":'XPathException', "error":""},
    ],
    'LDAP':[
        {'type':'normal', 'search':'supplied argument is not a valid ldap', "error":""},
        {'type':'normal', 'search':'javax.naming.NameNotFoundException', "error":""},
    ],
    'db2' : [
        {'type':'normal', 'search':'DB2 SQL error:', "error":""},
        {'type':'normal', 'search':'[IBM][JDBC Driver]', "error":""},
    ],
    'Interbase':[
        {'type':'normal', 'search':'Dynamic SQL Error', "error":""},
    ],
    'sybase':[
        {'type':'normal', 'search':'Sybase message:', "error":""},
    ]
}

'''
默认的请求头
'''
headerDictDefault = {
    "User-Agent":" Mozilla/5.0 (Windows NT 5.1; rv:14.0) Gecko/20100101 Firefox/14.0.1",
    "Accept":" text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3",
    "Connection": "keep-alive",
    "Referer": "",
}

'''
HTTP状态码列表
'''
HTTP_STATUS_DICT = {
    '100': 'Continue', 
    '101': 'Switching Protocols', 
    '200': 'OK', 
    '201': 'Created', 
    '202': 'Accepted', 
    '203': 'Non-Authoritative Information', 
    '204': 'No Content', 
    '205': 'Reset Content', 
    '206': 'Partial Content', 
    '300': 'Multiple Choices', 
    '301': 'Moved Permanently', 
    '302': 'Found', 
    '303': 'See Other', 
    '304': 'Not Modified', 
    '305': 'Use Proxy', 
    '307': 'Temporary Redirect',
    '400': 'Bad Request', 
    '401': 'Unauthorized', 
    '403': 'Forbidden', 
    '404': 'Not Found',
    '405': 'Method Not Allowed', 
    '406': 'Not Acceptable', 
    '407': 'Proxy Authentication Required',
    '408': 'Request Timeout', 
    '409': 'Conflict', 
    '410': 'Gone', 
    '411': 'Length Required',
    '412': 'Precondition Failed', 
    '413': 'Request Entity Too Large', 
    '414': 'Request URI Too Long',
    '415': 'Unsupported Media Type', 
    '416': 'Requested Range Not Satisfiable',
    '417': 'Expectation Failed',
    '461': 'Intercept by YUNDUN WAF',
    '500': 'Internal Server Error', 
    '501': 'Not Implemented',
    '502': 'Bad Gateway', 
    '503': 'Service Unavailable', 
    '504': 'Gateway Timeout',
    '505': 'HTTP Version Not Supported'
}

