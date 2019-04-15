#!/usr/bin/env python
# -*-encoding:UTF-8-*-
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import re
import ssl
import errno
import socket
import struct
import urllib
import urllib2
import httplib
import httplib2
import urlparse
import threading
import subprocess
from Queue import Queue
from engine.engine_lib.HttpRequest import *

from engine.logger import scanLogger as logger

# 扫描站点队列
siteQueue = Queue()

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


def getCurrentFunctionName():
    return inspect.stack()[1][3]


def popen(cmd):
    try:
        # 插件中   close_fds=False    为 True
        return subprocess.Popen(cmd, shell=True, close_fds=False, bufsize=-1, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT).stdout.readlines()
    except Exception, e:
        print str(e)
        return ''


def toStr(msg):
    try:
        return msg.encode('utf-8')
    except Exception, e:
        return ''


def httpRequest(url, method, headers, body, timeout, enable_forward):
    http = httplib2.Http()
    if enable_forward:
        http.follow_redirects = True
    else:
        http.follow_redirects = False

    socket.setdefaulttimeout(timeout)
    response, content = http.request(url, method, headers=headers, body=body)
    returnDict = dict()
    return returnDict


def checkProcessExist(process):
    try:
        result = popen("ps -ef | grep %s | grep -v grep | wc -l" % process)
        if result and int(result[0]) > 0:
            return True
        return False
    except Exception, e:
        return False


class Util:
    socketLocker = threading.Lock()
    flowLocker = threading.Lock()

    @classmethod
    def addTimeout(cls, t=5):
        cls.socketLocker.acquire()
        timeout = socket.getdefaulttimeout()
        if timeout:
            if timeout < 115:
                socket.setdefaulttimeout(timeout + t)
        cls.socketLocker.release()

    @classmethod
    def subTimeout(cls, t=5):
        cls.socketLocker.acquire()
        timeout = socket.getdefaulttimeout()
        if timeout:
            if timeout > 10:
                socket.setdefaulttimeout(timeout - t)
        cls.socketLocker.release()
        # end def


def checkIpv4(ip):
    match = re.findall(
        u"^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$",
        ip,
        re.I
    )
    if match and len(match) > 0:
        return True
    else:
        return False


def checkIpv4Inner(ip):
    match = re.findall(
        u"(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])",
        ip,
        re.I
    )
    if match and len(match) > 0:
        return True
    else:
        return False


def checkIpv4Range(ip_range):
    match = re.findall(
        u"^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])-(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$",
        ip_range,
        re.I
    )
    if match and len(match) > 0:
        return True
    else:
        return False


# end def
# MCJ :checkIpv6 'module' object has no attribute 'inet_pton' set checkIpv6()return false
def checkIpv6(ipv6_addr):
    try:
        # addr = socket.inet_pton(socket.AF_INET6, ipv6_addr)
        pass
    except socket.error:
        return False
    else:
        return False


def checkIpv6Inner(ipaddr):
    ip = ipaddr.upper()
    match = re.findall(
        u"((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?",
        ip, re.I)
    if match and len(match) > 0:
        return True
    else:
        return False


def checkIpv6Domain(domain):
    ip = domain.upper()
    match = re.findall(
        u"^\[((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\]$",
        ip, re.I)
    if match and len(match) > 0:
        return True
    else:
        return False


def checkIpv6Range(ip_range):
    try:
        last_colon_index = 0
        tmp = ip_range.split('-')
        if len(tmp) == 2:
            if checkIpv6(tmp[0]):
                if checkIpv6(tmp[1]):
                    return True
                for i in range(len(tmp[0])):
                    if tmp[0][i] == ':':
                        last_colon_index = i
                tmp_line = tmp[0][last_colon_index + 1:]
                if len(tmp_line) > len(tmp[1]):
                    return False
                elif len(tmp_line) < len(tmp[1]):
                    return True
                else:
                    if cmp(tmp_line, tmp[1]) <= 0:
                        return True
                    else:
                        return False
            else:
                return False
        else:
            return False
    except Exception, e:
        return False


# 十六进制 to 十进制
def hex2dec(string_num):
    return int(string_num.upper(), 16)


# 十进制 to 十六进制
def dec2hex(string_num):
    base = [str(x) for x in range(10)] + [chr(x) for x in range(ord('A'), ord('A') + 6)]
    num = int(string_num)
    mid = []
    while True:
        if num == 0: break
        num, rem = divmod(num, 16)
        mid.append(base[rem])

    return ''.join([str(x) for x in mid[::-1]])


def ipv4Toint(addr):
    try:
        return struct.unpack("!I", socket.inet_aton(addr))[0]
    except Exception, e:
        return ''


def intToipv4(i):
    try:
        return socket.inet_ntoa(struct.pack("!I", i))
    except Exception, e:
        return ''


def fullIpv6(ip):
    if ip == "" or len(ip) < 4 or len(ip) > 39:
        return False
    ip = ip.upper()
    match = re.findall(
        u"^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$",
        ip, re.I)
    if match and len(match) > 0:
        ip_sep = ip.split(":")
        if len(ip_sep) < 8:
            t = 8 - len(ip_sep)
            ip = ip.replace("::", ":" * (t + 2))
        ip_sep = ip.split(":")
        ip = []
        for row in ip_sep:
            row = "0000%s" % (row)
            ip.append(row[-4:])
        ip = ":".join(ip)

        return ip
    else:
        return False


def easyIpv6(ip):
    if ip == "" or len(ip) < 4 or len(ip) > 39:
        return False
    ip = ip.lower()
    match = re.findall(
        u"^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$",
        ip, re.I)
    if match and len(match) > 0:
        ip_sep = ip.split(":")
        ip = []
        for row in ip_sep:
            i = 0
            for i in range(len(row)):
                if row == "":
                    break
                elif row == "0":
                    row = "0"
                    break
                elif row[0] == "0":
                    row = row[1:]
                else:
                    break
            ip.append(row)
        if len(ip) == 8:
            ip = ":".join(ip)
            i = 8
            while i > 1:
                index = ip.find(":" + "0:" * i)
                if index > 0:
                    ip = "%s::%s" % (ip[0:index], ip[index + (2 * i + 1):])
                    break
                i -= 1
        else:
            ip = ":".join(ip)

        return ip
    else:
        return False


def getIpv4Range(ip_start, ip_end):
    ip_list = []
    ip_start_int = ipv4Toint(ip_start)
    ip_end_int = ipv4Toint(ip_end)

    if ip_start_int > ip_end_int:
        ip_list = False
    elif ip_start_int == ip_end_int:
        ip_list.append(ip_start)
    else:
        for i in range(ip_start_int, ip_end_int + 1):
            ip = intToipv4(i)
            ip_list.append(ip)
    return ip_list


def getIpv6Range(ip_start, ip_end):
    ip_list = []
    ip_start = fullIpv6(ip_start)
    ip_end = fullIpv6(ip_end)

    if ip_start == False or ip_end == False:
        return False
    if ip_start == ip_end:
        ip_list.append(easyIpv6(ip_start))
        return ip_list
    if cmp(ip_start, ip_end) == 1:
        return False

    ip_org = ""
    i = 0
    for i in range(len(ip_start)):
        if ip_start[i] != ip_end[i]:
            ip_org = ip_start[0:i]
            ip_start = ip_start[i:]
            ip_end = ip_end[i:]
            break
    if len(ip_start) > 4:
        return False

    j = len(ip_start)

    for i in range(hex2dec(ip_start), hex2dec(ip_end) + 1):
        t = dec2hex(i)
        t = "0000%s" % (t)
        t = "%s%s" % (ip_org, t[-j:])
        ip_list.append(easyIpv6(t))

    return ip_list


def domainToip(domain):
    try:
        if domain == "":
            return False
        if domain.find("://") > 0:
            domain = domain.split("://")[1]
        if checkIpv4(domain) or checkIpv6(domain):
            return domain
        match = re.findall(
            u"((\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5]))",
            domain, re.I)
        if match and len(match) > 0:
            return match[0][0]
        # end if

        match = re.findall(
            u"((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?",
            domain, re.I)
        if match and len(match) > 0:
            return match[0][0]

        if domain.find(":") > 0:
            if len(domain.split(":") > 2):
                return False
            else:
                domain = domain.split(":")[0]

        res = socket.getaddrinfo(domain, None)
        if res and len(res) > 0:
            return res[0][4][0]

        return False

    except Exception, e:
        return False


def ipv6ToBin(ipv6):
    try:
        tmp = fullIpv6(ipv6)
        if tmp == False:
            return False
        res_ip = ''
        ret = []
        for i in range(len(tmp)):
            if tmp[i] != ':':
                res = bin(int(tmp[i], 16))
                res = res[2:]
                a = len(res)
                if a < 4:
                    r = ''
                    for j in range(4 - a):
                        r += '0'
                    res += r
                res_ip += res

        return res_ip

    except Exception, e:
        return False


def validUrls(domain, urlList, resList=[200]):
    try:
        liveList = []
        conn = httplib.HTTPConnection(domain)
        for url in urlList:
            try:
                conn.request("HEAD", url)
                res = conn.getresponse()
                res.read()
                if res.status in resList:
                    liveList.append(url)
            except Exception, e:
                pass
        conn.close()
        return liveList
    except Exception, e:
        return liveList


def nonascii(url, code="utf-8"):
    _nonascii = re.compile(r"[^\x00-\xff]")
    try:
        if isinstance(url, str):
            url = url.decode(code)
        return _nonascii.search(url)
    except Exception, e:
        return ''


def safeUrlString(url):
    _reserved = ';/?:@&=+$|,#'  # RFC 3986 (Generic Syntax)
    _unreserved_marks = "-_.!~*'()"  # RFC 3986 sec 2.3
    _safe_chars = urllib.always_safe + '%' + _reserved + _unreserved_marks
    return urllib.quote(url, _safe_chars)


def getTopDomain(domain):
    try:
        domain = domain.lower()
        domain = domain.replace('http://', '')
        domain = domain.replace('https://', '')

        suffix = ['cn', 'com', 'edu', 'gov', 'int', 'mil', 'net', 'org', 'biz', 'info', 'pro', 'name', 'museum', 'coop',
                  'aero', 'xxx', 'idv']

        if checkIpv4(domain) or checkIpv6(domain):
            return domain

        if checkIpv6Inner(domain):

            a = domain.find('[')
            b = domain.find(']')
            if a >= 0 and b >= 0:
                return domain[a:b] + ']'
            else:
                return None

        if domain.find('/') > 0:
            t = domain.split('/')
            domain = t[0]

        if domain.find(':') > 0:
            t = domain.split(':')
            domain = t[0]

        t = domain.split('.')
        if len(t) < 2:
            return None

        if t[-1] not in suffix and t[-2] not in suffix:
            return domain

        if t[-2] in suffix and len(t) > 2:
            return '.'.join(t[-3:])

        if t[-1] in suffix and len(t) > 1:
            return '.'.join(t[-2:])

        return '.'.join(t)
    except Exception, e:
        writeFileLog(str(e), getCurrentFunctionName())
        return domain


# ----------------------plugins common-----------------------------------------------
def checkUrlType(url):
    not_run_type_list = ['rar', 'zip', 'tar', 'js', 'css', 'db', 'xml', 'txt']
    try:
        filename = url.split('/')[-1].split('.')
        type = ""
        if len(filename) > 1:
            type = filename[1]

        if type != "":
            if type in not_run_type_list:
                return False

        return True
    except Exception, e:
        logger.error("File:common.py, function checkUrlType:" + str(e))
        return True


def requestUrl(http, url, taskId=0, siteId=0):
    try:
        res = {}
        content = ''
        try:
            res, content = http.request(url, "GET")
        except socket.timeout, e:
            res['status'] = '404'
            res['content-location'] = url
        except Exception, e:
            req = urllib2.Request(url)
            response = urllib2.urlopen(req)
            header = response.info()
            location = response.geturl()
            content = response.read()
            response.close()
            for key in header:
                res[key] = header[key]

            res['status'] = '200'
            res['content-location'] = location

        return res, content
    except Exception, e1:
        pass

    return {'status': '404', 'content-location': url}, ""


def changeParams(params):
    list = []
    try:
        params = params.split('&')
        count = len(params)
        if count == 0:
            list.append(params[0])
        else:
            for i in range(len(params)):
                temp = params[0]
                params = params[1:]
                params.append(temp)
                list.append('&'.join(params))

        return list
    except Exception, e:
        print "changeParams Exception", str(e)
        return list


def getRequest(url, method='GET', headers={}, body="", domain=None):
    try:

        # scheme = parse[0]
        if not domain:
            parse = urlparse.urlparse(url)
            domain = parse[1]
        # path = url.replace("%s://%s" % (scheme, domain), "")
        # if path == "":
        #     path = "/"
        list = []
        list.append("%s %s" % (method, url))
        if len(headers.keys()) > 0:
            for k in headers:
                list.append("%s: %s" % (k, headers[k]))
        else:
            list.append("Host: %s" % domain)
            list.append("Connection: Keep-alive")
            list.append("Accept: text/plain")
            list.append(
                "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.1) Gecko/20090624 Firefox/3.5")
        if body != "":
            list.append("Content: %s" % body)
        return "\n".join(list)
    except Exception, e:
        logger.error("File:common.py, getRequest function:" + str(e) + ",url:" + str(url))
        return ''


def postRequest(url, method='POST', headers={}, data="", body="", domain=None):
    try:
        if not domain:
            parse = urlparse.urlparse(url)
            domain = parse[1]
        # path = url.replace("%s://%s" % (scheme, domain), "")

        list = []
        list.append("%s %s " % (method, url))
        if len(headers.keys()) > 0:
            for k in headers:
                list.append("%s: %s" % (k, headers[k]))

        else:
            list.append("Host: %s" % domain)
            list.append("Connection: Keep-alive")
            list.append("Accept: text/plain")
            list.append(
                "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.1) Gecko/20090624 Firefox/3.5")

        if data != "":
            list.append("")
            list.append(data)
        if body != "":
            list.append("Content: %s" % body)

        return "\n".join(list)
    except Exception, e:
        logger.error("File:common.py, postRequest function:" + str(e) + ",url:" + str(url))
        return ''


def getResponse(res, content='', keywords=None, save_con_num=50):
    try:
        list = []
        if res and len(res.keys()) > 0:
            list.append("HTTP/1.1 %s %s" % (res['status'], HTTP_STATUS_DICT[res['status']]))
            for k in res:
                if k != 'status':
                    list.append("%s:%s" % (k, res[k]))
            if content != "":
                list.append("")
                if not keywords:
                    list.append(content)
                else:
                    pattern = '(.{0,%s}%s.{0,%s})' % (save_con_num, keywords, save_con_num)
                    m = re.search(pattern, content, re.I | re.M | re.S)
                    if m:
                        save_con = m.groups()[0]
                        list.append(save_con)
                    else:
                        list.append(content)
        return "\n".join(list)
    except Exception, e:
        logger.error("File:common.py, getResponse function:" + str(e))
        return ''


def XssGetKeyWord(content, keyword):
    try:
        if content.find(keyword) >= 0:
            lines = content.replace('\r\n', '\n').split('\n')
            for line in lines:
                match = re.findall(r"<(\s*?)title(\s*?)>(.+?)<(\s*?)/(\s*?)title(\s*?)>", line, re.I)
                for row in match:
                    if row[2].find(keyword) >= 0:
                        return True, "</title>%s" % (keyword)

                # test <textarea>
                match = re.findall(r"<(\s*?)textarea(.*?)>(.+?)<(\s*?)/(\s*?)textarea(\s*?)>", line, re.I)
                for row in match:
                    if row[2].find(keyword) >= 0:
                        return True, "</textarea>%s" % (keyword)

                # test input
                match = re.findall(r"<(\s*?)input(.+?)value=(.+?)/(\s*?)>", line, re.I)
                for row in match:
                    if row[2].find(keyword) >= 0:
                        temp = row[2].strip()
                        if temp[0] == "'":
                            return True, "'/>%s" % (keyword)
                        elif temp[0] == "\"":
                            return True, "\"/>%s" % (keyword)
                        else:
                            return True, "/>%s" % (keyword)

                # test input
                match = re.findall(r"<(\s*)input(.+?)value(\s*)=(\s*)(\"|'|\s*)(.+?)\5(\s*)>", line, re.I)
                for row in match:
                    if row[5].find(keyword) >= 0:
                        temp = row[5].strip()
                        if row[4] == "'":
                            return True, "'>%s" % (keyword)
                        elif row[4] == "\"":
                            return True, "\">%s" % (keyword)
                        else:
                            return True, ">%s" % (keyword)

                # test action and href
                match = re.findall(r"(action|href)(\s*)=(\s*)(\"|')(.+?)\4", line, re.I)
                for row in match:
                    if row[4].find(keyword) >= 0:
                        return True, "%s>%s" % (row[3], keyword)

            # test <script>
            match = re.findall(r"<(\s*?)script(.*?)>(.+?)<(\s*?)/(\s*?)script(\s*?)>", content, re.I | re.DOTALL)
            for row in match:
                if row[2].find("<script>") >= 0:
                    return True, "</script>%s" % (keyword)

            return True, keyword
        else:
            return False, ""
    except Exception, e:
        print "XssGetKeyWord exception : ", str(e)
        return False, ""


def LinkGetKeyWord(content, keyword):
    try:
        if content.find(keyword) >= 0:
            lines = content.replace('\r\n', '\n').split('\n')
            for line in lines:
                # test <title>
                match = re.findall(r"<(\s*)title(\s*)>(.+?)<(\s*)/(\s*)title(\s*)>", line, re.I)
                for row in match:
                    if row[2].find(keyword) >= 0:
                        return True, "</title><iframe src=http://www.baidu.com></iframe>"

                # test <textarea>
                match = re.findall(r"<(\s*)textarea(.*?)>(.+?)<(\s*)/(\s*)textarea(\s*)>", line, re.I)
                for row in match:
                    if row[2].find(keyword) >= 0:
                        return True, "</textarea><iframe src=http://www.baidu.com></iframe>"

                # test input
                match = re.findall(r"<(\s*)input(.+?)value=(.+?)/(\s*)>", line, re.I)
                for row in match:
                    if row[2].find(keyword) >= 0:
                        temp = row[2].strip()
                        if temp[0] == "'":
                            return True, "'/><iframe src=http://www.baidu.com></iframe>"
                        elif temp[0] == "\"":
                            return True, "\"/><iframe src=http://www.baidu.com></iframe>"
                        else:
                            return True, "/><iframe src=http://www.baidu.com></iframe>"

                # test input
                match = re.findall(r"<(\s*)input(.+?)value(\s*)=(\s*)(\"|'|\s*)(.+?)\5(\s*)>", line, re.I)
                for row in match:
                    if row[5].find(keyword) >= 0:
                        temp = row[5].strip()
                        if row[4] == "'":
                            return True, "'><iframe src=http://www.baidu.com></iframe>"
                        elif row[4] == "\"":
                            return True, "\"><iframe src=http://www.baidu.com></iframe>"
                        else:
                            return True, "><iframe src=http://www.baidu.com></iframe>"

                # test action and href
                match = re.findall(r"(action|href)(\s*)=(\s*)(\"|')(.+?)\4", line, re.I)
                for row in match:
                    if row[4].find(keyword) >= 0:
                        return True, "%s><iframe src=http://www.baidu.com></iframe>" % (row[3])

                # test <script>
                match = re.findall(r"<(\s*)script(.*?)>(.+?)<(\s*)/(\s*)script(\s*)>", line, re.I)
                for row in match:
                    if row[2].find(keyword) >= 0:
                        return True, "</script><iframe src=http://www.baidu.com></iframe>"

            return True, "<iframe src=http://www.baidu.com></iframe>"
        else:
            return False, ""
    except Exception, e:
        print "LinkGetKeyWord exception : ", str(e)
        return False, ""


def LinkGetKeyWordNoSrc(content, keyword):
    try:
        if content.find(keyword) >= 0:
            lines = content.replace('\r\n', '\n').split('\n')
            for line in lines:
                # test <title>
                match = re.findall(r"<(\s*)title(\s*)>(.+?)<(\s*)/(\s*)title(\s*)>", line, re.I)
                for row in match:
                    if row[2].find(keyword) >= 0:
                        return True, "</title><iframe></iframe>"

                # test <textarea>
                match = re.findall(r"<(\s*)textarea(.*?)>(.+?)<(\s*)/(\s*)textarea(\s*)>", line, re.I)
                for row in match:
                    if row[2].find(keyword) >= 0:
                        return True, "</textarea><iframe></iframe>"

                # test input
                match = re.findall(r"<(\s*)input(.+?)value=(.+?)/(\s*)>", line, re.I)
                for row in match:
                    if row[2].find(keyword) >= 0:
                        temp = row[2].strip()
                        if temp[0] == "'":
                            return True, "'/><iframe></iframe>"
                        elif temp[0] == "\"":
                            return True, "\"/><iframe></iframe>"
                        else:
                            return True, "/><iframe></iframe>"

                # test input
                match = re.findall(r"<(\s*)input(.+?)value(\s*)=(\s*)(\"|'|\s*)(.+?)\5(\s*)>", line, re.I)
                for row in match:
                    if row[5].find(keyword) >= 0:
                        temp = row[5].strip()
                        if row[4] == "'":
                            return True, "'><iframe></iframe>"
                        elif row[4] == "\"":
                            return True, "\"><iframe></iframe>"
                        else:
                            return True, "><iframe></iframe>"

                # test action and href
                match = re.findall(r"(action|href)(\s*)=(\s*)(\"|')(.+?)\4", line, re.I)
                for row in match:
                    if row[4].find(keyword) >= 0:
                        return True, "%s><iframe></iframe>" % (row[3])

            # test <script>
            if content.find("script") > 0:
                match = re.findall(r"<(\s*)script(.*?)>(.+?)<(\s*)/(\s*)script(\s*)>", content, re.I | re.DOTALL)
                for row in match:
                    if row[2].find(keyword) >= 0:
                        return True, "</script><iframe></iframe>"

            return True, "<iframe></iframe>"
        else:
            return False, ""
    except Exception, e:
        print "LinkGetKeyWordNoSrc exception : ", str(e)
        return False, ""


def getRecord(ob, url, level, detail, request="", response="", output="", payload=[], params=[]):
    '''格式化扫描结果数据，为数据入库做准备
    返回格式化后的数据记录，字典类型，如：
        {'domain': 'www.yundun.com', 'ip': '127.0.0.1', 'siteId': 1, 'level': 'HIGH', 'url': 'https://www.yundun.com/login', 'response': '<html><body>no login</body></html>\n', 'request': 'GET /login  HTTP/1.1\nHost: www.yundun.com\nConnection: Keep-alive\nAccept: text/plain\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.1) Gecko/20090624 Firefox/3.5', 'detail': '\xe7\x99\xbb\xe5\xbd\x95\xe9\xa1\xb5\xe9\x9d\xa2\xe6\x9c\xaa\xe8\xae\xbe\xe7\xbd\xae\xe9\xaa\x8c\xe8\xaf\x81\xe7\xa0\x81\xe6\xa0\xa1\xe9\xaa\x8c', 'payload': "'\n''", 'vulId': '1', 'output': ''}
    '''
    try:
        return {'siteId': ob['siteId'], 'url': url, 'ip': ob['ip'], 'domain': ob['domain'], 'level': level,
                'vulId': ob['vulId'], 'request': request, 'response': response, 'detail': detail, 'output': output,
                'payload': "\n".join(payload), 'params': "\n".join(params)}
    except Exception, e:
        logger.error(e)


def getRecord2(scanInfo={}, injectInfo={}):
    '''
    created by lidq
    格式化扫描数据，为扫描结果落地做准备
    输入参数如下：
        scanInfo，扫描的一些前置信息，包括
        injectInfo，扫描结果信息，包括
        格式化输出信息如下：
        siteId，站点ID，对于sites表
        url，扫描出漏洞的url
        ip，网站对应的IP
        domain，域名
        level，风险等级
        vulId，病毒ID
        detail，详情
        request，请求实体
        response，响应实体
        output，额外的输出信息
        payload，注入攻击的字符串
    '''
    result = {}
    result['siteId'] = scanInfo['siteId']
    result['url'] = injectInfo['url']
    result['ip'] = scanInfo['ip']
    result['domain'] = scanInfo['domain']
    result['level'] = scanInfo['level']
    result['vulId'] = scanInfo['vulId']
    result['detail'] = injectInfo['detail']
    result['request'] = injectInfo['request']
    result['response'] = injectInfo['response']
    result['output'] = injectInfo['output']
    if injectInfo.has_key('payload'):
        result['payload'] = "\n".join(injectInfo['payload'])
    else:
        result['payload'] = ''
    if injectInfo.has_key('params'):
        result['params'] = "\n".join(injectInfo['params'])
    else:
        result['params'] = ''
    return result


def findCode(content):
    try:
        match = re.findall(r"<meta(.+?)charset(.*?)=(.+?)\"", content, re.I)
        if match and len(match) > 0:
            row = match[0][2].replace(" ", "").lower()
            return row
        else:
            return 'utf8'
    except Exception, e:
        logger.error("File:common.py, findCode:" + str(e))
        return 'utf8'


def changeCode(msg, code='utf8'):
    if code == 'utf8' or code == 'utf-8':
        return msg
    else:
        try:
            return msg.decode(code).encode('utf8')
        except Exception, e:
            return ""


def _conn_request(conn, request_uri, method="GET", body=None, headers={}):
    RETRIES = 2
    for i in range(RETRIES):
        try:
            if hasattr(conn, 'sock') and conn.sock is None:
                conn.connect()
            conn.request(method, request_uri, body, headers)
        except socket.timeout:
            raise
        except socket.gaierror:
            conn.close()
            raise
        except ssl.SSLError:
            conn.close()
            raise
        except socket.error, e:
            err = 0
            if hasattr(e, 'args'):
                err = getattr(e, 'args')[0]
            else:
                err = e.errno
            if err == errno.ECONNREFUSED:  # Connection refused
                raise
        except httplib.HTTPException:
            if hasattr(conn, 'sock') and conn.sock is None:
                if i < RETRIES - 1:
                    conn.close()
                    conn.connect()
                    continue
                else:
                    conn.close()
                    raise
            if i < RETRIES - 1:
                conn.close()
                conn.connect()
                continue
        try:
            response = conn.getresponse()
        except (socket.error, httplib.HTTPException):
            if i < RETRIES - 1:
                conn.close()
                conn.connect()
                continue
            else:
                conn.close()
                raise
        else:
            content = ""
            content = response.read()
        break
    return (response, content)


def valid_urls(url, url_list, res_list=[200]):
    try:
        if not url_list:
            return []
        live_list = []
        # Step 1. Send HEAD request to valid url
        conn = httplib.HTTPConnection(url)
        for item in url_list:
            try:
                res, _ = _conn_request(conn, item, "HEAD")
                if res.status in res_list:
                    live_list.append(item)
            except Exception, e:
                logger.error("function valid_urls for Exception(inner):%s" % str(e))

        conn.close()
        if float(len(live_list)) / len(url_list) > 0.3:
            return []

        return live_list
    except Exception, e:
        logger.error("function valid_urls Exception(outer):%s" % str(e))
        return live_list


def formatPluginParams(config={}, item={}):
    '''格式化插件参数，将任务参数及URL参数分离开，并且请求的query转换为字典
    输入参数：
       config：任务配置信息
       item：url信息
    返回的数据：
       scanInfo，返回任务信息
       urlDict，URL字典
    '''
    scanInfo = {}
    scanInfo['siteId'] = config['siteId']
    scanInfo['ip'] = config['ip']
    scanInfo['domain'] = config['domain']
    scanInfo['level'] = config['level']
    scanInfo['vulId'] = config['vulId']
