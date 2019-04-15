# --*-- coding: utf-8 --*--
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
import socket


def run_domain(http, ob):
    try:
        webserver = ob.get('webServer')
        if webserver and webserver in ['apache', 'nginx']:
            return []
        scheme = ob['scheme']
        domain = ob['domain']
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        port = '80'
        result = []
        if scheme == 'https':
            port = '443'
        hexAllFfff = "18446744073709551615"
        req = "GET / HTTP/1.0\r\n\r\n"
        req1 = "GET / HTTP/1.1\r\nHost: stuff\r\nRange: bytes=0-" + hexAllFfff + "\r\n\r\n"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((domain, int(port)))
        s.send(req)
        resp = s.recv(1024)
        s.close()
        if "Microsoft" not in resp:
            print "[*] Not IIS"
            return result
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.connect((domain, int(port)))
        s1.send(req1)
        resp1 = s1.recv(1024)
        s1.close()
        if "Requested Range Not Satisfiable" in resp1:
            print "[!!] Looks VULN"
        # elif " The request has an invalid header name" in resp1:
        #                 print "[*] Looks Patched"
            url = "%s://%s" % (scheme, domain)
            response = resp1
            request = req1
            detail = "IIS HTTP.sys远程执行代码漏洞"
            result.append(getRecord(ob, url, ob['level'], detail, request, response))

        return result

    except Exception, e:
        logger.error("File:MS15_034.py, run_domain function :%s" % (str(e)))
        return []








                
                
                

