#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket, thread, select, re, signal, sys
import MySQLdb
from engineConfig import *

from logger import scanLogger as logger

__version__ = '0.1.0 Draft 1'
BUFLEN = 8192
VERSION = 'Python Proxy/'+__version__
HTTPVER = 'HTTP/1.1'

exclude_suffix = ["jpg", "gif", "png", "bmp", "jpeg", "xml", "css"]

resp_pcre = re.compile(r"([hH][tT][tT][pP]\/1\.\d[\s\S]*?)\r\n\r\n")
resp_set_cookie_pcre = re.compile(r"[sS][eE][tT]-[Cc][oO][oO][kK][iI][eE]:([\s\S]*?)\r\n")
req_pcre = re.compile(r"[Cc][oO][oO][kK][iI][eE]:([\s\S]*?)\r\n")
url_pcre = re.compile(r"([hH][tT][tT][pP]s{0,1}:\/\/[\s\S]*?)\s")
domain_pcre = re.compile(r"([hH][tT][tT][pP]s{0,1}:\/\/[\s\S]*?)\/")

def update_cookie(domain, url, cookie):

    try:
        if url.split(".")[-1].lower() in exclude_suffix:
            return
        domain = domain.strip()
        url    = url.strip()
        cookie = cookie.strip()
        id = 0
        cookie_dic = {}
        tmp_list = []
        
        I_or_U = True  #True: insert, False: update

        conn = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, db=SCANER_DB_DATABASE,charset='utf8')
        cur = conn.cursor(MySQLdb.cursors.DictCursor)
        sql = "select * from cookie where url = %s"
        cur.execute(sql, (url))
        
        ret = cur.fetchone()
     
        if ret and ret["cookie"]:
            id = int(ret["id"])
            I_or_U = False
            
            c_str = ret["cookie"].strip()
            cookies = c_str.split(";")
        
            for c in cookies:
                c = c.strip()

                tokens = c.split("=", 1)
                
                if len(tokens) != 2:
                    continue

                cookie_dic[tokens[0].strip()] = tokens[1].strip()

    
        cookies = cookie.split(";")
        
        for c in cookies:
            c = c.strip()
            tokens = c.split("=", 1)
            
            if len(tokens) != 2:
                continue
            cookie_dic[tokens[0].strip()] = tokens[1].strip()
        
        
        
        for k in cookie_dic.keys():
            tmp_list.append(k + "=" + cookie_dic[k])
        
        new_cookie_str = "; ".join(tmp_list)
        
        if I_or_U:
            sql  = "insert into cookie values(0, %s, %s, %s, now())"
            cur.execute(sql, (domain, url, new_cookie_str))
            conn.commit()
        else:
            sql  = "update cookie set `domain` = %s, `url` = %s, `cookie` = %s, `update_time` = now() where id = %s"
            cur.execute(sql, (domain, url, new_cookie_str, str(id)))
            conn.commit()
    except Exception,e:
        print e

class ConnectionHandler:
    def __init__(self, connection, address, timeout):
        
        
        try:
            self.now_url = ""
            self.now_domain = ""
            self.client = connection
            self.client_buffer = ''
            self.timeout = timeout
            self.method, self.path, self.protocol = self.get_base_header()
            if self.method=='CONNECT':
                self.method_CONNECT()
            elif self.method in ('OPTIONS', 'GET', 'HEAD', 'POST', 'PUT',
                                 'DELETE', 'TRACE'):
                self.method_others()
            self.client.close()
        except Exception, e:
            self.client.close()
            self.target.close()
        #end try

    def get_base_header(self):
        while 1:
            self.client_buffer += self.client.recv(BUFLEN)
            end = self.client_buffer.find('\n')
            if end!=-1:
                break
        print '====%s'%self.client_buffer[:end]#debug
        
        domain = domain_pcre.findall(self.client_buffer[:end])
        url    = url_pcre.findall(self.client_buffer[:end]) 
        
        if domain and len(domain) == 1 and url and len(url) == 1:
            print "domain:",domain[0]
            print "url:", url[0]
            
            self.now_domain = domain[0]
            self.now_url    = url[0]
        data = (self.client_buffer[:end+1]).split()
        self.client_buffer = self.client_buffer[end+1:]
        return data

    def method_CONNECT(self):
        self._connect_target(self.path)
        self.client.send(HTTPVER+' 200 Connection established\n'+
                         'Proxy-agent: %s\n\n'%VERSION)
        self.client_buffer = ''
        self._read_write()        

    def method_others(self):
        self.path = self.path[7:]
        i = self.path.find('/')
        host = self.path[:i]        
        path = self.path[i:]
        self._connect_target(host)
        self.target.send('%s %s %s\n'%(self.method, path, self.protocol)+
                         self.client_buffer)

        req_cookie =  req_pcre.findall(self.client_buffer)
        if req_cookie and len(req_cookie) == 1:
            print "req_cookie", req_cookie[0]
            
            update_cookie(self.now_domain, self.now_url, req_cookie[0])
        #end if
        self.client_buffer = ''
        self._read_write()

    def _connect_target(self, host):
        _host = ''
        _port = ''
        if '[' in host and ']' in host:
            _host = host[host.find('[')+1:host.find(']')] 
            _port = host[host.find(']'):]
            if ':' in _port:
                _port = int(_port[_port.find(':')+1:])
            else:
                _port = 80 
            self.target = socket.socket(socket.AF_INET6)
            self.target.connect((_host,80))
        else:
            i = host.find(':')
            if i!=-1:
                _port = int(host[i+1:])
                _host = host[:i]
            else:
                port = 80
            (soc_family, _, _, _, address) = socket.getaddrinfo(host, port)[0]
            self.target = socket.socket(soc_family)
            self.target.connect(address)

    def _read_write(self):
        time_out_max = self.timeout/3
        socs = [self.client, self.target]
        count = 0
        while 1:
            count += 1
            (recv, _, error) = select.select(socs, [], socs, 3)
            if error:
                break
            if recv:
                for in_ in recv:
                    
                    data = in_.recv(BUFLEN)
                    resp = resp_pcre.findall(data)
                    if resp and len(resp) == 1:
                        
                        resp_cookie = resp_set_cookie_pcre.findall(resp[0])
                        
                        if resp_cookie and len(resp_cookie) == 1:
                            print "resp_cookie", resp_cookie[0]
                            update_cookie(self.now_domain, self.now_url, resp_cookie[0])
                        #end if
                    #end if
                    
                    if in_ is self.client:
                        out = self.target
                    else:
                        out = self.client
                    if data:
                        out.send(data)
                        count = 0
            if count == time_out_max:
                break
            
def single_process( a, b):
    soc.close()
    sys.exit(0)

def start_server(host='', port=8080, IPv6=False, timeout=60,
                  handler=ConnectionHandler):
    global soc
    httpProxyFlag = 0
    if httpProxyFlag == 1:
        print 'ipv6'
        soc = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        print 'ipv4'
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    soc.bind((host, port))
    print "Serving on %s:%d."%(host, port)
    soc.listen(0)
    while 1:
        thread.start_new_thread(handler, soc.accept()+(timeout,))

if __name__ == '__main__':
    signal.signal(signal.SIGTERM,single_process) 
    signal.signal(signal.SIGINT,single_process)

    try:
        ifen = 1
        port = 8080
        ifen = 1
        if ifen and int(ifen) == 1:
            if port:
                start_server(port = int(port))
            #end if
        #end if

    except Exception, e:
        logger.error("File:proxy.py main:" + str(e))
    #end try


