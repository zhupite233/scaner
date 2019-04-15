#!/usr/bin/python
# -*- coding: utf-8 -*-
import time
import HTMLParser
import platform
import urlparse
import hashlib
import json as jsonRaw
from xml import sax
from engine_lib import yd_json as json
from db.MysqlDao import MysqlDao
from engine_utils.common import *
from engine_lib import yd_urllib as urllib2
from engineConfig import SCANER_SPIDER_DOWNLOAD_DIR

from logger import scanLogger as logger

#执行扫描相关的命令
def vulscan_popen(command = ''):
    fp = os.popen(command)
    output = fp.read()
    return  output.split("\n")

class Spider:
    def __init__(self, conf):
        try:
            self.module = self.__class__.__name__
            self.taskId = conf['taskId']
            self.assetTaskId = conf['assetTaskId']
            self.siteId = conf['siteId']
            self.scheme = conf['scheme']
            self.domain = conf['domain'].lower()
            if checkIpv6(conf['domain']):
                self.domain = easyIpv6(conf['domain'])
                self.domain = '[' + self.domain + ']'

            self.path = conf['path']
            self.url = "%s://%s%s" % (self.scheme, self.domain, self.path)
            self.ip = conf['ip']
            if checkIpv6(conf['ip']):
                self.ip = conf['ip'].lower()
                self.ip = easyIpv6(self.ip)

            self.title = conf['title']
            self.policy = conf['policy']
            self.cookie = conf['cookie']
            self.status = True
            self.siteCode = ''
            self.otherDomainList = []
            self.urlQueue = Queue()
            self.timeoutContent = "timeout"
            self.webScanTimeout = conf['webScanTimeout']
            self.maxTimeoutCount = conf['maxTimeCount']
            self.timeoutCount = 0
            self.result = []
            self.endTime = conf['endTime']
            self.num = 0
            self.maxnum = conf['maxnum']
            self.nomatchTypeList = ['.mp3','.pdf','.png','.jpg','.gif','.rm','.asf','.exe','.mov','.ttf','.rmvb','.rtf','.ra','.mp4','.wma','.wmv','.xps','.doc','.docx','.txt','.zip','.rar','.mht','.msi','.flv','.xls','.nrg','.cd','.ppt','.ld2','.ocx','.url','.avi','.swf','.db','.bmp','.psd','.chm','.iso','.ape','.cue','.u32','.ucd','.dll','.ico','.pk','.lrc','.m4v','.cnn','.m3u','.tif','.mpeg','.srt','.chs','.cab','.xsl','.pps','.doc','.tar','.tgz','.bz','.gz','.mpg','.jpeg','.bmp']
            self.uncontentTypeList = ['.mdb','.sql']
            self.htmlPattern = []
            self.ipPattern = re.compile("^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$")
            self.ipv6Pattern = re.compile("^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$")
            self.sameUrlPatternCount = 5
            self.downloadDir = conf['downloadDir']
            self.excludeUrl = conf['excludeUrl']
            self.includeUrl = conf['includeUrl']
            self.patternDict = {}
            self.sep = '####################'
            self.hasSpace = True
            self.swfs = []
            self.postPattern = set()
            self.topDomain = getTopDomain(self.domain)
            self.htmlParser = HTMLParser.HTMLParser()
            self.http = HttpRequest({'timeout':30,'cookie':conf['cookie']})
            self.dao = MysqlDao()
            self.code = ''
            self.init()
        except Exception,e:
            logger.exception(e)

    def getFullUrl(self, scheme, domain, url):
        try:
            if url.find('http://') >= 0 or url.find('https://') >= 0 or url.find('HTTP://') >= 0 or url.find('HTTPS://') >= 0:
                return url

            url = url.replace("../","/").replace("./","/").replace("//","/")
            if url == '':
                return "%s://%s/" % (scheme, domain)
            else:
                if url[0] == '/':
                    return "%s://%s%s" % (scheme, domain, url)
                else:
                    return "%s://%s/%s" % (scheme, domain, url)
                #end if
            #end if
            
        except Exception,e:
            raise
        #end try
    #end def

    def parseUrl(self, url):
        try:
            scheme = ''
            domain = ''
            path = ''
            
            parse = urlparse.urlparse(url)
            scheme = parse[0]
            domain = parse[1]
            if domain.find(':') > 0:
                port = domain.split(':')[1]
                if port == '80':
                    scheme = 'http'
                    domain = domain.split(':')[0]
                elif port == '443':
                    scheme = 'https'
                    domain = domain.split(':')[0]
                #end if
            #end if
            if parse[2] == "":
                path = "/"
            else:
                t = parse[2].split("/")
                if len(t) <= 2:
                    path = "/"
                else:
                    t[-1] = ""
                    path = "/".join(t)
                #end if
            #end if
            
            return scheme, domain, path
        except Exception, e:
            raise
        #end try 
    #end def 

    def getRedirect(self, url):
        try:
            scheme = 'http'
            domain = ''
            path = ''
            parse = urlparse.urlparse(url)
            if parse[0] == 'http' or parse[0] == 'https':
                scheme = parse[0]
            #end if
            domain = parse[1]
            path = parse[2]
            if path == '':
                path = '/'
            #end if
            url = "%s://%s%s" % (scheme, domain, path)
            http = HttpRequest({'timeout':60,'follow_redirects':False,'cookie':self.cookie})
            res, content = http.request(url)
            if res and res.has_key('status') and res['status'] in ['200','301','302','403']:
                if res['status'] in ['301','302'] and res.has_key('location'):
                    url = self.getFullUrl(scheme, domain, res['location'])
                    return self.parseUrl(url)

                match = re.findall(r"<(\s*)meta(\s+)http-equiv=(\s*)(\"|')(\s*)refresh(\s*)(\4)(\s+)content=(\s*)(\"|')([\.0-9\s]+);(\s*)url=(\s*)(\"|')?(.+?)(\"|')?(\s*)(\"|')(\s*)[/]*>",content,re.I)
                if match and len(match) > 0:
                    url = self.getFullUrl(scheme, domain, match[0][-5].replace(" ", ""))
                    
                    return self.parseUrl(url)
                #end if
                
                if res.has_key('content-location'):
                    url = self.getFullUrl(scheme, domain, res['content-location'])
                    
                    return self.parseUrl(url)
                
                return self.parseUrl(url)
            
        except Exception,e:
            raise SyntaxError('url can not open')

    def checkOtherDomain(self, url):
        try:
            if self.policy != 5:
                return
            parse = urlparse.urlparse(url)
            scheme = parse[0].lower()
            if scheme != 'http' and scheme != 'https':
                return
            domain = parse[1].lower()
            if domain.find("]:") > 0 or domain.find(":") > 0:
                if domain.find("]:") > 0:
                    port = domain.split("]:")[1]
                else:
                    port = domain.split(":")[1]
                if port == "80":
                    scheme = "http"
                    if domain.find("]:") > 0:
                        domain = domain.split("]:")[0]+"]"
                    else:
                        domain = domain.split(":")[0]
                elif port == "443":
                    scheme = "https"
                    if domain.find("]:") > 0:
                        domain = domain.split("]:")[0]+"]"
                    else:
                        domain = domain.split(":")[0]

            url = "%s://%s" % (scheme, domain)
            if url in self.otherDomainList:
                return
            else:
                self.otherDomainList.append(url)

            ip = ""
            if domain == self.domain or len(domain.split('.')) < 3:
                return
            if checkIpv4Inner(domain) or checkIpv6Inner(domain):
                return
            else:
                ip = domainToip(domain)
            if self.ip != ip:
                return

            scheme, domain, path = self.getRedirect("%s://%s/" % (scheme, domain))
            if scheme != 'http' and scheme != 'https':
                scheme = 'http'
            if len(domain.split('.')) < 3:
                return

            if self.dao.getDataCount('sites', {'task_id':self.taskId, 'asset_task_id':self.assetTaskId,'domain':domain,'scheme':scheme}) > 0:
                return
            #end if

            siteDb = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'scheme':scheme,'domain':domain,'ip':self.ip,'policy':self.policy,'progress':''}
            siteId = self.dao.insertData('sites', siteDb)
            if siteId and siteId > 0:
                siteQueue.put(str(siteId))
            #end if
        except Exception, e:
            logger.exception(e)
        #end try
    #end def

    def checkPolicy(self, url):
        try:
            if checkIpv4Inner(url) or checkIpv6Inner(url):
                return
            #end if
            parse = urlparse.urlparse(url)
            if self.policy == 2 or self.policy == 5:
                #完整扫描，获取二级域名
                scheme = parse[0]
                top_domain = getTopDomain(parse[1])
                temp = parse[1].split(':')[0]
                if top_domain == self.topDomain and temp != self.domain.split(':')[0]:
                    #发现二级域名
                    domain = parse[1]
                    if domain.find(":") > 0:
                        port = domain.split(":")[1]
                        if port == "80":
                            scheme = 'http'
                            domain = domain.split(":")[0]
                        elif port == '443':
                            scheme = 'https'
                            domain = domain.split(":")[0]
                        #end if
                    #end if

                    scheme, domain, path = self.getRedirect("%s://%s/" % (scheme,domain))
                    if scheme != 'http' and scheme != 'https':
                        scheme = 'http'
                    #end if
                    if len(domain.split('.')) < 3:
                        return
                    #end if


                    if self.dao.getDataCount('sites',{'task_id':self.taskId,'asset_task_id':self.assetTaskId,'scheme':scheme,'domain':domain}) > 0:
                        return
                    #end if

                    ip = domainToip(domain)
                    if not ip or ip == '' or (not checkIpv4(ip) and not checkIpv6(ip)):
                        return
                    #end if

                    siteDb = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'scheme':scheme,'domain':domain,'path':path,'ip':ip,'policy':55,'progress':''}
                    siteId = self.dao.insertData('sites',siteDb)
                    if siteId < 1:
                        return
                    #end if
                    siteQueue.put(siteId)

                    if self.dao.getDataCount('host_infos', {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip}) < 1:
                        currentTime = time.strftime("%Y-%m-%d %X",time.localtime())
                        hostInfo = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'state':1,'start_time':currentTime}
                        self.dao.insertData('host_infos', hostInfo)

                        taskDb = {'host_scan_state':0,'weak_pwd_scan_state':0,'port_state':0}
                        self.dao.updateData('task', taskDb, {'id':self.taskId})
        except Exception,e:
            logger.exception(e)

    def checklogout(self, url, urlContent = ""):
        try:
            list1 = ['logout','exit','tuichu','quit','abort','withdraw']
            list2 = []
            temp = u"注销"
            list2.append(temp.encode('utf8'))
            list2.append(temp.encode('gb2312'))
            temp = u"退出"
            list2.append(temp.encode('utf8'))
            list2.append(temp.encode('gb2312'))

            parse = urlparse.urlparse(url)
            path = parse[2]

            for row in list1:
                if path.find("%s." % (row)) >= 0:
                    return True

            urlContent = urlContent.replace(" ","")
            if urlContent == "":
                return False
            for row in list2:
                if urlContent.find(row) == 0:
                    return True

            return False
        except Exception,e:
            logger.exception(e)
            return False

    def getIpByHost(self, domain):
        try:
            a = domain.find('[')
            b = domain.find(']')
            if a >= 0 and b >= 0:
                return domain[a+1:b]
            #end if
            ip = socket.gethostbyname(domain)
            return ip
        except Exception, e:
            logger.exception(e)
            return ''
        #end try
    #end def

    def updateUrlList(self, url, method='get', params='', refer=''):
        try:
            if url == '':
                return

            if self.dao.getSpiderUrlCount(self.siteId, url, params, method) > 0:
                return

            url = url.decode('gb2312','replace').encode('utf-8')
            refer = refer.decode('gb2312','replace').encode('utf-8')
            params = params.decode('utf8','replace').encode('utf8')

            #添加路径模式及参数模式两个字段，是为了避免将参数值不同的多个数据写入数据库
            patternPost = ''
            patternQuery = ''
            patternPath = self.patternPath(urlparse.urlparse(url)[2])
            if method == 'get' and params:
                patternQuery = self.patternQuery(params)
            elif method == 'post':
                if urlparse.urlparse(url)[4]:
                    patternQuery = self.patternQuery(urlparse.urlparse(url)[4])
                patternPost = self.patternPost(jsonRaw.loads(params))
            else:
                pass

            #过滤相同的URL, 相同模式的URL最多允许有20条
            if method == 'get':
                if self.dao.countSpiderUrlForGet(self.siteId, url, patternQuery) > 20:
                    return 
            elif method == 'post':
                if self.dao.countSpiderUrlForPost(self.siteId, url, patternPost) > 20:
                    return 
            else:
                pass

            urlInfo = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'site_id':self.siteId,'url':url,'method':method,'params':params,'refer':refer, 'pattern_path':patternPath, 'pattern_query':patternQuery, 'pattern_post':patternPost}
            self.dao.insertData('spider_url', urlInfo)
        except Exception, e:
            logger.exception(e)

    def updateUrlOtherList(self, url, method='get', params='', refer='', type=0):
        try:
            if url == '':
                return

            if self.dao.getSpiderUrlOtherCount(self.siteId, url, params, method) > 0:
                return

            url = url.decode('gb2312','replace').encode('utf-8')
            refer = refer.decode('gb2312','replace').encode('utf-8')
            params = params.decode('utf8','replace').encode('utf8')
            urlInfo = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'site_id':self.siteId,'url':url,'method':method,'params':params,'refer':refer, 'type':type}
            self.dao.insertData('spider_url_other', urlInfo)
        except Exception, e:
            logger.exception(e)

    def changeCode(self, msg):
        if self.code == 'utf8' or self.code == 'utf-8':
            return msg
        elif self.code == 'gbk':
            try:
                return msg.decode('gbk').encode('utf8')
            except Exception,e:
                logger.exception(e)
                return msg

        elif self.code == 'gb2312':
            try:
                return msg.decode('gb2312').encode('utf8')
            except Exception,e:
                logger.exception(e)
                return msg
            #end try
        else:
            try:
                return msg.decode(self.code).encode('utf8')
            except Exception,e:
                pass
            #end try
            try:
                return msg.decode('utf8').encode('utf8')
            except Exception,e:
                pass
            #end try
            try:
                return msg.decode('gb2312').encode('utf8')
            except Exception,e:
                pass
            #end try
            try:
                return msg.decode('gbk').encode('utf8')
            except Exception,e:
                pass
            #end try
            try:
                return msg.encode('utf8')
            except Exception,e:
                pass
            #end try
            return msg
        #end if
    #end def

    def getBasePath(self,url):
        try:
            path = ''
            parse = urlparse.urlparse(url)
            if parse[2] == "":
                path = '/'
            elif parse[2][-1] == "/":
                path = parse[2]
            elif parse[2].find('.') > 0 or parse[2].find('?') > 0:
                t = parse[2].split('/')
                if len(t) <= 2:
                    path = '/'
                else:
                    path = "%s/" % ("/".join(t[0:-1]))
                #end if
            else:
                path = "%s/" % (parse[2])
            #end if
            if path == "":
                path = "/"
            #end if

            return path
        except Exception,e:
            logger.exception(e)
            return '/'
        #end try
    #end def

    def getBaseUrl(self,url):
        try:
            if url.lower().find('http://') < 0 and url.lower().find('https://') < 0:
                if url == '':
                    url = '%s://%s/' % (self.scheme, self.domain)
                elif url[0] == '/':
                    url = '%s://%s%s' % (self.scheme, self.domain, url)
                else:
                    url = '%s://%s/%s' % (self.scheme, self.domain, url)
                #end if
            #end if
            res, content = self.requestUrl(url)
            if res.has_key('content-location'):
                url = res['content-location']
            #end if

            return url
        except Exception,e:
            logger.exception(e)
            return "%s://%s/" % (self.scheme, self.domain)
        #end try
    #end def

    def getBase(self):
        try:
            # res, content = self.requestUrl(self.scheme + "://" + self.domain + "/")
            res, content = self.requestUrl(self.scheme + "://" + self.domain + self.path)
            match = re.findall(r"<(\s*)meta(\s+)http-equiv=(\s*)(\"|')(\s*)refresh(\s*)(\4)(\s+)content=(\s*)(\"|')([\.0-9\s]+);(\s*)url=(.+?)(\10)(\s*)[/]*>",content,re.I)
            if match and len(match) > 0:
                self.url = self.getBaseUrl(match[0][-3].replace(" ",""))
                return
            #end if
            #method 1 end

            #action 2 start
            if res.has_key('status') and (res['status'] == '302' or res['status'] == '301'):
                if res.has_key('location'):
                    self.url = self.getBaseUrl(res['location'])
                    return
                #end if
            #end if
            #action 2 end

            if res.has_key('content-location'):
                self.url = res['content-location']
            else:
                self.url = self.scheme + "://" + self.domain + "/"
            #end if

        except Exception,e:
            logger.exception(e)
        #end try
    #end def

    def loadInitUrl(self):
        try:
            self.addUrl(self.url,"%s://%s/" % (self.scheme,self.domain))
            self.urlQueue.put(self.url)

            if self.path != '':
                self.addUrl(self.path,self.url)
                self.urlQueue.put(self.path)
            #end if

            for row in self.includeUrl:
                self.addUrl(row, self.url)
                self.urlQueue.put(row)
            #end for

            lines = []
            dicPath = os.path.dirname(__file__) + "/dict/path"
            f = file(dicPath, "r+")
            temp = f.readlines()
            f.close()
            for line in temp:
                if self.path[-1:] == '/':
                    url = "%s://%s%s%s" % (self.scheme, self.domain, self.path, line[1:])
                else:
                    url = "%s://%s%s%s" % (self.scheme, self.domain, self.path, line[0:])
                url = url.replace("\n","").replace("\r","")
                lines.append(url)
            #end for

            timeoutCount = 0
            result = []
            for line in lines:
                res, content = self.http.request(line) 
                if content == self.timeoutContent:
                    timeoutCount = timeoutCount + 1
                if timeoutCount > 10:
                    break
                if res['status'] == '200' or res['status'] == '403' or res['status'] == '401':
                    content = content.lower()
                    if content.find('转到父目录')>=0 or content.find('返回上一级目录')>=0 or  content.find('directory listing for')>=0 or content.find('directory listing denied') >= 0 or content.find('index of') >= 0 or content.find('href') >= 0 or content.find('action') >= 0:
                        result.append(line)
                        if len(result) > 4:
                            return

            for line in result:
                self.addUrl(line, '')

            #create getswf tmp dir
            path = self.downloadDir + str(self.taskId)
            if not os.path.exists(path):
                os.mkdir(path)

        except Exception,e:
            logger.exception(e)
        except socket.timeout, e1:
            res['status'] = '404'
            res['content-location'] = tmp_url

    def getRobots(self):
        try:
            base = "%s://%s/" % (self.scheme, self.domain)
            robotsUrl = base + "robots.txt"
            res,content = self.requestUrl(robotsUrl)
            rows=[]
            if content.find('allow') > -1:
                lines = content.splitlines()
                allow_compile = re.compile(r"allow(\s*):(\s*)(.+)",re.I)
                for line in lines:
                    match=allow_compile.search(line.rstrip())
                    if match:
                        row=match.group(3).split('*')[0]
                        if row != '':
                            rows.append(row)
                        #end if
                    #end if
                #end for
            #end if
            for row in rows:
                url=self.changeUrl(base, row)
                res , content = self.requestUrl(url)
                if res['status'] == '200' or res['status'] == '403' or res['status'] == '401':
                    self.addUrl(url,robotsUrl)
                    url_tuple = urlparse.urlparse(url)
                    row_list = url_tuple[2].split('/')
                    for i in range(10):
                        if len(row_list) > 2:
                            row_list = row_list[0:-1]
                            self.addUrl("%s://%s%s/" % (url_tuple[0],url_tuple[1],'/'.join(row_list)),robotsUrl)
                        else:
                            break
                        #end if
                    #end for
                #end if
            #end for
        except Exception,e:
            logger.exception(e)
        #end try
    #end def 

    def getSitemap(self):
        class LocsHandler(sax.ContentHandler):
            def __init__(self):
                self.isLoc = 0
                self.__locs = []
            #end def

            @property
            def urls(self):
                return self.__locs

            def startElement(self, name, attributes):
                if name == 'loc':
                    self.url = ""
                    self.isLoc = 1

            def characters(self, data):
                if self.isLoc:
                    self.url += data

            def endElement(self, name):
                if name == "loc":
                    self.isLoc = 0
                    self.__locs.append( self.url )

        try:
            #修正因sitemap取不到导致的异常问题
            sitemap="%s://%s/%s" % (self.scheme, self.domain, 'sitemap.xml')
            http = HttpRequest({'timeout':60,'follow_redirects':False,'cookie':self.cookie})
            res, content = http.request(sitemap)
            if res and res.has_key('status') and res['status'] == '200':
                parser = sax.make_parser()
                handler = LocsHandler()
                parser.setContentHandler(handler)
                parser.parse(sitemap)
                for url in handler.urls:
                    self.addUrl(url.encode('utf8'),sitemap )
            else:
                logger.debug("sitemap.xml no exists：" + sitemap)
        except sax.SAXException, e:
            logger.exception(e)
            pass
        except Exception,e:
            logger.exception(e)

    def getCode(self):
        try:
            res, content = self.requestUrl(self.url)
            match = re.findall(r"<meta(.+?)charset(.*?)=(.+?)\"",content,re.I)
            if match and len(match) > 0:
                row = match[0][2]
                row = row.replace(" ","")
                row = row.lower()
                self.code = row
            #end if

            self.updateSiteTitle(content)

        except Exception,e:
            logger.exception(e)
        #end try
    #end def

    def updateSiteTitle(self,content):
        try:
            match = re.findall(r"<(\s*)title(\s*)>(.*?)<(\s*)/(\s*)title(\s*)>",content,re.I|re.DOTALL)
            if match and len(match) > 0:
                self.title = match[0][2].replace("\r","").replace("\n","")
            #end if
            if self.title == '':
                return
            #end if
            self.title = self.changeCode(self.title)
            if self.title == '':
                return
            #end if

            self.dao.updateData('sites', {'title':self.title}, {'id':self.siteId})

        except Exception,e:
            logger.exception(e)
        #end try
    #end def

    def indexForbidden(self):
        try:
            base = "%s://%s/" % (self.scheme, self.domain)
            res ,content = self.http.request(base)
            if res.has_key('status') and res['status'] == '403':
                index_urls=['index.html','index.php','index.asp','index.aspx','index.jsp']
                for index in index_urls:
                    url="%s%s" %(base,index)
                    r ,c = self.requestUrl(url)
                    if r.has_key('status') and r['status'] == '200':
                        self.addUrl(url, base)
                    #end if
                #end for
            #end if
        except Exception,e:
            logger.exception(e)
        #end try
    #end def


    def urlfromDevice(self):
        try:
            refer = "addurl2"
            urllist = []
            if urllist and len(urllist) > 0:
                for url in urllist:
                    if url.find("%2E") >= 0 or url.find("%2e") >= 0 or url.find("%5C") >= 0 or url.find("%5c") >= 0:
                        url = urllib2.unquote(url)
                    #end if
                    if url.find("/./") >= 0 or url.find("'") >= 0 or url.find("\"") >= 0 or url.find("\\") >= 0 or url.find("..") >= 0 or url.find("--") >= 0:
                        continue
                    #end if
                    url_tuple = urlparse.urlparse(url)
                    row_list = url_tuple[2].split('/')
                    for i in range(10):
                        if len(row_list) > 2:
                            row_list = row_list[0:-1]
                            self.addUrl2("%s://%s%s/" % (url_tuple[0],url_tuple[1],'/'.join(row_list)), refer)
                        else:
                            break
                        #end if
                    #end for
                    
                    self.addUrl2(url, refer)
                #end for
            #end if
            
        except Exception,e:
            logger.exception(e)
        #end try
    #end def

    def init(self):
        try:
            self.getBase()
            self.getCode()
            self.indexForbidden()
            self.loadInitUrl()
            self.getRobots()
            self.getSitemap()
            self.urlfromDevice()

        except Exception,e:
            logger.exception(e)
        #end try
    #end def

    def checkTimeOut(self):
        if self.timeoutCount > self.maxTimeoutCount:
            return False
        #end if
        if self.endTime < time.time():
            return False
        #end if

        return True
    #end def

    def start(self):
        try:
            i = 0
            while True:
                i += 1
                logger.debug("urlQueue qsize: " + str(self.urlQueue.qsize()))
                if self.urlQueue.empty():
                    logger.debug("Spider is end")
                    break
                #end if

                if self.checkTimeOut() == False:
                    break
                #end if

                url = self.urlQueue.get(True, 5)

                if url == None or url == '':
                    continue
                #end if
                if url == -1:
                    break
                #end if

                if self.num >= self.maxnum:
                    logger.debug("Spider is end")
                    break
                #end if

                url = url.strip()

                if self.ifScan(url) == False:
                    continue
                #end if

                urllist = self.getList(url)
                for row in urllist:
                    self.checkOtherDomain(row)
                    self.checkPolicy(row)
                    self.addUrl(row, url)
                #end for
            #end while
            self.clearSwf()
        except Exception, e:
            logger.exception(e)
            return -1
        #end try
    #end def

    def startTester(self, url):
        try:
            self.getBase()
            self.getCode()
            url = url.strip()
            
            urllist = self.getList(url)
            logger.debug(url)
            logger.debug("\n".join(urllist))
            #for row in urllist:
            #    self.checkOtherDomain(row)
            #    self.checkPolicy(row)
            #    self.addUrl(row, url)
        except Exception, e:
            logger.exception(e)
            return -1

    def ifScan(self, url):
        try:
            parse = urlparse.urlparse(url)
            path = parse[2].lower()
            if self.nomatchTypeList and len(self.nomatchTypeList) > 0:
                for row in self.nomatchTypeList:
                    if path.find(row) > 0:
                        return False
                    #end if
                #end for
            #end if

            return True
        except Exception, e:
            logger.exception(e)
            return False
        #end try
    #end def

    def pathPattern(self, path):
        pattern = ""
        #1:[alpha],2:[int]
        flag = 0
        for i in range(len(path)):
            num = ord(path[i])
            if (num >= 65 and num <= 90) or (num >= 97 and num <= 122):
                if flag == 0:
                    flag = 1
                elif flag == 1:
                    flag = 1
                elif flag == 2:
                    pattern = "%s[int]" % (pattern)
                    flag = 1
                #end if
            elif num >= 48 and num <= 57:
                if flag == 0:
                    flag = 2
                elif flag == 1:
                    pattern = "%s[alpha]" % (pattern)
                    flag = 2
                elif flag == 2:
                    flag = 2
                #end if
            else:
                if flag == 0:
                    pattern = "%s%s" % (pattern, path[i])
                elif flag == 1:
                    pattern = "%s[alpha]%s" % (pattern, path[i])
                    flag = 0
                elif flag == 2:
                    pattern = "%s[int]%s" % (pattern, path[i])
                    flag = 0
                #end if
            #end if
            if i == len(path) - 1 and flag != 0:
                if flag == 1:
                    pattern = "%s[alpha]" % (pattern)
                elif flag == 2:
                    pattern = "%s[int]" % (pattern)

        if pattern.find('.') > 0:
            pattern = "%s.%s" % (pattern.split('.')[0], path.split('.')[1])
        return pattern

    def patternPost(self, parameters):
        '''post请求参数模式'''
        try:
            paramsList = []
            for row in parameters:
                if row['name'] != 'submit':
                    paramsList.append(row['name'])
            paramsList.sort()
            paramsList = list(set(paramsList))
            params = []
            needhandleNum = False
            for k in paramsList:
                params.append("%s=%s" %(k,'v'))
            return '&'.join(params)
        except Exception, e:
            logger.exception(e)

    def patternQuery(self, parameters):
        try:
            paramsList = map(lambda s: s.split('=', 1) if len(s.split('='))>1 else [s[:s.find('=')],''] if s.find('=') != -1  else [s,''],parameters.split('&'))
            paramsList.sort()
            params = []
            needhandleNum = False
            for k,v in paramsList:
                params.append("%s=%s" %(k,'v'))
            return '&'.join(params)
        except Exception, e:
            logger.exception(e)

    def patternPath(self, path):
        '''获取路径的模式，以备后续处理'''
        pattern = ""
        #1a[alpha],2i[int]
        flag = ''
        #整个路径的深度
        depth = len(path.split('/'))

        if path.split('/')[-1:][0].find('.'):
            isFile = 1
            currentPath = "/".join(path.split('/')[:-1])
            filename = path.split('/')[-1:][0]
        else:
            isFile = 0
            currentPath = path

        current=0
        patternStr = str(depth) + '-'
        for i in range(len(currentPath)):
            num = ord(currentPath[i])
            if (num >= 65 and num <= 90) or (num >= 97 and num <= 122):   #A-Z a-z
                if flag == '':
                    flag = 'a'
                    current += 1
                elif flag == 'a':
                    current += 1
                elif flag == 'i':
                    flag = 'a'
                    patternStr = patternStr + str(current) + "i"
                    current = 1
            elif num >= 48 and num <= 57:   #0-9 
                if flag == '':
                    flag = 'i'
                    current += 1
                elif flag == 'i':
                    current += 1
                elif flag == 'a':
                    flag = 'i'
                    patternStr = patternStr + str(current) + "a"
                    current = 1
            else:
                if flag == '':
                    flag = ''
                    patternStr = patternStr + currentPath[i]
                elif flag == 'i':
                    flag = ''
                    patternStr = patternStr + str(current) + "i" + currentPath[i]
                elif flag == 'a':
                    flag = ''
                    patternStr = patternStr + str(current) + "a" + currentPath[i]
                current = 0
            if i == len(currentPath) - 1:
                if flag == 'i':
                    patternStr = patternStr + str(current) + "i"
                elif flag == 'a':
                    patternStr = patternStr + str(current) + "a"
        if isFile:
            patternStr = patternStr + "/" + filename
        return patternStr

    def checkHtmlPattern(self, url):
        try:
            parse = urlparse.urlparse(url)
            url = parse[2]
            if len(url.split('/')) <= len(self.path.split('/')):
                return True

            pattern = self.pathPattern(url)
            if pattern in self.htmlPattern:
                if pattern.find('.html') > 0 or pattern.find('.htm') > 0 or pattern.find('.xhtml') > 0 or pattern.find('.shtml') > 0:
                    filename = pattern.split('/')[-1].split('.')[0]
                    if filename.find('[alpha]') < 0 or filename.find('-[int]') > 0 or filename.find('_[int]') > 0:
                        return False
                elif pattern[-1] == '/':
                    if pattern.split('/')[-2].find('[alpha]') < 0:
                        return False
            else:
                self.htmlPattern.append(pattern)

            return True
        except Exception, e:
            logger.exception(e)
            return True

    def addNewDomain(self, url):
        try:
            if checkIpv4Inner(url) or checkIpv6Inner(url):
                return
            #end if
            parse = urlparse.urlparse(url)
            scheme = parse[0]
            domain = parse[1]

            if domain.find(':') > 0:
                port = domain.split(':')[1]
                if port == '80':
                    scheme = 'http'
                    domain = domain.split(':')[0]
                elif port == '443':
                    scheme = 'https'
                    domain = domain.split(':')[0]
                #end if
            #end if

            print "%s://%s/" % (scheme, domain)
            scheme, domain, path = self.getRedirect("%s://%s/" % (scheme, domain))
            if scheme != 'http' and scheme != 'https':
                scheme = 'http'
            #end if
            if len(domain.split('.')) < 3:
                return
            #end if

            if domain.find(':') > 0:
                if self.dao.getDataCount('sites', {'task_id':self.taskId,'assetTaskId':self.assetTaskId,'domain':domain,'scheme':scheme}) > 0:
                    return
                #end if
                if self.dao.getDataCount('sites', {'task_id':self.taskId,'assetTaskId':self.assetTaskId,'domain':"%s:%s" % (self.ip,domain.split(':')[1]),'scheme':scheme}) > 0:
                    return
                #end if
            else:
                if self.dao.getDataCount('sites', {'task_id':self.taskId,'assetTaskId':self.assetTaskId,'domain':domain,'scheme':scheme}) > 0:
                    return
                #end if
                if self.dao.getDataCount('sites', {'task_id':self.taskId,'assetTaskId':self.assetTaskId,'domain':self.ip,'scheme':scheme}) > 0:
                    return
                #end if
            #end if

            siteDb = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'domain':domain,'scheme':scheme,'ip':self.ip,'path':path,'policy':1,'progress':''}
            siteId = self.dao.insertData('sites', siteDb)
            siteQueue.put(str(siteId))

        except Exception, e:
            logger.exception(e)
        #end try
    #end def

    _filtercompile = re.compile(r"[(\"\'\\)]")
    def urlFilter(self, url):
        return self._filtercompile.search(url)
    #end def

    def parameterPattern(self, parameters):
        try:
            paramsList = map(lambda s: s.split('=',1) if len(s.split('='))>1 else [s[:s.find('=')],''] if s.find('=') != -1  else [s,''],parameters.split('&'))
            paramsList.sort()
            params = []
            needhandleNum = False
            for k,v in paramsList:
                try:
                    int(v)
                    params.append("%s=%s" %(k,'[int]'))
                    needhandleNum = True
                except ValueError:
                    params.append("%s=%s" %(k,v))
                #end try
            #end for  
            return needhandleNum,'&'.join(params)
        except Exception, e:
            logger.exception(e)
        #end try
    #end def

    def patternExist(self, parse):
        try:
            pathExist = False
            paramsExist = False
            patterns = {'path':None,'params':None}
            path = parse[2]
            parameters = parse[4]

            parametersPattern = self.parameterPattern(parameters)
            if parametersPattern:
                needhandleNum,pattern = parametersPattern
                patterns['params'] = (path,needhandleNum,pattern)           
                paramsExist = self.patternDict.has_key(path) and self.patternDict[path].has_key(pattern)

            pathPattern = self.pathPattern(path)
            patterns['path'] = pathPattern
            if pathPattern in self.htmlPattern:
                if pathPattern.find('.html') > 0 or pathPattern.find('.htm') > 0 or pathPattern.find('.xhtml') > 0 or pathPattern.find('.shtml') > 0:
                    filename = pathPattern.split('/')[-1].split('.')[0]
                    if filename.find('[alpha]') < 0 or filename.find('-[int]') > 0 or filename.find('_[int]') > 0:
                        pathExist = True
                    #end if
                elif pathPattern[-1] == '/':
                    if pathPattern.split('/')[-2].find('[alpha]') < 0:
                        pathExist = True
                    #end if
                #end if
            #end if
            return pathExist or paramsExist, patterns
        except Exception,e:
            logger.exception(e)
            return True, ''
        #end try
    #end def

    def updatePattern(self, patterns):
        try:
            if patterns['path']:
                pattern = patterns['path']
                if pattern not in self.htmlPattern:
                    self.htmlPattern.append(pattern)
                #end if
            #end if

            if not patterns['params']:
                return
            #end if
            path, needhandleNum, pattern = patterns['params']
            if needhandleNum:
                if self.patternDict.has_key(path):
                    if self.patternDict[path].has_key(pattern):
                        self.patternDict[path][pattern] += 1
                        if self.patternDict[path][pattern] > self.sameUrlPatternCount:
                            return
                        else:
                            self.patternDict[path][pattern] = 1
                    else:
                        self.patternDict[path][pattern] = 1
                    #end if
                else:
                    self.patternDict[path] = {pattern:1}
                #end if
            #end if
        except Exception,e:
            logger.exception(e)
        #end try
    #end def

    def checkSpecialPatternExist(self, path, parameters):
        try:
            if parameters.find('=') == -1:
                if not hasattr(self, "noequalPattern"):
                    self.noequalPattern = set()
                #end if
                flag = 0
                pattern = []
                for s in parameters:
                    if s.isdigit():
                        if flag != 1: pattern.append('d')
                        flag = 1
                    elif s.isalpha():
                        if flag != 2: pattern.append('w')
                        flag = 2
                    else:
                        pattern.append(s)
                        flag = 3
                    #end if
                #end for
                pattern = "%s#%s" % (path, ''.join(pattern))
                key = hashlib.md5(pattern).hexdigest()
                if key not in self.noequalPattern:
                    self.noequalPattern.add(key)
                    return False
                else:
                    return True
                #end if
            #end if
        except Exception,e:
            logger.exception(e)
            return False
        #end try
    #end def

    def checkExcludeItemUrl(self, mod_url, url):
        try:
            if mod_url.find("?") > 0:
                r1 = re.compile(mod_url.split("?")[0].replace("*","(.*?)"))
                res = re.findall(r1, url.split("?")[0])
                if res and len(res) > 0:
                    mod_params = mod_url.split("?")[1]
                    if mod_url == "*" and url.find("?") < 0:
                        return True
                    #end if
                    if url.find("?") > 0:
                        params = url.split("?")[1]
                        mod_params_list = mod_params.split("&")
                        for row in mod_params_list:
                            r2 = re.compile(row.replace("*","(.*?)"))
                            res = re.findall(r2, params)
                            if res and len(res) > 0:
                                pass
                            else:
                                return False
                            #end if
                        #end for
                        return True
                    #end if
                #end if
            else:
                r1 = re.compile(mod_url.replace("*","(.*?)"))
                res = re.findall(r1, url.split("?")[0])
                if res and len(res) > 0:
                    return True
                #end if
            #end if
            
            return False
        except Exception, e:
            logger.exception(e)
            return False
        #end try
    #end def

    def checkExcludeUrl(self, excludeUrl, url):
        try:
            for row in excludeUrl:
                if row.find("http://") < 0 and row.find("https://") < 0:
                    continue
                #end if
                if self.checkExcludeItemUrl(row, url):
                    return True
                #end if
            #end for
            
            return False
        except Exception,e:
            logger.exception(e)
            return False
        #end try
    #end def

    def addUrl2(self, url, refer):
        try:
            if self.checkExcludeUrl(self.excludeUrl, url):
                return False
            #end if
            
            if self.ifScan(url) == False:
                return False
            #end if

            if url in self.result:
                return False
            #end if

            parse = urlparse.urlparse(url)

            if parse[0] != 'http' and parse[0] != 'https':
                return False

            #end if

            if parse[1].find(self.domain) < 0:
                return False
            #end if
            
            path = parse[2]
            if path.find(".\\") >= 0 or path.find("\\.") >= 0 or path.find("/./") == 0 or path.find("\\") >= 0 or parse[4].find("'") >= 0 or parse[4].find("..") >= 0 or parse[4].find("--") >= 0:
                return False
            #end if
            path = path.replace("/////","/").replace("////","/").replace("///","/").replace("//","/")
            if len(path) == 1 and path == "/":
                path = ""
            elif len(path) > 1 and path[0] == "/":
                path = path[1:]
            #end if
            if url.find("?") >= 0:
                url = "%s://%s/%s?%s" % (parse[0], parse[1], path, parse[4])
            else:
                url = "%s://%s/%s" % (parse[0], parse[1], path)
            #if
            parse = urlparse.urlparse(url)

            if parse[1] != self.domain:
                if checkIpv6Inner(parse[1]) and checkIpv6Inner(self.domain):
                    a = parse[1].find(']')
                    b = self.domain.find(']')
                    if parse[1][:a+1] == self.domain[:b+1]:
                        self.addNewDomain(url)
                    #end if
                    return False
                #end if
                
                if parse[1].lower().split(':')[0] == self.domain.split(':')[0]:
                    self.addNewDomain(url)
                #end if
                return False       
            #end if

            isJs = refer.find(".js") != -1
            if isJs and self.urlFilter(url):
                return False
            #end if
            
            flag, patterns = self.patternExist(parse)
            if flag:
                return False
            #end if
            res = validUrls(parse[1], [url], [200,403])
            if res and len(res) > 0:
                self.updatePattern(patterns)
            else:
                return False
            #end if
            
            self.num += 1
            if url.find('%25') or url.find('%20'):
                url = urllib2.unquote(url)
            #end if
            self.result.append(url)
            self.urlQueue.put(url)
                    
            if self.policy == 3 and self.path != '':
                if not parse[2].startswith(self.path):
                    return False
                #end if
            #end if
                            
            temp = self.changeCode(url)
            if temp.find('?') > 0:
                self.updateUrlList(temp.split('?')[0], 'get', temp.split('?')[1], refer)
            else:
                self.updateUrlList(temp, 'get', '', refer)
            #end if

            return True
        except Exception, e:
            logger.exception(e)
            return False
        #end try
    #end def

    def addUrl(self, url, refer):
        try:
            if self.checkExcludeUrl(self.excludeUrl, url):
                return False
            #end if
            
            if self.ifScan(url) == False:
                return False
            #end if

            if url in self.result:
                return False
            #end if

            parse = urlparse.urlparse(url)

            if  parse[0] != 'http' and parse[0] != 'https':
                return False
            #end if

            if parse[1].find(self.domain) < 0:
                return False
            #end if

            if parse[1].split(':')[0] != self.domain:
                #外链
                if getTopDomain(parse[1].split(':')[0]) == self.topDomain:
                    self.updateUrlOtherList(url, method='get', params='', refer='', type=1)

                if checkIpv6Inner(parse[1]) and checkIpv6Inner(self.domain):
                    a = parse[1].find(']')
                    b = self.domain.find(']')
                    if parse[1][:a+1] == self.domain[:b+1]:
                        self.addNewDomain(url)
                    #end if
                    return False
                if parse[1].lower().split(':')[0] == self.domain.split(':')[0]:
                    self.addNewDomain(url)
                #end if
                return False
            #end if

            isJs = refer.find(".js") != -1
            if isJs and self.urlFilter(url):
                return False
            #end if

            if self.checkHtmlPattern(url) == False:
                return False
            #end if

            flag = True
            path = parse[2]
            parameters = parse[4]

            if self.checkSpecialPatternExist(path,parameters):
                return False
            #end if

            if self.patternDict.has_key(path):
                if parameters == '':
                    return False
                else:
                    result = self.parameterPattern(parameters)
                    if result:
                        needhandleNum, pattern = result
                        if needhandleNum:
                            if self.patternDict[path].has_key(pattern):
                                self.patternDict[path][pattern] += 1
                                if self.patternDict[path][pattern] > self.sameUrlPatternCount:
                                    flag = False
                                #end if
                            else:
                                self.patternDict[path][pattern] = 1
                            #end if
                        #end if
                    #end if
                #end if
            else:
                self.patternDict[path] = {}
                if parameters != '':
                    result = self.parameterPattern(parameters)
                    if result:
                        needhandleNum, pattern = result
                        if needhandleNum:
                            self.patternDict[path][pattern] = 1
                        #end if
                    #end if
                #end if
            #end if
            if flag:
                self.num += 1
                if url.find('%25') or url.find('%20'):
                    url = urllib2.unquote(url)
                #end if
                self.result.append(url)
                self.urlQueue.put(url)
                    
                if self.policy == 3 and self.path != '':
                    if not parse[2].startswith(self.path):
                        return False
                    #end if
                #end if
                            
                temp = self.changeCode(url)
                if temp.find('?') > 0:
                    self.updateUrlList(temp.split('?')[0], 'get', temp.split('?')[1], refer)
                else:
                    self.updateUrlList(temp, 'get', '', refer)
                #end if

                return True
            else:
                return False
            #end if
        except Exception, e:
            logger.exception(e)
            return False
        #end try
    #end def

    def requestUrl(self, url):
        try:
            res = {}
            content = ""
            isquoted = False 
            try:
                tmp_url = urllib2.unquote(url)
                parse = urlparse.urlparse(tmp_url)
                if parse[0] != 'http' and parse[0] != 'https':
                    return {'status':'404','content-location':tmp_url}, ""
                #end if

                if tmp_url.find('%') < 0:
                    tmp_url = urllib2.quote(tmp_url, '%:/?=#&;,')
                    isquoted = True
                #end if
                tmp_url = urllib2.unquote(tmp_url)    
                res, content = self.http.request(tmp_url)

                #返回404则为死链
                if res['status'] == '404':
                    self.updateUrlOtherList(url, method='get', params='', refer='', type=0)

            except socket.timeout, e1:
                res['status'] = '404'
                res['content-location'] = tmp_url
            #end try

            if res.has_key('content-location'):
                if res['content-location'] != tmp_url:
                    unquoteLocation=res['content-location']
                    if isquoted:
                        unquoteLocation = urllib2.unquote(res['content-location'])
                    #end if
                    self.addUrl(unquoteLocation, tmp_url)
                    res={'status':'302','content-location':unquoteLocation}
                    content=""
                #end if
            if self.hasSpace:
                try:
                    lines = []
                    for k in res:
                        lines.append(k+':'+res[k] + "\n")
                    #end for
                    lines.append(self.sep+"\n")
                    lines.append(content) 

                    filename = hashlib.sha1(tmp_url).hexdigest()
                    filename = "%s#%s#" % (filename, self.siteId)
                    f = file(self.downloadDir + filename, 'w+')
                    f.writelines(lines)
                    f.close()
                except IOError:
                    self.hasSpace = False
                #end try
            #end if
            return res,content
        except socket.error, e:
            #死链
            self.updateUrlOtherList(url, method='get', params='', refer='', type=0)
            logger.error("socket.error:" + e.message + "::::" + url)
            return {'status':'404','content-location':url}, ''
        except socket.timeout, e1:
            #死链
            self.updateUrlOtherList(url, method='get', params='', refer='', type=0)
            self.timeoutCount = self.timeoutCount + 1
            logger.error("socket.timeout::::" + url)
            return {'status':'404','content-location':url}, self.timeoutContent
        except httplib2.ServerNotFoundError, e2:
            #死链
            self.updateUrlOtherList(url, method='get', params='', refer='', type=0)
            logger.error("ServerNotFoundError:" + e2.message + "::::" + url)
            return {'status':'404','content-location':url}, ''
        except httplib.ResponseNotReady, e3:
            #死链
            self.updateUrlOtherList(url, method='get', params='', refer='', type=0)
            logger.error("ResponseNotReady:" + e3.message + "::::" + url)
            return {'status':'404','content-location':url}, ''
        except Exception, e4:
            #死链
            self.updateUrlOtherList(url, method='get', params='', refer='', type=0)
            logger.exception(e4)
            return {'status':'404','content-location':url}, ''

        '''
        except socket.timeout, e:
            self.timeoutCount = self.timeoutCount + 1
            return {'status':'404','content-location':url}, self.timeoutContent
        except Exception,e:
            logger.exception(e)
            return {'status':'404','content-location':url}, ''
        '''

    def ifUrlRight(self, url):
        try:
            if url == '#' or url.lower().find('javascript:') >= 0 or url.find('{#') >= 0:
                return False
            else:
                return True
            #end if
        except Exception, e:
            return False
        #end try
    #end if

    def changeUrl(self, source_url, url):
        try:
            if self.ifUrlRight(url) == False:
                return source_url
            #end if
            source_url = source_url.strip()
            source_url_tuple = urlparse.urlparse(source_url)
            source_url_domain = source_url_tuple[1]
            source_url_dir = source_url_tuple[2]
            if source_url_dir == '' or source_url_dir[0] != '/':
                source_url_dir = '/'
            #end if

            url = url.strip()
            url_tuple = urlparse.urlparse(url)
            if url_tuple[0] == '':
                path = ""
                if url_tuple[2] != '':
                    temp_list = source_url_dir.split('/')[0:-1]
                    temp = url_tuple[2]
                    if temp[0:3] == '../':
                        if len(temp_list) > 1:
                            temp_list = temp_list[0:-1]
                        #end if
                        temp = temp[3:]
                        for i in range(10):
                            if temp[0:3] == '../':
                                if len(temp_list) > 1:
                                    temp_list = temp_list[0:-1]
                                #end if
                                temp = temp[3:]
                            else:
                                break
                            #end if
                        #end for
                        temp_list.append(temp)
                    elif temp[0:2] == './':
                        temp_list.append(temp[2:])
                    elif temp[0] == '/':
                        temp_list = ['']
                        temp_list.append(temp[1:])
                    elif temp[0] == '?':
                        file = source_url_dir[-1]
                        if file.find('?') >= 0:
                            temp_list.append("%s%s" % (file.split('?')[0],url))
                        else:
                            temp_list.append("%s%s" % (file,url))
                        #end if
                    else:
                        temp_list.append(temp)
                    #end if
                    path = '/'.join(temp_list)
                else:
                    path = source_url_dir
                #end if
                if path.find('/../') > 0:
                    for x in xrange(10):
                        p = path.split('/../',1)
                        path = '/'.join(p[0].split('/')[:-1])+'/'+p[1]
                        if path.find('../') < 0:
                            break
                        #end if
                    #end for
                if path.find('./'):
                    path = path.replace('./','')
                #end if

                path = path[:-2] if path[-2:] == ".." else path

                path = path[:-1] if path[-1:] == "." else path
                
                path = path.replace("//",'/')

                temp_tuple = (self.scheme,source_url_domain,path,url_tuple[3],url_tuple[4],url_tuple[5])
                url = urlparse.urlunparse(temp_tuple)
            #end if
            return url
        except Exception, e:
            logger.exception(e)
            return url
        #end try
    #end def

    def specialDir(self, url):
        try:
            parse = urlparse.urlparse(url)
            if parse[2].find('thumb') > 0:
                return False
            #end if
        except Exception, e:
            logger.exception(e)
            return True
        #end try
    #end def

    def specialAction(self, url):
        try:
            parse = urlparse.urlparse(url)
            if parse[4] == "N=D" or parse[4] == "M=A" or parse[4] == "S=A" or parse[4] == "D=A" or re.search(r"C=[MNSD];O=[AD]",parse[4],re.I):
                return False
            else:
                return True
            #end if
        except Exception,e:
            logger.exception(e)
            return True

    def getUrlFromJs(self, url, content):
        try:

            list = []
            if content.find('url') >= 0:
                match = re.findall(r"[^_]url(\s*)=(\s*)(\"|')(.+?)\3",content,re.I)
                for row in match:
                    list.append({'url':row[3],'url_content':''})

            if content.find('.href') >= 0:
                match = re.findall(r"\.href(\s*)=(\s*)(\"|')(.+?)\3",content,re.I)
                for row in match:
                    list.append({'url':row[3],'url_content':''})

            if content.find('window.open') >= 0:
                match = re.findall(r"window\.open(\s*)\((\s*)('|\")(.+?)\3(,?)",content,re.I)
                for row in match:
                    list.append({'url':row[3],'url_content':''})

            if content.find('window.navigate') >= 0:
                match = re.findall(r"window\.navigate(\s*)\((\s*)('|\")(.+?)\3",content,re.I)
                for row in match:
                    list.append({'url':row[3],'url_content':''})

            if content.find('.location') >= 0:
                match = re.findall(r"\.location(\s*)=(\s*)('|\")(.+?)\3",content,re.I)
                for row in match:
                    list.append({'url':row[3],'url_content':''})

            if content.find('location.replace') >=0 or content.find('location.assign') >=0:
                match = re.findall(r"location\.(replace|assign)(\s*)\((\s*)('|\")(.+?)\4",content,re.I)
                for row in match:
                    list.append({'url':row[4],'url_content':''})

            return list
        except Exception, e:
            logger.exception(e)
            return []

    def getUrlByFullPath(self, url, content):
        try:
            list = []
            match = re.findall(r"('|\")(http|https)://(.+?)\1",content,re.I)
            for row in match:
                list.append({'url':"%s://%s" % (row[1],row[2]),'url_content':''})
            #end for
            return list
        except Exception,e:
            logger.exception(e)
            return []
        #end try
    #end def

    def getATag(self,url,content):
        try:
            list = []
            if content != '' and (content.find('href') > 0 or content.find('HREF') > 0):
                match = re.findall(r"(\s+)href(\s*)=(\s*)('|\")(.*?)\4(.*?)>(.*?)<",content,re.I|re.DOTALL)
                
                if len(match) > 0:
                    for row in match:
                        if row[4] != '':
                            t = {'url':row[4],'url_content':row[6]}
                            list.append(t)
                        #end if
                    #end for
                #end if
                match = re.findall(r"(\s+)href(\s*)=(\s*)([\d\w#].*?)(/>|>| )",content,re.I|re.DOTALL)
                if len(match) > 0:
                    for row in match:
                        t = {'url':row[3],'url_content':''}
                        list.append(t)
                    #end for
                #end if
                return list
            else:
                return []
            #end if
        except Exception, e:
            logger.exception(e)
            return []
        #end try
    #end def

    def getIframeSrc(self, url, content):
        try:
            list = []
            if content != '' and (content.find('src') >= 0 or content.find('SRC') >= 0):
                match = re.findall(r"src(\s*)=(\s*)('|\")(.*?)\3",content,re.I)
                for row in match:
                    if row[3] != '':
                        list.append({'url':row[3],'url_content':''})
                    #end if
                #end for
                match = re.findall(r"src(\s*)=(\s*)([\d\w#].*?)(/>|>| )",content,re.I)
                if len(match) > 0:
                    for row in match:
                        t = {'url':row[2],'url_content':''}
                        list.append(t)
                    #end for
                #end if
            #end if
            return list
        except Exception, e:
            logger.exception(e)
            return []
        #end try
    #end def

    def getSwf(self, url, content):
        #<embed src="subscribe.swf"
        try:
            urls = []
            if content != '' and content.find('.swf') >= 0:
                temp = []
                match = re.findall(r"embed(\s*)src(\s*)=(\s*)('|\")(.+?)\.swf\4",content,re.I)
                for row in match:
                    temp.append(self.changeUrl(url,row[4]+'.swf'))
                #end for
                _action = None
                _code = None
                for swf_url in temp:
                    if swf_url not in self.swfs:
                        self.swfs.append(swf_url)
                        filename = hashlib.sha1(swf_url).hexdigest()
                        filename = "%s#%s#" % (filename,self.siteId)
                        path = "%s%s/%s" % (self.downloadDir,self.taskId,filename)
                        popen(" wget -O %s %s " % (path,swf_url))
                        if os.path.exists(path):
                            isbig = os.stat(path).st_size > 512*1024
                            swf_content = ''.join(vulscan_popen("swfdump -a %s 2>&1" % path))
                            #./tmp/355/4b331afa9fa6c76fc49863c3acb949be6cb00a90#778# is not a valid SWF file or contains errors.
                            if swf_content.find('is not a valid SWF file'):
                                logger.debug(path + " is not a valid SWF file")
                                continue
                            #   (   16 bytes) action: GetUrl URL:"subscribe.aspx" Label:""  -> http://www.testfire.net/subscribe.swf
                            if _action is None:
                                _action = re.compile(r"URL(\s*):(\s*)('|\")(.+?)\3",re.I)
                            #end if
                            match = _action.findall(swf_content)
                            for row in match:
                                urls.append({'url':row[3],'url_content':''})
                            #end for
                            if isbig:
                               continue
                            swf_file = open(path)
                            swf_content = swf_file.read()
                            swf_file.close()
                            #x00/redir.php?r=http://www.eclectasy.com/Fractal-Explorer/index.html\x00 -> http://testphp.vulnweb.com/Flash/add.swf
                            if _code is None:
                                _code = re.compile(r"(.+)\x00((.+?)\.(php|asp|aspx|jsp|html|htm)(.*?))\x00",re.I)
                            #end if
                            for line in swf_content.splitlines():
                                match = _code.search(line)
                                if match:
                                    urls.append({'url':match.group(2),'url_content':''})
                                #end if
                            #end for
                        #end if
                    #end if
                #end for
            #end if
            return urls
        except Exception, e:
            logger.exception(e)
            return urls
        #end try
    #end def

    def clearSwf(self):
        try:
            # MCJ: if system is windows ,pass
            if 'Windows' in platform.system():
                pass
            else:
                popen("rm -rf %s%s/" % (self.downloadDir, self.taskId))
        except Exception,e:
            logger.exception(e)
        #end try
    #end def

    def dirEndswithSlash(self, url):
        try:
            if not url.endswith('/'):
                url = urllib2.quote(url, '%:/?=#&;,')
                res, content = self.http.request(url)
                if res.has_key('content-location') and res['content-location'].endswith('/'):
                    if res['content-location'][:-1] == url:
                        url = res['content-location']
                    #end if
                #end if
                return urllib2.unquote(url)
            else:
                return url
            #end if
        except Exception, e:
            logger.exception(e)
            return url
        #end try
    #end def

    def checkPostPattern(self, url, fields):
        try:
            params = [':'.join((p['name'],p['type'])) for p in fields]
            params.sort()
            pattern = '%s#%s' % (url, '&'.join(params))
            key = hashlib.md5(pattern).hexdigest()
            if key not in self.postPattern:
                self.postPattern.add(key)
                return False
            #end if
            return True
        except Exception, e:
            logger.exception(e)
            return False
        #end try
    #end def

    def getForm(self, url, content):
        try:
            url = self.htmlParser.unescape(url)
            isJs = url.find(".js") != -1
            match = re.findall(r"<(\s*)form(.+?)>(.+?)<(\s*)/(\s*)form(\s*)>",content,re.I|re.DOTALL)
            for row in match:
                method = ''
                action = None
                fields = []

                if row[1].lower().find("action") >= 0:
                    temp = re.findall(r"action(\s*)=(\s*)('|\")(.*?)(\3)",row[1],re.I)
                    if len(temp) > 0:
                        action = temp[0][3].replace(' ','')
                    else:
                        temp = re.findall(r"action(\s*)=(\s*)(.+?)(\s|$)",row[1],re.I)
                        if len(temp) >0:
                            action = temp[0][2]
                        #end if
                    #end if
                else:
                    action = url
                #end if

                if action == None:
                    continue
                #end if

                if isJs:
                    m = re.search(r"(['\"])(.*?)(\1)",action.decode('string_escape'))
                    if m: action = m.group(2)
                #end if

                if action == '':
                    action = url
                #end if

                temp = re.findall(r"method(\s*)=(\s*)('|\")(.*?)(\3)",row[1],re.I)
                if len(temp) > 0:
                    method = temp[0][3].lower().replace(' ','')
                else:
                    temp = re.findall(r"method(\s*)=(\s*)(.+?)(\s|$)",row[1],re.I)
                    if len(temp) >0:
                        method = temp[0][2].lower()
                    #end if
                #end if
                if method == '':
                    method = 'get'
                #end if

                input_match = re.findall(r"<(\s*)input(.+?)>",row[2],re.I|re.DOTALL)
                if len(input_match) > 0:
                    for input_row in input_match:
                        type = ''
                        name = ''
                        value = ''
                        temp = re.findall(r"type(\s*)=(\s*)('|\")(.+?)(\3)",input_row[1],re.I)
                        if len(temp) > 0:
                            type = temp[0][3].lower().replace(' ','')
                        else:
                            temp = re.findall(r"type(\s*)=(\s*)(.+?)(\s|/|$)",input_row[1],re.I)
                            if len(temp) >0:
                                type = temp[0][2].lower()
                            #end if
                        #end if
                        if type == '':
                            type = 'text'
                        #end if

                        temp = re.findall(r"name(\s*)=(\s*)('|\")(.+?)(\3)",input_row[1],re.I)
                        if len(temp) > 0:
                            name = temp[0][3].replace(' ','')
                        else:
                            temp = re.findall(r"name(\s*)=(\s*)(.+?)(\s|/|$)",input_row[1],re.I)
                            if len(temp) >0:
                                name = temp[0][2]
                            #end if
                        #end if

                        temp = re.findall(r"value(\s*)=(\s*)('|\")(.*?)(\3)",input_row[1],re.I)
                        if len(temp) > 0:
                            value = temp[0][3].replace(' ','')
                        else:
                            temp = re.findall(r"value(\s*)=(\s*)(.+?)(\s|/|$)",input_row[1],re.I)
                            if len(temp) >0:
                                value = temp[0][2]
                            #end if
                        #end if

                        if type in ['reset','button']:
                            continue
                        #end if
                        if name == '':
                            continue
                        #end if
                        fields.append({'type':type,'name':name,'value':value})
                    #end for
                #end if

                select_match = re.findall("<(\s*)select(.+?)>(.+?)<(\s*)/(\s*)select(\s*)>",row[2],re.I|re.DOTALL)
                if len(select_match) > 0:
                    for select_row in select_match:
                        name = ''
                        value = ''
                        temp = re.findall(r"name(\s*)=(\s*)('|\")(.+?)(\3)",select_row[1],re.I)
                        if len(temp) > 0:
                            name = temp[0][3].replace(' ','')
                        #end if
                        temp = re.findall(r"<(\s*)option(.+?)value(\s*)=(\s*)('|\")(.*?)(\5)(.*?)>(.+?)<(\s*)/(\s*)option(\s*)>",select_row[2],re.I)
                        if len(temp) > 0:
                            for temp_row in temp:
                                if temp_row[1].find('selected') >= 0 or temp_row[7].find('selected') >= 0:
                                    value = temp_row[5].replace(' ','')
                                    break
                                #end if
                            #end for
                            if value == '':
                                value = temp[0][5].replace(' ','')
                            #end if
                        else:
                            temp = re.findall(r"<(\s*)option(.+?)>(.+?)<(\s*)/(\s*)option(\s*)>",select_row[2],re.I)
                            if len(temp) > 0:
                                for temp_row in temp:
                                    if temp_row[1].find('selected') >= 0:
                                        value = temp_row[2].strip()
                                        break
                                    #end if
                                #end for
                                if value == '':
                                    value = temp[0][2].strip()
                                #end if
                            #end if
                        #end if
                        if name == '':
                            continue
                        #end if
                        fields.append({'type':'select','name':name,'value':value})
                    #end for
                #end if

                area_match = re.findall("<(\s*)textarea(.+?)>(.*?)<(\s*)/(\s*)textarea(\s*)>",row[2],re.I|re.DOTALL)
                if len(area_match) > 0:
                    for area_row in area_match:
                        name = ''
                        value = ''
                        temp = re.findall(r"name(\s*)=(\s*)('|\")(.+?)(\3)",area_row[1],re.I)
                        if len(temp) > 0:
                            name = temp[0][3].replace(' ','')
                        else:
                            temp = re.findall(r"name(\s*)=(\s*)(.+?)(\s|$)",area_row[1],re.I)
                            if len(temp) > 0:
                                name = temp[0][2]
                        #end if
                        value = area_row[2].strip()
                        if name == '':
                            continue
                        #end if
                        fields.append({'type':'textarea','name':name,'value':value})
                    #end for
                #end if

                fullpath = self.changeUrl(url, action)
                if fullpath == "" or fullpath[0] == '#' or len(fullpath.split("?")) > 2 or fullpath.find('>') >= 0 or fullpath.find('<') >= 0 or fullpath.find('{') >= 0 or fullpath.find('}') >= 0 or fullpath.find('\\') >= 0 or fullpath.find('+') >= 0 or fullpath.find('|') >= 0 or fullpath.find(',') >=0 :
                    continue
                #end if
                parse = urlparse.urlparse(fullpath)
                if  parse[0] != 'http' and parse[0] != 'https':
                    continue
                #end if

                # 网站由多路径组成，如果配置中没有传来排除的路径，由扫描全部路径
                if parse[1].find(self.domain) < 0 or parse[2].find(self.path) != 0:
                #if parse[1].find(self.domain) < 0:
                    continue
                #end if

                if method != 'post':
                    paramslist = []
                    for f in fields:
                        paramslist.append(f['name']+'='+f['value'])
                    params = '&'.join(paramslist)

                    self.addUrl(fullpath+'?'+params,url)
                else:
                    patternExist = self.checkPostPattern(parse,fields)
                    if not patternExist:
                        params = self.changeCode(json.write(fields))
                        if self.checkExcludeUrl(self.excludeUrl, url):
                            continue
                        #end if
                        self.updateUrlList(fullpath, 'post', params, url)
                    #end if
                #end if
            #end for
        except Exception, e:
            logger.exception(e)
        #end try
    #end def

    def getList(self, url):
        try:
            for row in self.nomatchTypeList:
                if url.lower().find(row) > 0:
                    return []
            for row in self.uncontentTypeList:
                if url.lower().find(row) > 0:
                    return []
            if url.find("www.phpmyadmin.net") > 0 and url.find("token") > 0:
                return []

            if self.specialDir(url) == False:
                return []

            list = []
            temp = []

            res, content = self.requestUrl(url)
            if not url.endswith('/'):
                url = urllib2.quote(url, '%:/?=#&;,')
                if res.has_key('content-location') and res['content-location'].endswith('/'):
                    if res['content-location'][:-1] == url:
                        url = res['content-location']
                url = urllib2.unquote(url)

            if content != "":
                temp.extend(self.getUrlByFullPath(url, content))
                temp.extend(self.getUrlFromJs(url, content))
                temp.extend(self.getATag(url, content))
                temp.extend(self.getIframeSrc(url, content))
                temp.extend(self.getSwf(url, content))
                self.getForm(url, content)

            for row in temp:
                if self.checklogout(row['url'], row['url_content']):
                    continue

                row = row['url']
                if row.find('#') > 0:
                    row = row.split('#')[0]

                row = self.htmlParser.unescape(row).strip()
                if row == "" or row[0] == '#' or len(row.split("?")) > 2 or row.find('>') >= 0 or row.find('<') >= 0 or row.find('{') >= 0 or row.find('}') >= 0 or row.find('\\') >= 0 or row.find('+') >= 0 or row.find('|') >= 0 or row.find(',') >=0 :
                    continue

                if row == "":
                    continue

                row = self.changeUrl(url, row)
                if self.specialAction(row) == False:
                    continue

                url_tuple = urlparse.urlparse(row)
                row_list = url_tuple[2].split('/')
                for i in range(10):
                    if len(row_list) > 2:
                        row_list = row_list[0:-1]
                        t = "%s://%s%s/" % (url_tuple[0],url_tuple[1],'/'.join(row_list))
                        if self.checkExcludeUrl(self.excludeUrl, t):
                            continue

                        if t in list:
                            continue

                        list.append(t)
                    else:
                        break
                if self.checkExcludeUrl(self.excludeUrl, row):
                    continue
                if row in list:
                    continue
                
                list.append(row)
            return list
        except Exception, e:
            logger.exception(e)
            return []

def main(argv):
    try:
        dict = {}
        scaner = Spider(dict)
        scaner.start()

    except Exception,e:
        logger.exception(e)
    #end try
#end def

