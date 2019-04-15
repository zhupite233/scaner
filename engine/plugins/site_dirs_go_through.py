# --*-- coding: utf-8 --*--
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
import re
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
'''
plugin_name: 目录遍历漏洞
desc：浏览器显示目录结构及目录中文件，导致重要文件及信息泄露
solu：APACHE 的httpd.conf文件
      路径： vi ./conf/httpd.conf
　　Options Indexes MultiViews　 ← 找到这一行，将“Indexes”删除
　　　 ↓
　　Options MultiViews 　 ← 变为此状态（不在浏览器上显示树状目录结构）
AllowOverride None
Order allow,deny
Allow from all
</Directory>

TOMCAT修改conf/web.xml文件
    <servlet>
        <servlet-name>default</servlet-name>
        <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
        <init-param>
            <param-name>debug</param-name>
            <param-value>0</param-value>
        </init-param>
        <init-param>
            <param-name>listings</param-name>
            <param-value>false</param-value> // 这里改为false 重启就好了
        </init-param>
        <load-on-startup>1</load-on-startup>
    </servlet>
'''


def run_domain(http, ob):
    result = []
    scheme = ob['scheme']
    domain = ob['domain']
    header = {'Host': domain}
    source_ip = ob.get('source_ip')
    site_dirs = ob['site_dirs']
    if not site_dirs:
        site_dirs = ['/']
    if source_ip:
        domain = source_ip
    if site_dirs:
        for path in site_dirs:
            url = "%s://%s%s" % (scheme, domain, path)
            pattern = r'(<title>Index of\s+%s\s*</title>|\[(To Parent Directory|%s)\])' % (path, u'转到父目录'.decode('utf-8'))
            try:
                res, content = http.request(url, 'GET', headers=header)
                if res and res.get('status') == '200' and \
                        re.search(pattern, content.decode('utf-8','ignore'), re.I|re.M):
                    detail = "存在目录遍历漏洞"
                    request = getRequest(url, domain=ob['domain'])
                    response = getResponse(res, content)
                    result.append(getRecord(ob, url, ob['level'], detail, request, response))
            except Exception, e:
                logger.error("File:site_dirs_go_through.py, run_domain function :%s" % (str(e)))

    return result