# coding: utf-8
desc = '''
1. SQL注入攻击是黑客对数据库进行攻击的常用手段之一。随着B/S模式应用开发的发展，使用这种模式编写应用程序的程序员也越来越多。但是由于程序员的水平及经验也参差不齐，相当大一部分程序员在编写代码的时候，没有对用户输入数据的合法性进行判断，使应用程序存在安全隐患。用户可以提交一段数据库查询代码，根据程序返回的结果，获得某些他想得知的数据，这就是所谓的SQL Injection，即SQL注入。

2. SQL注入从HTTP请求方式上可分为三种：
   (1) GET方式注入。
   (2) POST方式注入。
   (3) HEAD方式注入。

3. 从注入类型上可分为：
   (1) 数字型注入。判断方式为：在URL参数后面加“and 1=1”和“and 1=2”进行判断。
   (2) 字符型注入。判断方式一般为：在URL参数后面加“' and '1'='1”和“' and '1'='2”进行判断。
   (3) 搜索型注入。搜索型注入一般为POST提交方式。判断方式一般为：在URL参数后面加“%' and '%'='”和“%' and 'ss'='”进行判断。

4. 从注入利用方式上可分为：
   (1) 利用数据库返回的错误信息进行注入，往往这种注入方式成功率是最高的。
   (2) 通过联合查询，虽然没有返回数据库错误信息，但是通过UNION SELECT 可轻易获取数据库敏感信息。
   (3) 盲注，盲注是通过一个字符一个字符的猜解数据库里的相关信息，虽然速度比较慢，但是最终还是可以获取数据库敏感信息。

5. 攻击者成功利用此漏洞后：
   (1) 可获取数据库相关敏感数据。导致数据库泄露。
   (2) 可修改、删除数据库相关数据。导致数据被篡改
   (3) 可通过该SQL注入提升权限，获取网站或者服务器权限。
'''
solu = '''
1. 对外部用户提交的数据进行严格的过滤。强制限制外部提交的值的类型，如是数字型则判断提交的数字是否为数字型，如是字符型过滤单引号限制字符长度。

2. 联系网站的制作商，向其索要补丁包。

3. 如果您用的是开源的CMS，请到其官网上下载最新的补丁。

4. 如果您懂得程序并可以修改服务器代码，请根据您的网站语言选择防注入程序：
    ASP语言下载
    PHP语言下载
    .NET语言下载
    下载后根据使用说明进行修改，即可起到防护作用。

5. 如果您的网站语言是JSP的，请参考下列防注入方法进行防范：
    sql_inj.java代码：

    package sql_inj;
    import java.net.*;
    import java.io.*;
    import java.sql.*;
    import java.text.*;
    import java.lang.String;
    public class sql_inj{
    public static boolean sql_inj（String str）
    {
    String inj_str = “'|and|exec|insert|select|delete|update|count|*|%|chr|mid|master|truncate|char|declare|;|or|-|+|,”;//这里是注入关键词可以根据需要进行增加或者修改。
    String[] inj_stra=inj_str.split（“\\|”）；
    for （int i=0 ; i < inj_stra.length ; i++ ）
    {
    if （str.indexOf（inj_stra[i]）>=0）
    {
    return true;
    }
    }
    return false;
    }
    }
      sql_inj.java为一个改进的防注入bean，编译后将class文件放在tomcat的classes下的sql_inj目录中

    JSP页面调用：
   <jsp:useBean id=“sql_inj” class=“sql_inj.sql_inj” scope=“page”/>
    <%
    String currenturl = request.getRequestURI（）+（request.getQueryString（）==null?“”:（“?”+request.getQueryString（）））；
    if （sql_inj.sql_inj（currenturl））{ //判断url及参数中是否包含注入代码，是的话就跳转。
    response.sendRedirect（“/”）；
    return;
    }
    //out.println（currenturl）；
    %>

6. 部署Web应用防火墙。

'''

from web import db
from web.models.web_policy_db import WebVulList


def update_vul(vul_id):
    vul = db.session.query(WebVulList).filter(WebVulList.vul_id==vul_id).first()
    vul.solu = solu
    vul.desc = desc
    db.session.add(vul)
    db.session.commit()