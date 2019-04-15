#!/usr/bin/python
# coding: utf-8

import time
import os
import sys
import socket
import re
import platform
import shlex

base_dir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
sys.path.append(base_dir)
install_dir = "/opt/ydscan"
soft_dir = "/opt/ydscan/soft"
conf_dir = "/opt/ydscan/conf"


def bash(cmd):
    """
    run a bash shell command
    执行bash命令
    """
    return shlex.os.system(cmd)


def valid_ip(ip):
    if ('255' in ip) or (ip == "0.0.0.0"):
        return False
    else:
        return True


def color_print(msg, color='red', exits=False):
    """
    Print colorful string.
    颜色打印字符或者退出
    """
    color_msg = {'blue': '\033[1;36m%s\033[0m',
                 'green': '\033[1;32m%s\033[0m',
                 'yellow': '\033[1;33m%s\033[0m',
                 'red': '\033[1;31m%s\033[0m',
                 'title': '\033[30;42m%s\033[0m',
                 'info': '\033[32m%s\033[0m'}
    msg = color_msg.get(color, 'red') % msg
    print msg
    if exits:
        time.sleep(2)
        sys.exit()
    return msg


def get_ip_addr():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        if_data = ''.join(os.popen("LANG=C ifconfig").readlines())
        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', if_data, flags=re.MULTILINE)
        ip = filter(valid_ip, ips)
        if ip:
            return ip[0]
    return ''


class PreSetup(object):
    def __init__(self):
        self.db_host = '127.0.0.1'
        self.db_port = 3306
        self.db_user = 'ydscan'
        self.db_pass = 'Yd#234'
        self.db = 'scan'
        self.ip = ''
        self.dist = platform.linux_distribution()[0].lower()
        self.version = platform.linux_distribution()[1]

    @property
    def _is_redhat(self):
        if self.dist.startswith("centos") or self.dist.startswith("red") or self.dist == "fedora" or self.dist == "amazon linux ami":
            return True

    @property
    def _is_centos7(self):
        if self.dist.startswith("centos") and self.version.startswith("7"):
            return True

    def check_platform(self):
        if not self._is_redhat:
            print(u"支持的平台: CentOS Linux release 7, 暂不支持其他平台安装.")
            exit()

    @staticmethod
    def check_bash_return(ret_code, error_msg):
        if ret_code != 0:
            color_print(error_msg, 'red')
            exit()

    def _setup_mysql(self):
        color_print('开始安装设置mysql (请手动设置mysql安全)', 'green')
        # color_print('默认用户名: %s 默认密码: %s' % (self.db_user, self.db_pass), 'green')
        db_user = raw_input('请输入数据库服务器用户 [ydscan]: ').strip()
        db_pass = raw_input('请输入数据库服务器密码: ').strip()
        grant_host = raw_input('请输入数据库授权访问主机: ').strip()
        if not grant_host:
            grant_host = '127.0.0.1'
        if db_user:
            self.db_user = db_user
        if db_pass:
            self.db_pass = db_pass
        if self._is_centos7:
            ret_code = bash('yum -y install mariadb-server mariadb-devel MySQL-python psmisc')
            self.check_bash_return(ret_code, "安装mysql(mariadb)失败, 请检查安装源是否更新或手动安装！")

            bash('systemctl enable mariadb.service')
            bash('systemctl start mariadb.service')
        else:
            color_print('系统版本非Centos7， 请检查', 'red')
        bash('mysql -e "create database %s default charset=utf8"' % self.db)
        bash('mysql -e "grant all on %s.* to \'%s\'@\'%s\' identified by \'%s\'"' % (self.db,
                                                                                     self.db_user,
                                                                                     grant_host,
                                                                                     self.db_pass))
        res_code = bash('mysql -e "source %s/scan_model.sql"' % (self.db_user, self.db_pass, conf_dir))
        bash('mysql -e "update mysql.user set password=PASSWORD(\'Flzx3qcYsyhl9t\') where User=\'root\'"')
        bash('mysql -e "flush privileges"')
        self.check_bash_return(res_code, "初始化数据库SCAN库失败！")

    def _set_env(self):
        color_print('开始设置防火墙', 'green')
        if self._is_redhat:
            os.system("export LANG='en_US.UTF-8'")
            if self._is_centos7 :
                cmd_22 = "iptables -A INPUT -s 59.56.19.0/24 -p tcp --dport 22 -j ACCEPT && " \
                       "iptables -A INPUT -s 183.131.177.240/28 -p tcp --dport 22 -j ACCEPT && " \
                       "iptables -A INPUT -p tcp --dport 22 -j DROP"
                cmd_redis = "iptables -A INPUT -s 115.238.233.206/27 -p tcp --dport 6379 -j ACCEPT && " \
                            "iptables -A INPUT -p tcp --dport 6379 -j DROP"
                cmd_mysql = "iptables -A INPUT -s 115.238.233.206/27 -p tcp --dport 3306 -j ACCEPT && " \
                            "iptables -A INPUT -p tcp --dport 3306 -j DROP"
                cmd_waf = "iptables -A INPUT -s 59.56.19.0/24    -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 59.56.79.0/24    -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 115.231.25.0/24  -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 183.131.214.0/24 -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 101.71.32.0/24   -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 111.1.37.0/24    -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 112.175.69.0/24  -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 112.175.238.0/24 -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 112.175.245.0/24 -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 220.95.238.0/24  -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 122.9.0.0/16     -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 23.252.161.0/24  -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 23.252.163.0/24  -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -s 103.36.210.0/24  -p tcp --dport 443 -j ACCEPT && "\
                            "iptables -A INPUT -p tcp --dport 443 -j DROP"
                color_print('设置PORT 22', 'green')
                color_print('清除iptables设置', 'green')
                bash("iptables -F")
                bash(cmd_22)
                color_print('设置REDIS PORT 6379', 'green')
                bash(cmd_redis)
                color_print('设置PORT 3306', 'green')
                bash(cmd_mysql)
                color_print('设置PORT 443', 'green')
                bash(cmd_waf)
            else:
                color_print('系统版本非Centos7， 请检查', 'red')
        else:
            color_print('系统版本非Centos7， 请检查', 'red')

    def _test_db_conn(self):
        import MySQLdb
        try:
            MySQLdb.connect(host=self.db_host, port=int(self.db_port),
                            user=self.db_user, passwd=self.db_pass, db=self.db)
            color_print('连接数据库成功', 'green')
            return True
        except MySQLdb.OperationalError, e:
            color_print('数据库连接失败 %s' % e, 'red')
            return False

    def _depend_rpm(self):
        color_print('开始安装依赖包', 'green')
        if self._is_redhat:
            cmd = 'yum -y install python-pip mysql-devel MySQL-python gcc gcc-c++ python-devel vim lrzsz python-virtualenv psmisc emerge zlib fontconfig freetype libX11 libXext libXrender mkfontscale'
            ret_code = bash(cmd)
            self.check_bash_return(ret_code, "安装依赖失败, 请检查安装源是否更新或手动安装！")
        else:
            color_print('系统版本非Centos7， 请检查', 'red')

    def _require_pip(self):
        color_print('开始安装依赖pip包', 'green')
        cmd = "cd %s && virtualenv scan_env && source %s/scan_env/bin/activate " % (install_dir, install_dir)
        bash(cmd)
        pip_update = "%s/scan_env/bin/pip install --upgrade pip" % install_dir
        bash(pip_update)
        cmd_pip = "%s/scan_env/bin/pip install -r %s/scaner/scripts/requirement.txt -i http://pypi.douban.com/simple --trusted-host pypi.douban.com" % (install_dir, install_dir)
        cmd_pip_other = "%s/scan_env/bin/pip install WTForms reportlab" % install_dir
        ret_code1 = bash(cmd_pip)
        ret_code = bash(cmd_pip_other)
        ret_code2 = bash("unzip %s/mysql.zip -d %s/scan_env/lib/python2.7/site-packages/" % (soft_dir, install_dir))
        self.check_bash_return(ret_code1, "安装依赖的python库失败！")
        self.check_bash_return(ret_code, "安装依赖的python库失败！")
        self.check_bash_return(ret_code2, "安装依赖mysql-connector失败！")

    def _input_mysql(self):
        while True:
            mysql = raw_input('是否安装新的MySQL服务器? (y/n) [y]: ')
            if mysql != 'n':
                self._setup_mysql()
            else:
                db_host = raw_input('请输入数据库服务器IP [127.0.0.1]: ').strip()
                db_port = raw_input('请输入数据库服务器端口 [3306]: ').strip()
                db_user = raw_input('请输入数据库服务器用户 [ydscan]: ').strip()
                db_pass = raw_input('请输入数据库服务器密码: ').strip()
                db = raw_input('请输入使用的数据库 [scan]: ').strip()

                if db_host: self.db_host = db_host
                if db_port: self.db_port = db_port
                if db_user: self.db_user = db_user
                if db_pass: self.db_pass = db_pass
                if db: self.db = db

            if self._test_db_conn():
                break

            print

    def _setup_nginx(self):
        color_print('开始安装nginx', 'green')
        cmd_pcre = "cd %s && unzip pcre-8.34.zip && cd pcre-8.34 && ./configure && make && make install" % soft_dir
        ret_code = bash(cmd_pcre)
        self.check_bash_return(ret_code, "安装pcre-8.34失败！")
        cmd_nginx = "cd %s && tar -xvf nginx-1.11.3.tar.gz && cd nginx-1.11.3 && ./configure --prefix=/usr/local/nginx --with-http_ssl_module --with-stream_ssl_module --with-mail_ssl_module && make && make install" % soft_dir
        ret_code = bash(cmd_nginx)
        self.check_bash_return(ret_code, "安装nginx失败！")

    def _setup_uwsgi(self):
        color_print('开始安装uwsgi', 'green')
        cmd_uwsgi = "cd %s && tar -xvf uwsgi-2.0.13.1.tar.gz && cd uwsgi-2.0.13.1 && make && echo /usr/local/lib >> /etc/ld.so.conf && ldconfig && cp uwsgi /usr/bin" % soft_dir
        ret_code = bash(cmd_uwsgi)
        self.check_bash_return(ret_code, "安装uwsgi失败！")

    def _setup_wkhtml(self):
        color_print('开始安装wkhtmltox', 'green')
        cmd_wkhtmltox = "cd %s && tar -xvf wkhtmltox-0.12.3_linux-generic-amd64.tar.xz && mv wkhtmltox .. && " \
                        "ln -s %s/wkhtmltox/bin/wkhtmltopdf /usr/bin/wkhtmltopdf && " \
                        "ln -s %s/wkhtmltox/bin/wkhtmltoimage /usr/bin/wkhtmltoimage" % (soft_dir, install_dir, install_dir)
        ret_code = bash(cmd_wkhtmltox)
        self.check_bash_return(ret_code, "安装wkhtmltox失败！")

    def _setup_phantomjs_casperjs(self):
        color_print('开始安装phantomjs', 'green')
        cmd1 = "cd %s && yum -y install bzip2 && tar -xvf phantomjs-2.1.1-linux-x86_64.tar.bz2 && cp phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/bin/" % soft_dir
        ret_code = bash(cmd1)
        self.check_bash_return(ret_code, "安装phantomjs失败！")
        cmd2 = "cd %s && unzip casperjs-casperjs-0.6.9-0-g9fcf674.zip && mv casperjs-casperjs-9fcf674/ casperjs && ln -sf %s/casperjs/bin/casperjs /usr/bin/casperjs" % (soft_dir, soft_dir)
        ret_code = bash(cmd2)
        self.check_bash_return(ret_code, "安装casperjs失败！")

    def _setup_fonts(self):
        color_print('开始安装fonts', 'green')
        cmd_fonts = "cd %s && cp MSYH.TTC /usr/share/fonts/ && mkfontscale && mkfontdir" % soft_dir
        ret_code = bash(cmd_fonts)
        self.check_bash_return(ret_code, "安装fonts失败！")

    def _setup_swf(self):
        color_print('开始安装swftools', 'green')
        cmd = "cd %s && tar -xvf swftools-2013-04-09-1007.tar.gz && cd swftools-2013-04-09-1007 && ./configure && make && make install" % soft_dir
        ret_code = bash(cmd)
        self.check_bash_return(ret_code, "安装swftools失败！")

    def _setup_redis(self):
        color_print('开始安装redis', 'green')
        cmd_redis = "cd %s && tar -xvf redis-3.2.3.tar.gz && cd redis-3.2.3/src && make && make install && " \
                    "mkdir -p /usr/local/redis/etc && mkdir -p /usr/local/redis/bin && mv mkreleasehdr.sh " \
                    "redis-benchmark redis-check-aof redis-check-rdb redis-cli redis-sentinel " \
                    "redis-server redis-trib.rb /usr/local/redis/bin/" % soft_dir
        ret_code = bash(cmd_redis)
        self.check_bash_return(ret_code, "安装redis失败！")
        start_redis = "cp %s/redis.conf /usr/local/redis/etc/ && /usr/local/redis/bin/redis-server /usr/local/redis/etc/redis.conf" % conf_dir
        ret_code = bash(start_redis)
        self.check_bash_return(ret_code, "start_redis失败！")

    def _init_nginx_uwsgi(self):
        bash("mkdir %s/logs" % install_dir)
        cmd = "mv /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/nginx.conf.bak && " \
              "cp %s/nginx.conf /usr/local/nginx/conf/ " % conf_dir
        bash(cmd)
        cmd = "%s/start_stop_service.sh start" % install_dir
        ret_code = bash(cmd)
        self.check_bash_return(ret_code, "start_nginx_uwsgi失败！")

    def _setup_supervisor(self):
        cmd = "%s/scan_env/bin/pip install supervisor -i http://pypi.douban.com/simple --trusted-host pypi.douban.com" % install_dir
        ret_code = bash(cmd)
        self.check_bash_return(ret_code, "安装supervisor失败！")
        cmd = "%s/scan_env/bin/supervisord -c %s/conf/supervisord.conf" % (install_dir, install_dir)
        ret_code = bash(cmd)
        self.check_bash_return(ret_code, "Start supervisor失败！")

    def start(self):
        color_print('请务必先查看手册,检查soft及conf&star_stop脚本是否已上传至相应目录')
        time.sleep(3)
        self.check_platform()
        self._depend_rpm()
        self._require_pip()
        self._set_env()
        self._input_mysql()
        redis = raw_input('是否安装新的Redis服务器? (y/n) [y]: ')
        if redis != 'n':
            self._setup_redis()
        self._setup_nginx()
        self._setup_uwsgi()
        self._setup_wkhtml()
        self._setup_fonts()
        self._setup_swf()
        self._setup_phantomjs_casperjs()
        self._init_nginx_uwsgi()
        self._setup_supervisor()


if __name__ == '__main__':
    pre_setup = PreSetup()
    pre_setup.start()
