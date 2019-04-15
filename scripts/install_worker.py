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


    def _depend_rpm(self):
        color_print('开始安装依赖包', 'green')
        if self._is_redhat:
            cmd = 'yum -y install unzip python-pip mysql-devel MySQL-python gcc gcc-c++ python-devel vim lrzsz python-virtualenv psmisc emerge zlib fontconfig freetype libX11 libXext libXrender mkfontscale'
            ret_code = bash(cmd)
            self.check_bash_return(ret_code, "安装依赖失败, 请检查安装源是否更新或手动安装！")
        else:
            color_print('系统版本非Centos7， 请检查', 'red')

    def _require_pip(self):
        color_print('开始安装依赖pip包', 'green')
        cmd = "cd %s && virtualenv scan_env && source %s/scan_env/bin/activate " % (install_dir, install_dir)
        bash(cmd)
        pip_update = "%s/scan_env/bin/pip install --upgrade pip -i http://pypi.douban.com/simple" % install_dir
        bash(pip_update)
        cmd_pip = "%s/scan_env/bin/pip install -r %s/scaner/scripts/requirement.txt -i http://pypi.douban.com/simple --trusted-host pypi.douban.com" % (install_dir, install_dir)
        cmd_pip_other = "%s/scan_env/bin/pip install WTForms reportlab" % install_dir
        ret_code1 = bash(cmd_pip)
        ret_code = bash(cmd_pip_other)
        ret_code2 = bash("unzip %s/mysql.zip -d %s/scan_env/lib/python2.7/site-packages/" % (soft_dir, install_dir))
        self.check_bash_return(ret_code1, "安装依赖的python库失败！")
        self.check_bash_return(ret_code, "安装依赖的python库失败！")
        self.check_bash_return(ret_code2, "安装依赖mysql-connector失败！")


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
        self._setup_supervisor()


if __name__ == '__main__':
    pre_setup = PreSetup()
    pre_setup.start()
