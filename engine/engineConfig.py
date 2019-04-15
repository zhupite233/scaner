# --*--coding:utf-8--*--
import os
import platform


engine_basedir = os.path.abspath(os.path.dirname(__file__))
if 'Windows' in platform.system():
    HOSTS_PATH = "C:\\Windows\\System32\\drivers\\etc\\hosts"
else:
    HOSTS_PATH = "/etc/hosts"

SCANER_LOG_BASE_PATH = '/tmp/'      #日志目录
SCANER_LOG_OUTPUT_STDIN = 1         #是否输出到标准输出, 仅供调试用

# 数据库配置
SCANER_DB_HOST = "192.168.3.86"
SCANER_DB_USER = "ydscan"
SCANER_DB_PASSWORD = "Yd#234"
SCANER_DB_DATABASE = "scan_prod"

#scaner temp dir
SCANER_TEMP_DIR = ""
SCANER_SPIDER_DOWNLOAD_DIR = "/tmp/scaner_spider/"
if not os.path.exists(SCANER_SPIDER_DOWNLOAD_DIR):
    os.makedirs(SCANER_SPIDER_DOWNLOAD_DIR)

if __name__ == "__main__":
    print SCANER_LOG_BASE_PATH
    print SCANER_LOG_OUTPUT_STDIN

