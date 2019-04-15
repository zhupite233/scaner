# --*-- coding: utf-8 --*--
import os
import platform
from kombu import Exchange, Queue

MY_SERVER_NAME = ''

NMAP_PATH = 'D:/nmap/nmap.exe'

basedir = os.path.abspath(os.path.dirname(__file__))
WEBROOT = basedir

#pdf文件绝对路径
PDF_ROOT = '/wls/wls81/pdf/'
PDF_DOMAIN = 'http://0.0.0.0:8085/'

#pdf模板logo图片路径
PDF_LOGO_PATH1 = '/web/static/report2/imgs/'
PDF_LOGO_PATH2 = '/../scaner_report/app/static/report2/imgs/'

#站点域名
SITE_DOMAIN = "https://scan.yundun.com/"

# database
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')
SQLALCHEMY_DATABASE_URI = 'mysql://ydscan:Yd#234@192.168.3.86/scan_prod'
SQLALCHEMY_BINDS = {
    'scan': SQLALCHEMY_DATABASE_URI,
}

TABLE_PREFIX = 't_'
# secret
CSRF_ENABLED = True
SECRET_KEY = 'xgeESX@ghj67g487Gwj8j$^df'
SESSION_LIFETIME = 1000 * 24 * 60 * 60

# pagigat
PER_PAGE = 10
CSS_FRAMEWORK = 'bootstrap3'
LINK_SIZE = 'sm'
# decide whether or not a single page returns pagination
SHOW_SINGLE_PAGE = False

# email
MAIL_SERVER = ''
MAIL_PORT = 25
MAIL_USERNAME = ''
MAIL_PASSWORD = ''
MAIL_SENDER = ''

if 'Windows' in platform.system():
    STRSPIT = "\\"
else:
    STRSPIT = "/"
UPLOAD_FOLDER = 'app' + STRSPIT + 'up_loads' + STRSPIT
DOWN_FOLDER = 'app' + os.sep + 'downloads' + os.sep

# log path
LOG_PATH = basedir + os.sep + 'log'
LOG_BASE_PATH = '/tmp/'
LOG_OUTPUT_STDIN = 0         #是否输出到标准输出, 仅供调试用

# cmdb remote server info
CMDB_HOSTNAME = ''
CMDB_USERNAME = ''
CMDB_PASSWORD = ''
CMDB_PORT = ''


# mysql config
DB_USERNAME = 'ydscan'
DB_PASSWORD = 'Yd#234'
DB_HOST = '192.168.3.86'
DB_PORT = 3306
DB_NAME = 'scan_prod'
# 全网态势报告通知url
PATCH_REP_URL = 'http://www.tsgz.vm'
# SPIDER_URL
SPIDER_URL = 'http://192.168.3.74:9022'
SPIDER_TOKEN = 'wbsllmigfa4ct0zp4gdd4hx2umpijg4e'
SPIDER_LIMIT_TIME = {'509': 3000, '510': 1800, '511': 1200}
# Celery configuration
CELERY_BROKER_URL = 'redis://192.168.3.86:6379/7'
CELERY_RESULT_BACKEND = 'redis://192.168.3.86:6379/7'

#Celery Queue
CELERY_QUEUES = (
    Queue('default', Exchange('default'), routing_key='default'),
    Queue('engines',  Exchange('engine'),   routing_key='engine.engines'),
    Queue('reports',  Exchange('report'),   routing_key='report.reports'),
    Queue('hosts',  Exchange('host'),   routing_key='host.hosts'),
    Queue('ports',  Exchange('port'),   routing_key='port.ports')
)
CELERY_DEFAULT_QUEUE = 'default'
CELERY_DEFAULT_EXCHANGE_TYPE = 'direct'
CELERY_DEFAULT_ROUTING_KEY = 'default'

#Celery Routes # 一定要修改job运行函数名称namespace
CELERY_ROUTES = ({'web.utils.web_job.run_engine':
                    {'queue': 'engines', 'routing_key': 'engine.engines'}
                  },
                 {'web.utils.web_job.run_report':
                    {'queue': 'reports', 'routing_key': 'report.reports'}
                  },
                 {'host_scan.utils.host_job.run_host_engine':
                    {'queue': 'hosts', 'routing_key': 'host.hosts'}
                  },
                 {'port_scan.utils.port_job.run_port_engine':
                    {'queue': 'ports', 'routing_key': 'port.ports'}
                  },
                 {'web.new_tasks.run_add_together':
                    {'queue': 'default', 'routing_key': 'default'}
                  },
                 )


