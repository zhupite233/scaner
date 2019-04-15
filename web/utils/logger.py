# --*-- coding: utf-8 --*--
#日志工厂类，用于统一管理所有的日志
#用法示例
#       loggerfactory = loggerFactory()
#       logger = loggerfactory.getLogger(__name__)
#       logger.info("操作成功！")
__author__ = 'lidq'

import os
import logging
import logging.handlers
import time
from config import LOG_BASE_PATH, LOG_OUTPUT_STDIN 

#LOG_BASE_PATH = '/tmp/'
#LOG_OUTPUT_STDIN = 0         #是否输出到标准输出

class loggerFactory:

    loggers = {}
    def getLogger(self, logname):
        if not self.loggers.has_key('default'):

            currDay = time.strftime('%Y-%m-%d', time.localtime(time.time()))
            if not os.path.exists(LOG_BASE_PATH):
                os.mkdir(LOG_BASE_PATH)
            logFile = LOG_BASE_PATH + 'scaner_' + currDay + '.log'

            #统一日志格式
            #fmt = "%(asctime)s - %(name)s- [%(scriptfile)s:%(scriptline)s] - %(levelname)s - %(message)s"
            fmt = "%(asctime)s - %(name)s- [%(filename)s:%(lineno)s] - %(levelname)s - %(message)s"
            formatter = logging.Formatter(fmt)

            #为日志添加两种输出目的地：文件与标准输出
            #日志输出到文件
            handlerFile = logging.handlers.RotatingFileHandler(logFile, maxBytes=20*1024*1024, backupCount=10)
            handlerFile.setFormatter(formatter)

            #日志输出到标准输出
            handlerStream = logging.StreamHandler()
            handlerStream.setFormatter(formatter)

            #获取日志操作对象
            logger = logging.getLogger(logname)
    
            #添加日志句柄
            logger.addHandler(handlerFile)
	    if LOG_OUTPUT_STDIN == 1: 
                logger.addHandler(handlerStream)
    
            #设置日志级别
            #logger.setLevel(logging.INFO)
            logger.setLevel(logging.DEBUG)
	    self.loggers['default'] = logger
	return self.loggers['default']

loggerfactory = loggerFactory()
mylogger = loggerfactory.getLogger("scaner")
