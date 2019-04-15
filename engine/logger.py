# --*-- coding: utf-8 --*--
#日志工厂类，用于统一管理所有的日志
#用法示例
#       loggerfactory = loggerFactory()
#       logger = loggerfactory.getLogger(__name__)
#       logger.info("操作成功！")
__author__ = 'lidq'

import os
import sys
#sys.path.append(os.path.dirname(__file__))
import logging
import logging.handlers
import time
import engineConfig as config

class loggerFactory:

    loggers = {}
    def getLogger(self, logname):
        if not self.loggers.has_key('default'):

            currDay = time.strftime('%Y-%m-%d', time.localtime(time.time()))
            if not os.path.exists(config.SCANER_LOG_BASE_PATH):
                os.mkdir(config.SCANER_LOG_BASE_PATH)
            logFile = config.SCANER_LOG_BASE_PATH + 'scaner_' + currDay + '.log'
    
            #统一日志格式
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
	    if config.SCANER_LOG_OUTPUT_STDIN == 1: 
                logger.addHandler(handlerStream)
    
            #设置日志级别
            #logger.setLevel(logging.INFO)
            logger.setLevel(logging.DEBUG)
	    self.loggers['default'] = logger
	return self.loggers['default']

    def getSpiderLogger(self, logname):
        if not self.loggers.has_key('spider'):
            currDay = time.strftime('%Y-%m-%d', time.localtime(time.time()))
            if not os.path.exists(config.SCANER_LOG_BASE_PATH):
                os.mkdir(config.SCANER_LOG_BASE_PATH)
            logFile = config.SCANER_LOG_BASE_PATH + 'scaner_spider.log'

            #统一日志格式
            fmt = "%(asctime)s - %(message)s"
            formatter = logging.Formatter(fmt)
    
            #日志只输出到文件
            handlerFile = logging.handlers.RotatingFileHandler(logFile, maxBytes=20*1024*1024, backupCount=10)
            handlerFile.setFormatter(formatter)

            #获取日志操作对象
            logger = logging.getLogger(logname)
    
            #添加日志句柄
            logger.addHandler(handlerFile)
            #设置日志级别
            logger.setLevel(logging.INFO)
	    self.loggers['spider'] = logger
	return self.loggers['spider']

loggerfactory = loggerFactory()
#logger = loggerfactory.getLogger(__name__)
scanLogger = loggerfactory.getLogger("scaner")

spiderLogger = loggerfactory.getSpiderLogger("spider")

