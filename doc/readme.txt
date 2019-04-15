
task表中可删除的字段：
spider_type 蜘蛛类型，在源代码中有两个spider 和 spider2 ,未来我们的代码中应该只有一个
spider_enable  是否开启爬虫，开启爬虫与开启web扫描的功能一样要抓取页面，所以皮字段多余

web_scan_thread, weak_pwd_scan_thread, port_scan_thread, host_scan_thread 每个扫描任务所用的线程数，此项多余，可定制为固定的级别，而不需要用户填写

策略不区别是web扫描，主机扫描，弱口令扫描，端口扫描，一个策略中可以是这几项的混合

