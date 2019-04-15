# --*-- coding: utf-8 --*--

# from lxml import etree
#
# parser = etree.XMLParser(load_dtd=True)
# tree = etree.parse("latest.xml", parser)
# root = tree.getroot()
# for entry in root:
#     # print "元素名称：", article.name
#     print entry.tag
#     for field in entry:
#         print field.get('vuln-id')
#     # break
#     # id = article.get("vuln-id")#用.get("属性名")可以得到article元素相应属性的值
#     # describe = article.get("vuln-descript")
#     # print id, descript


from bs4 import BeautifulSoup
from cnnvd_model import CnnvdVul
from common.sql_orm import DBSession
from time import sleep
db_session = DBSession()
i,j = 0,0
for file_name in ['latest', 'month', '2017', '2016', '2015', '2014', '2013', '2012', '2011', '2010', '2009', '2008', '2007', '2006', '2005', '2004', '2003', '2002', '2001', '2000', '1999_and_before']:

    soup = BeautifulSoup(open('E:/CNNVD/%s.xml' % file_name), 'xml')
    entry = soup.find_all('entry')

    for data in entry:
        print i, j
        try:
            try:
                remote = data.find('thrtype')
                remote = unicode(remote.contents[0])
                i += 1
            except:
                level = ''
            try:
                cnnvd_id = data.find('vuln-id')
                cnnvd_id = unicode(cnnvd_id.contents[0])
            except:
                cnnvd_id = ''
            if not remote:
                continue
            try:
                log = db_session.query(CnnvdVul).filter(CnnvdVul.cnnvd_id == cnnvd_id).first()
                if not log:
                    continue
                # if log.level:
                #     continue
                log.remote = remote
                db_session.add(log)
                db_session.commit()
                j += 1
            except Exception, e:
                print str(e)
                sleep(1)
                db_session.rollback()
        except:
            pass

    db_session.close()

    #         try:
    #             name = data.find('name')
    #             name = unicode(name.contents[0])
    #         except:
    #             i += 1
    #             continue
    #         try:
    #             cnnvd_id = data.find('vuln-id')
    #             cnnvd_id = unicode(cnnvd_id.contents[0])
    #         except:
    #             cnnvd_id = ''
    #         try:
    #             cve_id = data.find('cve-id')
    #             cve_id = unicode(cve_id.contents[0])
    #         except:
    #             cve_id = ''
    #         try:
    #             published_date = data.find('published')
    #             published_date = unicode(published_date.contents[0])
    #         except:
    #             published_date = ''
    #         try:
    #             modified_date = data.find('modified')
    #             modified_date = unicode(modified_date.contents[0])
    #         except:
    #             modified_date = ''
    #         try:
    #             vul_type = data.find('vuln-type')
    #             vul_type = unicode(vul_type.contents[0])
    #         except:
    #             vul_type = ''
    #         try:
    #             describe = data.find('vuln-descript')
    #             describe = unicode(describe.contents[0])
    #         except:
    #             describe = ''
    #         try:
    #             solution = data.find('vuln-solution')
    #             solution = unicode(solution.contents[0])
    #         except:
    #             solution = ''
    #         try:
    #             level = data.find('severity')
    #             level = unicode(level.contents[0])
    #         except:
    #             level = ''
    #         # print '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s ' % (type(name), type(cnnvd_id), type(cve_id), type(published_date), type(modified_date), type(vul_type), type(describe), type(solution))
    #         # print '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s ' % (name, cnnvd_id, cve_id, published_date, modified_date, vul_type, describe, solution)
    #         try:
    #             cnnvd = CnnvdVul(name=name, cnnvd_id=cnnvd_id, cve_id=cve_id, published_date=published_date,
    #                              modified_date=modified_date, vul_type=vul_type, level=level, describe=describe, solution=solution)
    #             db_session.add(cnnvd)
    #             db_session.commit()
    #
    #         except Exception, e:
    #             print str(e)
    #             j += 1
    #             db_session.rollback()
    #     except:
    #         i += 1
    # print i, j
    # db_session.close()


#
# soup = BeautifulSoup(open('latest.xml'), 'xml')
# for data in soup.entry.children:
#     print type(data.string)



#
# import xml.etree.ElementTree as ET
#
#
# tree = ET.parse('latest.xml')
# node_all = tree.findall('entry')
# for node in node_all:
#     print node.tag