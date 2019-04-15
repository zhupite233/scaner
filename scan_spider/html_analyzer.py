# --*-- coding:utf-8 --*--
from lxml import html as l_html

from Data import UrlData


class HtmlAnalyzer(object):
    '''页面分析类'''
    @staticmethod
    def extract_links(html,base_ref,tags=[]):
        '''
        抓取页面内链接(生成器)
        base_ref : 用于将页面中的相对地址转换为绝对地址
        tags     : 期望从该列表所指明的标签中提取链接
        '''
        if not html or not html.strip():
            return
        link_list = []
        try:
            doc = l_html.document_fromstring(html)
        except Exception,e:
            return

        default_tags = ['a','img','iframe','frame']
        default_tags.extend(tags)
        default_tags = list(set(default_tags))
        doc.make_links_absolute(base_ref)
        links_in_doc = doc.iterlinks()
        for link in links_in_doc:
            if link[0].tag in set(default_tags):
                url_data = UrlData(link[2].rstrip('?').rstrip('#'))
                # yield {link[2]: url_data}
                yield url_data