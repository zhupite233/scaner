# --*-- coding:utf-8 --*--
import json
import re
import time
import urlparse

from lxml import etree
from selenium.common.exceptions import NoAlertPresentException
from splinter import Browser

from scan_spider.tag_mcj import tag_attr_dict, tag_mouse_event_dict, tag_auto_js_list, fill_form_dict
from Data import UrlData


class WebKit(object):
    '''WebKit引擎'''
    def __init__(self, login_dict={}):
        self.tag_attr_dict = tag_attr_dict
        self.tag_mouse_event_dict = tag_mouse_event_dict
        self.tag_auto_js_list = tag_auto_js_list
        self.browser = Browser("phantomjs", service_args=['--ignore-ssl-errors=true'])
        self.login_dict = login_dict
        self.browser.driver.set_page_load_timeout(8)
        self.browser.driver.set_script_timeout(8)

    def auto_login(self):
        self.browser.visit(self.login_dict.get('login_url'))
        time.sleep(5)
        # for k, v in self.login_dict.get('values').items():
        #     self.browser.fill(k, v)
        # self.browser.find_by_tag('button').click()

    # def set_cookie(self, custom_headers):
    #     cookie_list= custom_headers.get('Cookie').split(';')
    #     cookie_dict = {}
    #     for kv_str in cookie_list:
    #         kv_list = kv_str.split('=')
    #         cookie_dict[kv_list[0]] = kv_list[1]
    #     if cookie_dict:
    #         self.browser.cookies.add(cookie_dict)

    def extract_links(self, url):
        '''
        抓取页面链接
        :param url:
        '''
        try:
            self.browser.execute_script('''
                _open = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function (method, url, data) {
                    if (!this._url) {
                        this._url = url;console.log(url);
                        this._method = method;

                    }
                    _open.apply(this, arguments);
                };
                _send = XMLHttpRequest.prototype.send;
                XMLHttpRequest.prototype.send = function (data) {
                var a = document.createElement("a");
                //为a创建属性href
                var a_attr = document.createAttribute("href");
                if(data) {
                    var full_url = this._url+'?type=ajax&method='+this._method+'?'+data
                }else {
                    var full_url = this._url+'?type=ajax&method='+this._method
                }

                a_attr.value = full_url;
                //把属性添加到a
                a.setAttributeNode(a_attr);
                console.log('1111111'+data);
                 //将a追加到body
                document.getElementsByTagName("body").item(0).appendChild(a);
                    console.log(2222222222+this._url)
                    console.log(333,arguments)
                //window.$Result$.add_ajax(this._url, this._method, data);
                _send.apply(this, arguments);
                //下面是禁止跳转
                 //var _this = $(this);
                 //var subHref = _this.attr('href');
                 //e.preventDefault();
                };
            ''')

            self.browser.visit(url)

        except Exception, e:
            return
        # time.sleep(1)  # 必须等待浏览器加载完毕
        # print self.browser.html

        # 从form取url, 并返回form表单填充值
        form_elements = self.browser.find_by_tag('form')

        for form_ele in form_elements:
            url, url_data, fill_dict = self.get_url_by_form(form_ele)
            # 对form表单进行值填充， 有些form表单有空值校验，不填充，无法触发js事件
            if fill_dict:
                # self.browser.fill_form(fill_dict)
                pass
            if url and url_data:
                # yield {url: url_data}
                yield url_data
            else:
                continue
                # print url_data.url, url_data.post_data
        for tag, attr in self.tag_attr_dict.iteritems():
            try:
                link_list = self.browser.find_by_xpath('//%s[@%s]' % (tag,attr))
            except Exception, e:
                link_list = None
                print e
            if not link_list:
                continue
            for link in link_list:
                link = link.__getitem__(attr)
                if not link:
                    continue
                link = link.strip()
                if link == 'about:blank' or link.startswith('javascript:'):
                    continue
                if not link.startswith('http'):
                    link = urlparse.urljoin(url,link)
                import re
                p = '(type=ajax&method=(\w+)&{1})'
                m = re.search(p, link)
                method = 'get'
                if m:
                    link = link.replace(m.groups()[0], '')
                    method = m.groups()[1]
                url_data = UrlData(link.rstrip('?').rstrip('#'), method=method)
                # yield {link: url_data}
                yield url_data
        # 获取js事件并执行
        for tag, attr in self.tag_mouse_event_dict.iteritems():
            try:
                btn_eles = self.browser.find_by_xpath('//%s[@%s]' % (tag, attr))
            except Exception,e:
                print e
                btn_eles = []
            click_count = 0
            for btn in btn_eles:
                if click_count > 20:
                    break
                try:
                    if btn.visible:
                        btn.click()
                        click_count += 1
                        while True:

                            try:
                                alert = self.browser.get_alert()
                                if alert:
                                    alert.accept()
                                    time.sleep(0.2)
                            except NoAlertPresentException,e:
                                break
                            except Exception, e:
                                break
                            else:
                                continue
                        # tmp_url = self.browser.url
                        # url_data = UrlData(tmp_url.rstrip('?').rstrip('#'), method='get')
                        # yield {tmp_url: url_data}
                        # 从form取url, 并返回form表单填充值
                        form_elements = self.browser.find_by_tag('form')

                        for form_ele in form_elements:
                            url, url_data, fill_dict = self.get_url_by_form(form_ele)
                            # 对form表单进行值填充， 有些form表单有空值校验，不填充，无法触发js事件
                            if fill_dict:
                                # self.browser.fill_form(fill_dict)
                                pass
                            if url and url_data:
                                # yield {url: url_data}
                                yield url_data
                            else:
                                continue
                                # print url_data.url, url_data.post_data
                        for tag, attr in tag_attr_dict.iteritems():
                            link_list = self.browser.find_by_xpath('//%s[@%s]' % (tag,attr))

                            if not link_list:
                                continue
                            for link in link_list:
                                link = link.__getitem__(attr)
                                if not link:
                                    continue
                                link = link.strip()
                                if link == 'about:blank' or link.startswith('javascript:'):
                                    continue
                                if not link.startswith('http'):
                                    link = urlparse.urljoin(url,link)
                                import re
                                p = '(type=ajax&method=(\w+)&{1})'
                                m = re.search(p, link)
                                method = 'get'
                                if m:
                                    link = link.replace(m.groups()[0], '')
                                    method = m.groups()[1]
                                url_data = UrlData(link.rstrip('?').rstrip('#'), method=method)
                                # yield {link: url_data}
                                yield url_data
                except Exception, e:
                    print e
                    continue
                self.browser.back()
        # for tag, attr in self.tag_mouse_event_dict.iteritems():
        #     # 执行鼠标等js事件事件 参考事件字典 tag_mouse_event_dict
        #     js_elements = self.browser.find_by_xpath('//%s[@%s]' % (tag, attr))
        #     for js_element in js_elements:
        #         js = js_element.__getitem__(attr)
        #         if js:
        #             try:
        #                 self.browser.execute_script(str(js))
        #                 while True:
        #                     try:
        #                         alert = self.browser.get_alert()
        #                         if alert:
        #                             alert.accept()
        #                             time.sleep(0.5)
        #                     except NoAlertPresentException,e:
        #                         break
        #                     except Exception, e:
        #                         break
        #                     else:
        #                         continue
        #             except Exception:
        #                 continue

        # 执行自动提交事件，不包含js事件的
        # for tag_list in self.tag_auto_js_list:
        #     form_buttons = self.browser.find_by_xpath('//%s//%s[not(@%s)]' % (tag_list[0], tag_list[1], tag_list[2]))
        #     for button in form_buttons:
        #         try:
        #             button.click()
        #             while True:
        #                     try:
        #                         alert = self.browser.get_alert()
        #                         if alert:
        #                             alert.accept()
        #                             time.sleep(0.5)
        #                     except NoAlertPresentException,e:
        #                         break
        #                     else:
        #                         continue
        #         except Exception:
        #             continue


    def close(self):
        self.browser.quit()

    def get_url_by_form(self, form_ele):
        '''
        静态form的url及data获取
        :param form_ele:
        :return:
        '''
        try:
            action_url = form_ele.__getitem__('action')
            method = form_ele.__getitem__('method')
            # if not action_url:
            #     return None
            if not method:
                method = 'get'
            form_html_cont = form_ele.outer_html
            form_html = etree.HTML(form_html_cont)
            el_input_list = form_html.xpath('//input')
            post_data_list = []
            for el in el_input_list:
                input_dict = {'type': el.attrib.get('type'), 'name': el.attrib.get('name'), 'value': el.attrib.get('value')}
                post_data_list.append(input_dict)
            if 'get' == method:
                params, fill_dict = input_attrib2query(post_data_list)
                post_data_dict = {}
            else:
                post_data_dict, fill_dict = input_attrib2dict(post_data_list)
                params = json.dumps(post_data_list)
            if action_url:
                url_data = UrlData(action_url.rstrip('?').rstrip('#'), method=method, params=params, post_data=post_data_dict)
            else:
                url_data = None
            # print 1, action_url, 2, url_data, 3, fill_dict
            return action_url, url_data, fill_dict
        except Exception,e:
            action_url=None
            url_data=None
            fill_dict = None
            return action_url, url_data, fill_dict


def input_attrib2dict(body_list):
    '''
    将post请求的params转换成key-value字典
    [{"type":"submit","name":"seclev_submit","value":"Submit"},{"type":"select","name":"security","value":"low"}]
    ==>
    {"security":"low"}
    :param input_attrib: 字典构成的列表
    :return: 转换后的params，字典
    '''
    try:

        body_dict = {}
        fill_dict = {}
        for body in body_list:
            # if body["type"] != "submit":
            body_dict[body["name"]] = body["value"]
            fill_dict[body["name"]] = fill_form_dict.get(body["type"], 'fill_value')
        return body_dict, fill_dict
    except Exception, e:
        return {}


def input_attrib2query(body_list):
    '''
    将FORM的params转换成QUERY String
    [{"type":"submit","name":"seclev_submit","value":"Submit"},{"type":"select","name":"security","value":"low"}]
    ==>"security=low"
    :param input_attrib: 字典构成的列表
    :return: QUERY String
    '''
    try:

        query_str = ''
        fill_dict = {}
        for body in body_list:
            # if body["type"] != "submit":  # (改成不去掉submit 20170803)
            if body["value"]:
                query_str += '&%s=%s' % (body["name"],body["value"])
            else:
                query_str += '&%s=' % (body["name"])
            fill_dict[body["name"]] = fill_form_dict.get(body["type"], 'fill_value')
        query_str = query_str.lstrip('&')
        return query_str, fill_dict
    except Exception, e:
        return None, None


def get_url_ajax(ajax):
    '''
    通过正则获取ajax的url，但无法获取参数值
    :param ajax:
    :return:
    '''
    m_url = re.search('url\s*\:\s*([\"|/|\w|\+|\s]+),?', ajax, re.I|re.M|re.S)
    url_tmp = m_url.groups()[0]
    if re.search('\+', url_tmp):
        url_tmp = ''.join(url_tmp.split('+'))
    url = url_tmp.replace('\"', '').replace('\'', '').replace(' ', '')
    m_type = re.search('type\s*\:\s*\"?([/|\w|\+]+)\"?\s*,?', ajax, re.I|re.M|re.S)
    method = m_type.groups()[0]
    return url, method