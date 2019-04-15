# --*-- coding: utf-8 --*--
# pdf 生成类
# reportlab坐标系
#            y
#            |
#            |  页面在这里
#-x ------0-----------> x
#            |
#            |
#           -y
# A4纸 尺寸为 210mm*297mm
# 书写说明，为了更好的确认每个元素在页面中的位置，pdf统一使用 mm 单位，即单页PDF 宽210mm 高297mm
# 在代码中为了便于识别所有的位置变量，统一使用 Pleft 代表左侧x轴，Pright代表右侧x轴，Pheader代表顶部y轴，Pfooter代表底部y轴
# Pleft:10mm Pright:200mm Pheader:287mm Pfooter:10mm
__author__ = 'lidq'

from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.styles import getSampleStyleSheet   
from reportlab.rl_config import defaultPageSize   
from reportlab.lib.units import mm
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.graphics import renderPDF
from reportlab.graphics.charts.barcharts import VerticalBarChart
import json, sys
from config import WEBROOT, STRSPIT

#from data import formatResult
#from __future__ import division

#FONT_PATH = './wqy-zenhei.ttc'
#INDEX_ICON = './yundun_icon.jpg'
FONT_PATH = WEBROOT + STRSPIT + "app" + STRSPIT + "static" + STRSPIT + "font" + STRSPIT + "wqy-zenhei.ttc"
INDEX_ICON = WEBROOT + STRSPIT + "app" + STRSPIT + "static" + STRSPIT + "img" + STRSPIT + "yundun_icon.jpg"

START_X = 0*mm
START_Y = 0*mm
INDEX_TITLE = "安全漏洞扫报告"
INDEX_TITLE_TIME = "扫描时间:2016-08-08"
INDEX_TITLE_SUPPORT = "技术支持:上海云盾信息技术有限公司"
PAGE_TITLE = "安全漏洞扫描报告"
PAGE_FOOTER = "本报告由上海云盾信息技术有限公司生成,如果您对报告有任何疑问,可联系:021-60310101"

class PdfFactory():

    def scanPdf(self, filename, params):
        self.scanParams = params
        c = canvas.Canvas(filename)

        # page 1
        self.__resetEnv(c)
        self.__drawHeadFooter(c)
        self.__drawPage1(c)
        c.showPage()

        # page 2
        self.__resetEnv(c)
        self.__drawHeadFooter(c)
        self.__drawPage2(c)
        c.showPage()

        # page 3
        self.__resetEnv(c)
        self.__drawHeadFooter(c)
        self.__drawPage3(c)
        c.showPage()
        c.save()

    #初始化环境，当有分页时，每个分页需要初始化新的环境
    def __resetEnv(self, c):
        pdfmetrics.registerFont(TTFont('song', FONT_PATH))
        c.setFont('song', 10)

    def __drawHeadFooter(self, c):
        # 顶部及底部高度各为10mm,左右两边距各为10mm Pleft:10mm Pright:200mm Pheader:287mm Pfooter:10mm
        Pleft = START_X + 10*mm
        Pright = START_X + 200*mm
        Pheader = START_Y + 287*mm
        Pfooter = START_Y + 10*mm
        c.drawString(Pright -40*mm, Pheader + 2*mm, PAGE_TITLE)
        c.line(Pleft, Pheader, Pright, Pheader)
        c.line(Pleft, Pfooter, Pright, Pfooter)
        c.drawString(Pleft + 25*mm, Pfooter - 3*mm, PAGE_FOOTER)

    def __drawPage1(self, c):
        # 首页只有标题，时间，图标等内容，所有内容书写范围为Pleft:50mm Pright:160mm Pheader:247mm Pfooter:40mm    图标宽高为100＊150
        Pleft = START_X + 50*mm
        Pright = START_X + 160*mm
        Pheader = START_Y + 247*mm
        Pfooter = START_Y + 40*mm
        ICON_W =  100
        ICON_H = 150
        c.setFont("song", 20)
        c.drawString(Pleft + 35*mm, Pheader - 50*mm, INDEX_TITLE)
        c.setFont("song", 10)
        c.drawString(Pleft + 45*mm, Pheader - 55*mm, INDEX_TITLE_TIME)
        c.drawImage(INDEX_ICON, Pleft + 40*mm, Pheader - 120*mm, ICON_W, ICON_H)
        c.drawString(Pleft + 30*mm, Pheader - 150*mm, INDEX_TITLE_SUPPORT)

    def __drawPage2(self, c):
        # 第二页，内容部署，所有内容书写范围为Pleft:10mm Pright:200mm Pheader:287mm Pfooter:10mm
        Pleft = START_X + 10*mm
        Pright = START_X + 200*mm
        Pheader = START_Y + 287*mm
        Pfooter = START_Y + 10*mm
        c.setFillColorRGB(0,0,1)
        c.rect(Pleft, Pheader - 10*mm, 2*mm, 10*mm, fill=1)
        c.setFont("song", 15)
        c.drawString(Pleft + 5*mm, Pheader - 7*mm, "1. 扫描报告摘要")
        c.setStrokeColorRGB(0.1, 0.1, 0.2)
        c.line(Pleft, Pheader - 10*mm, Pright, Pheader - 10*mm)
        c.setFont("song", 10)
        c.drawString(Pleft, Pheader - 20*mm, "扫描目标:" + self.scanParams['domain'])
        c.drawString(Pleft, Pheader - 25*mm, "发起扫描时间:" + self.scanParams['start_time'])
        c.drawString(Pleft, Pheader - 30*mm, "扫描完成时间:" + self.scanParams['end_time'])

        # 1
        startx = Pleft + 70*mm
        c.setFillGray(0.8)
        c.rect(startx, Pheader - 30*mm, 15*mm, 15*mm, fill=1)
        c.setFont("song", 9)
        c.setFillColorRGB(1, 0, 1)
        c.drawString(startx + 3*mm, Pheader - 20*mm, str(len(self.scanParams['results']['HIGH']) + len(self.scanParams['results']['MED']) + len(self.scanParams['results']['LOW'])))
        c.drawString(startx + 1*mm, Pheader - 28*mm, "漏洞总数")

        # 2
        startx = startx + 20*mm
        c.setFillGray(0.8)
        c.rect(startx, Pheader - 30*mm, 15*mm, 15*mm, fill=1)
        c.setFont("song", 9)
        c.setFillColorRGB(1, 0, 1)
        c.drawString(startx + 3*mm, Pheader - 20*mm, "26")
        c.drawString(startx + 2*mm, Pheader - 24*mm, "OWASP")
        c.drawString(startx + 3*mm, Pheader - 28*mm, "Top10")

        # 3
        startx = startx + 20*mm
        c.setFillGray(0.8)
        c.rect(startx, Pheader - 30*mm, 15*mm, 15*mm, fill=1)
        c.setFont("song", 9)
        c.setFillColorRGB(1, 0, 1)
        c.drawString(startx + 3*mm, Pheader - 20*mm, str(len(self.scanParams['results']['HIGH'])))
        c.drawString(startx + 3*mm, Pheader - 28*mm, "高危")

        # 4
        startx = startx + 20*mm
        c.setFillGray(0.8)
        c.rect(startx, Pheader - 30*mm, 15*mm, 15*mm, fill=1)
        c.setFont("song", 9)
        c.setFillColorRGB(1, 0, 1)
        c.drawString(startx + 3*mm, Pheader - 20*mm, str(len(self.scanParams['results']['MED'])))
        c.drawString(startx + 3*mm, Pheader - 28*mm, "中危")

        # 5
        startx = startx + 20*mm
        c.setFillGray(0.8)
        c.rect(startx, Pheader - 30*mm, 15*mm, 15*mm, fill=1)
        c.setFont("song", 9)
        c.setFillColorRGB(1, 0, 1)
        c.drawString(startx + 3*mm, Pheader - 20*mm, str(len(self.scanParams['results']['LOW'])))
        c.drawString(startx + 3*mm, Pheader - 28*mm, "低危")

        #6
        startx = startx + 20*mm
        c.setFillGray(0.8)
        c.rect(startx, Pheader - 30*mm, 15*mm, 15*mm, fill=1)
        c.setFont("song", 9)
        c.setFillColorRGB(1, 0, 1)
        c.drawString(startx + 3*mm, Pheader - 20*mm, "26")
        c.drawString(startx + 3*mm, Pheader - 28*mm, "信息")

        # left pie
        self.__drawPage2LeftPie(c)

        # right owasp
        self.__drawPage2Owasp(c)

        # bottom group
        self.__drawPage2Group(c)

    # left Pie
    def __drawPage2LeftPie(self, c):
        totalHigh = len(self.scanParams['results']['HIGH'])
        totalMed = len(self.scanParams['results']['MED'])
        totalLow = len(self.scanParams['results']['LOW'])
	total = totalHigh + totalMed + totalLow

        # 第二页，左侧饼图，所有内容书写范围为Pleft:10mm Pright:100mm Pheader:247mm Pfooter:80mm
        Pleft = START_X + 10*mm
        Pright = START_X + 100*mm
        Pheader = START_Y + 247*mm
        Pfooter = START_Y + 80*mm

        #矩形框
        c.rect(Pleft, Pheader-80*mm, 80*mm, 80*mm, fill=0)
        c.setFont("song", 15)
        c.drawString(Pleft + 2*mm, Pheader - 10*mm, "漏洞等级分布")

        #饼图
        d = Drawing(400, 200)
        pc = Pie()
        pc.x = 65
        pc.y = 15
        pc.width = 70
        pc.height = 70
        pc.data = [totalHigh, totalMed, totalLow]
        pc.labels = ['高危','中危','低危']
        pc.sideLabels = 1
        pc.slices.strokeWidth=0.5
        for i in range(3):
            pc.slices[i].fontName = 'song'
        #pc.slices[1].fontColor = colors.red
        pc.slices[1].fillColor = colors.red
        d.add(pc)
        #添加饼图到画布
        renderPDF.draw(d, c, Pleft + 6*mm, Pheader - 55*mm)

        #底部标注
        c.rect(Pleft + 5 * mm, Pheader - 75*mm, 70*mm, 8*mm, fill=0)
        c.setFont("song", 7)
        c.circle(Pleft + 8*mm, Pheader - 71*mm, 2*mm, fill=1)
        c.drawString(Pleft + 11*mm, Pheader - 72*mm, "高危(" + str(round((totalHigh/float(total))*100, 1)) + "%)")

        c.circle(Pleft + 28*mm, Pheader - 71*mm, 2*mm, fill=1)
        c.drawString(Pleft + 31*mm, Pheader - 72*mm, "中危(" + str(round((totalMed/float(total))*100, 1)) + "%)")

        c.circle(Pleft + 48*mm, Pheader - 71*mm, 2*mm, fill=1)
        c.drawString(Pleft + 51*mm, Pheader - 72*mm, "低危(" + str(round((totalLow/float(total))*100, 1)) + "%)")

    def __drawPage2Owasp(self, c):
        # 第二页，右侧OWASP图，所有内容书写范围为Pleft:120mm Pright:200mm Pheader:247mm Pfooter:80mm
        Pleft = START_X + 100*mm
        Pright = START_X + 200*mm
        Pheader = START_Y + 247*mm
        Pfooter = START_Y + 80*mm
        c.setFillColorRGB(1, 1, 1)
        c.rect(Pleft, Pheader -80*mm, 100*mm, 80*mm, fill = 1)
        c.setFont("song", 15)
        c.setFillColorRGB(1, 0, 1)
        c.drawString(Pleft + 2*mm, Pheader - 10*mm, "OWASP TOP10占比分布")

        d = Drawing(300, 200)
        data = [(13, 5, 20, 22, 37, 45, 19, 4, 5, 10)]
        bc = VerticalBarChart()
        bc.x = 50
        bc.y = 50
        bc.height = 130
        bc.width = 180
        bc.data = data
        bc.strokeColor = colors.black
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = 50
        bc.valueAxis.valueStep = 10
        bc.categoryAxis.labels.boxAnchor = 'ne'
        bc.categoryAxis.labels.dx = 8
        bc.categoryAxis.labels.dy = -2
        bc.categoryAxis.labels.angle = 30
        bc.categoryAxis.categoryNames = ['1.SQL注入','2.失效的身份认证和会话管理','3.跨站脚本(XSS)', '4.不安全的直接引用对象','5.安全配置错误','6.敏感信息泄漏','功能级访问控制缺失','8.跨站请求伪造(CSRF)','9.使用含有已知漏洞的组件', '10.未验证的重定向和转发']
        bc.categoryAxis.labels.fontName = 'song'
        bc.categoryAxis.labels.fontSize = 5
        d.add(bc)
        renderPDF.draw(d, c, Pleft + 2*mm, Pheader - 80*mm)

    def __drawPage2Group(self, c):
        # 第二页，下方柱状图，所有内容书写范围为Pleft:10mm Pright:200mm Pheader:187mm Pfooter:10mm
        Pleft = START_X + 10*mm
        Pright = START_X + 200*mm
        Pheader = START_Y + 187*mm
        Pfooter = START_Y + 10*mm
        c.setFillColorRGB(1, 1, 1)
        c.rect(Pleft, Pheader-160*mm, 190*mm, 120*mm, fill = 1)
        c.setFont("song", 15)
        c.setFillColorRGB(1, 0, 1)
        c.drawString(Pleft + 3*mm, Pheader - 50*mm, "漏洞信息分组")

        a=[]
        familyids=[]
        for familyid in self.scanParams['statsFamily']:
            a.append(self.scanParams['statsFamily'][familyid]['total'])
            familyids.append(str(familyid))
        print a,familyids
        d = Drawing(400, 300)
        data = [a]
        bc = VerticalBarChart()
        bc.x = 50
        bc.y = 50
        bc.height = 245
        bc.width = 400
        bc.data = data
        bc.strokeColor = colors.black
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = 5
        bc.valueAxis.valueStep = 1
        bc.categoryAxis.labels.boxAnchor = 'ne'
        bc.categoryAxis.labels.dx = 8
        bc.categoryAxis.labels.dy = -2
        bc.categoryAxis.labels.angle = 30
        bc.categoryAxis.categoryNames = familyids
        bc.categoryAxis.labels.fontName = 'song'
        bc.categoryAxis.labels.fontSize = 10
        d.add(bc)
        renderPDF.draw(d, c, Pleft + 10*mm, Pheader - 160*mm)

    def __drawPage3(self, c):
        # 第二页，内容部署，所有内容书写范围为Pleft:10mm Pright:200mm Pheader:287mm Pfooter:10mm
        Pleft = START_X + 10*mm
        Pright = START_X + 200*mm
        Pheader = START_Y + 287*mm
        Pfooter = START_Y + 10*mm
        distance = 10*mm

        i = 1
        c.setFillColorRGB(1, 1, 1)
        c.rect(Pleft, Pheader - i*distance, 190*mm, 10*mm, fill=1)
        c.setFont("song", 10)
        c.setFillColorRGB(0, 0, 0)
        c.drawString(Pleft + 90*mm, Pheader - i*distance + 2*mm, "漏洞列表")
	i += 1
        c.setFillColorRGB(1, 1, 1)
        c.rect(Pleft, Pheader - i*distance, 190*mm, 10*mm, fill=1)
        c.setFont("song", 10)
        c.setFillColorRGB(0, 0, 0)
        c.drawString(Pleft + 10*mm, Pheader - i*distance + 2*mm, "漏洞名称")
        c.drawString(Pleft + 90*mm, Pheader - i*distance + 2*mm, "数量")

	for familyid in self.scanParams['statsFamily']:
	    i += 1
            c.setFillColorRGB(1, 1, 1)
            c.rect(Pleft, Pheader - i * distance, 190*mm, 10*mm, fill=1)
            c.setFont("song", 10)
            c.setFillColorRGB(0, 0, 0)
            c.drawString(Pleft + 10*mm, Pheader - i * distance + 2*mm, str(familyid) + ". " + self.scanParams['statsFamily'][familyid]['family'])
            c.drawString(Pleft + 90*mm, Pheader - i * distance + 2*mm, str(self.scanParams['statsFamily'][familyid]['total']))

if __name__ == "__main__":
    filename="./pdf_ok.pdf"
    pdf = PdfFactory()
    pdf.scanPdf(filename, formatResult)

