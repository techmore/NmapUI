from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS  # Import the CORS class
from datetime import datetime
import subprocess
import re
import json
import ipaddress
import socket
import threading  # Import threading for concurrent scanning
#from scapy.all import *
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import netifaces as ni
import requests
from ipaddress import ip_network
#from generate_report import generate_pdf
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Image
from PIL import Image as PILImage
from reportlab.pdfgen import canvas
from reportlab.platypus import (SimpleDocTemplate, Paragraph, PageBreak, Image, Spacer, Table, TableStyle)
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER, TA_JUSTIFY
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.pagesizes import LETTER, inch
from reportlab.graphics.shapes import Line, LineShape, Drawing
from reportlab.lib.colors import Color


class FooterCanvas(canvas.Canvas):

    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self.pages = []
        self.width, self.height = LETTER

    def showPage(self):
        self.pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self.pages)
        for page in self.pages:
            self.__dict__.update(page)
            if (self._pageNumber > 1):
                self.draw_canvas(page_count)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_canvas(self, page_count):
        page = "Page %s of %s" % (self._pageNumber, page_count)
        x = 128
        self.saveState()
        self.setStrokeColorRGB(0, 0, 0)
        self.setLineWidth(0.5)
        self.drawImage("static/techmore.png", self.width-inch*8-5, self.height-50, width=100, height=20, preserveAspectRatio=True)
        self.drawImage("static/techmore.png", self.width - inch * 2, self.height-50, width=100, height=30, preserveAspectRatio=True, mask='auto')
        self.line(30, 740, LETTER[0] - 50, 740)
        self.line(66, 78, LETTER[0] - 66, 78)
        self.setFont('Times-Roman', 10)
        self.drawString(LETTER[0]-x, 65, page)
        self.restoreState()

class PDFPSReporte:

    def __init__(self, path):
        self.path = path
        self.styleSheet = getSampleStyleSheet()
        self.elements = []

        # colors - Azul turkeza 367AB3
        self.colorOhkaGreen0 = Color((45.0/255), (166.0/255), (153.0/255), 1)
        self.colorOhkaGreen1 = Color((182.0/255), (227.0/255), (166.0/255), 1)
        self.colorOhkaGreen2 = Color((140.0/255), (222.0/255), (192.0/255), 1)
        #self.colorOhkaGreen2 = Color((140.0/255), (222.0/255), (192.0/255), 1)
        self.colorOhkaBlue0 = Color((54.0/255), (122.0/255), (179.0/255), 1)
        self.colorOhkaBlue1 = Color((122.0/255), (180.0/255), (225.0/255), 1)
        self.colorOhkaGreenLineas = Color((50.0/255), (140.0/255), (140.0/255), 1)

        self.firstPage()
        self.nextPagesHeader(True)
        self.remoteSessionTableMaker()
        self.nextPagesHeader(False)
        self.inSiteSessionTableMaker()
        self.nextPagesHeader(False)
        self.extraActivitiesTableMaker()
        self.nextPagesHeader(False)
        self.summaryTableMaker()
        # Build
        self.doc = SimpleDocTemplate(path, pagesize=LETTER)
        self.doc.multiBuild(self.elements, canvasmaker=FooterCanvas)

    def firstPage(self):
        img = Image('static/techmore.png', kind='proportional')
        img.drawHeight = 0.5*inch
        img.drawWidth = 2.4*inch
        img.hAlign = 'LEFT'
        self.elements.append(img)

        spacer = Spacer(30, 100)
        self.elements.append(spacer)

        img = Image('static/techmore.png')
        img.drawHeight = 2.5*inch
        img.drawWidth = 5.5*inch
        self.elements.append(img)

        spacer = Spacer(10, 250)
        self.elements.append(spacer)

        psDetalle = ParagraphStyle('Resumen', fontSize=9, leading=14, justifyBreaks=1, alignment=TA_LEFT, justifyLastLine=1)
        current_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        text = """Internal Network Vulnerability Scan<br/>
        Nmap, Vulners<br/>
        Timestamp: {current_timestamp}<br/>
        """
        paragraphReportSummary = Paragraph(text, psDetalle)
        self.elements.append(paragraphReportSummary)
        self.elements.append(PageBreak())

    def nextPagesHeader(self, isSecondPage):
        if isSecondPage:
            psHeaderText = ParagraphStyle('Hed0', fontSize=16, alignment=TA_LEFT, borderWidth=3, textColor=self.colorOhkaGreen0)
            text = 'IP addresses and summary'
            paragraphReportHeader = Paragraph(text, psHeaderText)
            self.elements.append(paragraphReportHeader)

            spacer = Spacer(10, 10)
            self.elements.append(spacer)

            d = Drawing(500, 1)
            line = Line(-15, 0, 483, 0)
            line.strokeColor = self.colorOhkaGreenLineas
            line.strokeWidth = 2
            d.add(line)
            self.elements.append(d)

            spacer = Spacer(10, 1)
            self.elements.append(spacer)

            d = Drawing(500, 1)
            line = Line(-15, 0, 483, 0)
            line.strokeColor = self.colorOhkaGreenLineas
            line.strokeWidth = 0.5
            d.add(line)
            self.elements.append(d)

            spacer = Spacer(10, 22)
            self.elements.append(spacer)

    def remoteSessionTableMaker(self):        
        psHeaderText = ParagraphStyle('Hed0', fontSize=12, alignment=TA_LEFT, borderWidth=3, textColor=self.colorOhkaBlue0)
        text = 'SESIONES REMOTAS'
        paragraphReportHeader = Paragraph(text, psHeaderText)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 22)
        self.elements.append(spacer)
        """
        Create the line items
        """
        d = []
        textData = ["IP", "Hostname", "Open Ports", "Version", "CVE"]
                
        fontSize = 8
        centered = ParagraphStyle(name="centered", alignment=TA_CENTER)
        for text in textData:
            ptext = "<font size='%s'><b>%s</b></font>" % (fontSize, text)
            titlesTable = Paragraph(ptext, centered)
            d.append(titlesTable)        

        data = [d]
        lineNum = 1
        formattedLineData = []

        alignStyle = [ParagraphStyle(name="01", alignment=TA_CENTER),
                      ParagraphStyle(name="02", alignment=TA_LEFT),
                      ParagraphStyle(name="03", alignment=TA_CENTER),
                      ParagraphStyle(name="04", alignment=TA_CENTER),
                      ParagraphStyle(name="05", alignment=TA_CENTER)]

        for row in range(10):
            lineData = [str(lineNum), "Miércoles, 11 de diciembre de 2019", 
                                            "17:30", "19:24", "1:54"]
            #data.append(lineData)
            columnNumber = 0
            for item in lineData:
                ptext = "<font size='%s'>%s</font>" % (fontSize-1, item)
                p = Paragraph(ptext, alignStyle[columnNumber])
                formattedLineData.append(p)
                columnNumber = columnNumber + 1
            data.append(formattedLineData)
            formattedLineData = []
            
        # Row for total
        totalRow = ["Total de Horas", "", "", "", "30:15"]
        for item in totalRow:
            ptext = "<font size='%s'>%s</font>" % (fontSize-1, item)
            p = Paragraph(ptext, alignStyle[1])
            formattedLineData.append(p)
        data.append(formattedLineData)
        
        #print(data)
        table = Table(data, colWidths=[50, 200, 80, 80, 80])
        tStyle = TableStyle([ #('GRID',(0, 0), (-1, -1), 0.5, grey),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                #('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ("ALIGN", (1, 0), (1, -1), 'RIGHT'),
                ('LINEABOVE', (0, 0), (-1, -1), 1, self.colorOhkaBlue1),
                ('BACKGROUND',(0, 0), (-1, 0), self.colorOhkaGreenLineas),
                ('BACKGROUND',(0, -1),(-1, -1), self.colorOhkaBlue1),
                ('SPAN',(0,-1),(-2,-1))
                ])
        table.setStyle(tStyle)
        self.elements.append(table)

    def inSiteSessionTableMaker(self):
        self.elements.append(PageBreak())
        psHeaderText = ParagraphStyle('Hed0', fontSize=12, alignment=TA_LEFT, borderWidth=3, textColor=self.colorOhkaBlue0)
        text = 'SESIONES EN SITIO'
        paragraphReportHeader = Paragraph(text, psHeaderText)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 22)
        self.elements.append(spacer)
        """
        Create the line items
        """
        d = []
        textData = ["No.", "Fecha", "Hora Inicio", "Hora Fin", "Tiempo Total"]
                
        fontSize = 8
        centered = ParagraphStyle(name="centered", alignment=TA_CENTER)
        for text in textData:
            ptext = "<font size='%s'><b>%s</b></font>" % (fontSize, text)
            titlesTable = Paragraph(ptext, centered)
            d.append(titlesTable)        

        data = [d]
        lineNum = 1
        formattedLineData = []

        alignStyle = [ParagraphStyle(name="01", alignment=TA_CENTER),
                      ParagraphStyle(name="02", alignment=TA_LEFT),
                      ParagraphStyle(name="03", alignment=TA_CENTER),
                      ParagraphStyle(name="04", alignment=TA_CENTER),
                      ParagraphStyle(name="05", alignment=TA_CENTER)]

        for row in range(10):
            lineData = [str(lineNum), "Miércoles, 11 de diciembre de 2019", 
                                            "17:30", "19:24", "1:54"]
            #data.append(lineData)
            columnNumber = 0
            for item in lineData:
                ptext = "<font size='%s'>%s</font>" % (fontSize-1, item)
                p = Paragraph(ptext, alignStyle[columnNumber])
                formattedLineData.append(p)
                columnNumber = columnNumber + 1
            data.append(formattedLineData)
            formattedLineData = []
            
        # Row for total
        totalRow = ["Total de Horas", "", "", "", "30:15"]
        for item in totalRow:
            ptext = "<font size='%s'>%s</font>" % (fontSize-1, item)
            p = Paragraph(ptext, alignStyle[1])
            formattedLineData.append(p)
        data.append(formattedLineData)
        
        #print(data)
        table = Table(data, colWidths=[50, 200, 80, 80, 80])
        tStyle = TableStyle([ #('GRID',(0, 0), (-1, -1), 0.5, grey),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                #('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ("ALIGN", (1, 0), (1, -1), 'RIGHT'),
                ('LINEABOVE', (0, 0), (-1, -1), 1, self.colorOhkaBlue1),
                ('BACKGROUND',(0, 0), (-1, 0), self.colorOhkaGreenLineas),
                ('BACKGROUND',(0, -1),(-1, -1), self.colorOhkaBlue1),
                ('SPAN',(0,-1),(-2,-1))
                ])
        table.setStyle(tStyle)
        self.elements.append(table)

    def extraActivitiesTableMaker(self):
        self.elements.append(PageBreak())
        psHeaderText = ParagraphStyle('Hed0', fontSize=12, alignment=TA_LEFT, borderWidth=3, textColor=self.colorOhkaBlue0)
        text = 'OTRAS ACTIVIDADES Y DOCUMENTACIÓN'
        paragraphReportHeader = Paragraph(text, psHeaderText)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 22)
        self.elements.append(spacer)
        """
        Create the line items
        """
        d = []
        textData = ["No.", "Fecha", "Hora Inicio", "Hora Fin", "Tiempo Total"]
                
        fontSize = 8
        centered = ParagraphStyle(name="centered", alignment=TA_CENTER)
        for text in textData:
            ptext = "<font size='%s'><b>%s</b></font>" % (fontSize, text)
            titlesTable = Paragraph(ptext, centered)
            d.append(titlesTable)        

        data = [d]
        lineNum = 1
        formattedLineData = []

        alignStyle = [ParagraphStyle(name="01", alignment=TA_CENTER),
                      ParagraphStyle(name="02", alignment=TA_LEFT),
                      ParagraphStyle(name="03", alignment=TA_CENTER),
                      ParagraphStyle(name="04", alignment=TA_CENTER),
                      ParagraphStyle(name="05", alignment=TA_CENTER)]

        for row in range(10):
            lineData = [str(lineNum), "Miércoles, 11 de diciembre de 2019", 
                                            "17:30", "19:24", "1:54"]
            #data.append(lineData)
            columnNumber = 0
            for item in lineData:
                ptext = "<font size='%s'>%s</font>" % (fontSize-1, item)
                p = Paragraph(ptext, alignStyle[columnNumber])
                formattedLineData.append(p)
                columnNumber = columnNumber + 1
            data.append(formattedLineData)
            formattedLineData = []
            
        # Row for total
        totalRow = ["Total de Horas", "", "", "", "30:15"]
        for item in totalRow:
            ptext = "<font size='%s'>%s</font>" % (fontSize-1, item)
            p = Paragraph(ptext, alignStyle[1])
            formattedLineData.append(p)
        data.append(formattedLineData)
        
        #print(data)
        table = Table(data, colWidths=[50, 200, 80, 80, 80])
        tStyle = TableStyle([ #('GRID',(0, 0), (-1, -1), 0.5, grey),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                #('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ("ALIGN", (1, 0), (1, -1), 'RIGHT'),
                ('LINEABOVE', (0, 0), (-1, -1), 1, self.colorOhkaBlue1),
                ('BACKGROUND',(0, 0), (-1, 0), self.colorOhkaGreenLineas),
                ('BACKGROUND',(0, -1),(-1, -1), self.colorOhkaBlue1),
                ('SPAN',(0,-1),(-2,-1))
                ])
        table.setStyle(tStyle)
        self.elements.append(table)

    def summaryTableMaker(self):
        self.elements.append(PageBreak())
        psHeaderText = ParagraphStyle('Hed0', fontSize=12, alignment=TA_LEFT, borderWidth=3, textColor=self.colorOhkaBlue0)
        text = 'REGISTRO TOTAL DE HORAS'
        paragraphReportHeader = Paragraph(text, psHeaderText)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 22)
        self.elements.append(spacer)
        """
        Create the line items
        """

        tStyle = TableStyle([
                   ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                   #('VALIGN', (0, 0), (-1, -1), 'TOP'),
                   ("ALIGN", (1, 0), (1, -1), 'RIGHT'),
                   ('LINEABOVE', (0, 0), (-1, -1), 1, self.colorOhkaBlue1),
                   ('BACKGROUND',(-2, -1),(-1, -1), self.colorOhkaGreen2)
                   ])

        fontSize = 8
        lineData = [["Sesiones remotas", "30:15"],
                    ["Sesiones en sitio", "00:00"],
                    ["Otras actividades", "00:00"],
                    ["Total de horas consumidas", "30:15"]]

        # for row in lineData:
        #     for item in row:
        #         ptext = "<font size='%s'>%s</font>" % (fontSize-1, item)
        #         p = Paragraph(ptext, centered)
        #         formattedLineData.append(p)
        #     data.append(formattedLineData)
        #     formattedLineData = []

        table = Table(lineData, colWidths=[400, 100])
        table.setStyle(tStyle)
        self.elements.append(table)

        # Total de horas contradas vs horas consumidas
        data = []
        formattedLineData = []

        lineData = [["Total de horas contratadas", "120:00"],
                    ["Horas restantes por consumir", "00:00"]]

        # for row in lineData:
        #     for item in row:
        #         ptext = "<b>{}</b>".format(item)
        #         p = Paragraph(ptext, self.styleSheet["BodyText"])
        #         formattedLineData.append(p)
        #     data.append(formattedLineData)
        #     formattedLineData = []

        table = Table(lineData, colWidths=[400, 100])
        tStyle = TableStyle([
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ("ALIGN", (1, 0), (1, -1), 'RIGHT'),
                ('BACKGROUND', (0, 0), (1, 0), self.colorOhkaBlue1),
                ('BACKGROUND', (0, 1), (1, 1), self.colorOhkaGreen1),
                ])
        table.setStyle(tStyle)

        spacer = Spacer(10, 50)
        self.elements.append(spacer)
        self.elements.append(table)


def generate_pdf():
    # Create a PDF document
    pdf = SimpleDocTemplate(
        "report.pdf",
        pagesize=letter
    )
    # Styles
    styles = getSampleStyleSheet()
    styleN = styles["BodyText"]
    styleH = styles["Heading1"]

    # Add a title
    title = Paragraph("My ReportLab PDF", styleH)

    # Add some text
    text = Paragraph("This is a sample PDF generated using ReportLab.", styleN)

    # Create a table
    data = [
        ["#", "Name", "Age"],
        ["1", "Alice", "28"],
        ["2", "Bob", "34"],
        ["3", "Charlie", "22"]
    ]

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    # Add an image
    #img_path = "path/to/your/image.jpg"
    #pil_img = PILImage.open(img_path)
    #img_width, img_height = pil_img.size
    #aspect = img_height / float(img_width)
    #img = Image(img_path, width=2*inch, height=(2*inch * aspect))

    # Add elements to PDF
    #elements = [title, text, table, img]
    elements = [title, text, table]
    # Generate PDF
    pdf.build(elements)

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app)

# Initialize Chrome options
chrome_options = Options()
chrome_options.add_argument("--headless")
#driver = webdriver.Chrome(options=chrome_options)

# Define the root route to serve the HTML page
@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('get_local_ip')
def get_local_ip():
    try:
        local_ip = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']
        subnet_mask = ni.ifaddresses('en0')[ni.AF_INET][0]['netmask']
        public_ip = requests.get('https://api.ipify.org').text
        cidr = calculate_cidr(local_ip, subnet_mask)
        emit('local_ip', {'local_ip': local_ip, 'subnet_mask': subnet_mask, 'public_ip': public_ip, 'cidr': cidr})

    except Exception as e:
        emit('scan_error', str(e))

def calculate_cidr(ip, subnet_mask):
    # Convert subnet mask to CIDR prefix length
    cidr_prefix = sum(bin(int(x)).count('1') for x in subnet_mask.split('.'))
    
    # Calculate network address
    ip_nodes = list(map(int, ip.split('.')))
    mask_nodes = list(map(int, subnet_mask.split('.')))
    network_address_nodes = [str(ip_nodes[i] & mask_nodes[i]) for i in range(4)]
    network_address = '.'.join(network_address_nodes)
    
    # Create CIDR notation
    cidr = f"{network_address}/{cidr_prefix}"

    return cidr

def start_deep_scan(targets):
    try:
        for target in targets:
            # Run the Nmap scan and capture the output
            print(f"nmap -T3 -sV {target} ...")
            screenshot_ports = []  # To keep track of ports to screenshot
            output = subprocess.check_output(['nmap', '-T3', '-sV', '--script', '/Users/seandolbec/projects/streamio-nmap/nmap-vulners/vulners', target]).decode('utf-8')
            # Create an IP packet with specific TTL (Time To Live) value
            driver = webdriver.Chrome(options=chrome_options)
            cve_array = []
            parsed_data = []
            lines = output.split('\n')
            current_host = None
            cve_pattern = re.compile(r"CVE-\d{4}-\d+\s+(\d+\.\d+)\s+(https://vulners\.com/cve/CVE-\d{4}-\d+)")
            pattern = re.compile(r"Nmap done: (\d+) IP address \((\d+) host up\) scanned in ([\d.]+) seconds")

            last_seen_port = None  # To keep track of the last seen port

            for line in lines:
                #print("line: "+ line)
                if "Nmap scan report for" in line:
                    if current_host:
                        parsed_data.append(current_host)
                    current_host = {'ip': line.split(' ')[-1], 'ports': []} 
                elif "/tcp" in line:
                    port_info = re.search(r'(\d+)/tcp\s+(\w+)\s+(.*)', line)
                    if port_info:
                        last_seen_port = port_info.group(1)  # Update the last seen port
                        port, state, service = port_info.groups()[:3]
                        #print("Port found : " + target + ":" + port)
                        # Make ASYNC
                        #try:
                        #    driver.get(f'http://{target}:{port}')
                        #    driver.save_screenshot(f'{target}_port_{port}.png')
                        #except Exception as e:
                        #    emit('screenshot', str(e))
                        current_host['ports'].append({'port': port, 'state': state, 'service': service})
                elif "Service Info: " in line:
                    trimmed_line = line.replace("Service Info: ", "")
                    emit('service_info', {'target':target, 'line': trimmed_line})
                    #print ("Service info : " + line)
                #elif "cpe" in line:
                    #print("CPE : " + line)
                elif "CVE" in line:
                    #print("CVE : " + line)
                    # Search for CVEs in the line
                    match = cve_pattern.search(line)

                    if match:
                        cve_id = match.group(0).split()[0]  # Extract the CVE ID
                        cve_score = match.group(1)  # Extract the CVE score
                        cve_url = match.group(2)  # Extract the CVE URL
                        #print("compare : " + cve_score + "7.0")
                        #line: |     	CVE-2020-25719	9.0	https://vulners.com/cve/CVE-2020-25719
                        if float(cve_score) >= 7.0:
                            # Append the extracted information to the array
                            cve_array.append({
                                'id': cve_id,
                                'score': cve_score,
                                'url': cve_url
                            })
                    #print('CVE -- ' + cve_id + cve_score + cve_url)
                elif "*EXPLOIT*" in line:
                    print("Exploit : " + line)
                    #pattern = re.compile(r"Exploit : \|(\s+)?([\w:-]+)\s+(\d+\.\d+)\s+(https://[\w:/-]+)")
                    #matches = pattern.findall(line)

                    #exploit_list = []
                    #for match in matches:
                    #    exploit_name = match[1]
                    #    exploit_rating = float(match[2])
                    #    exploit_url = match[3]
                    #    exploit_list.append({
                    #        'name': exploit_name,
                    #        'rating': exploit_rating,
                    #        'url': exploit_url
                    #    })
                    #exploit['target'].append({ 'name': exploit_name, 'rating': exploit_rating, 'url': exploit_url})

                    #return exploit_list

                #elif "Nmap done :" in line:
                    #print("NMAP DONE" + line)
                    # Use re.search to find matches
                    #match = re.search(pattern, nmap_output)
                    #print("post match")
                    #if match:
                    #total_ips = int(match.group(1))
                    #hosts_up = int(match.group(2))
                    #time_taken = float(match.group(3))

                    #print(f"Total IPs: {total_ips}")
                    #print(f"Hosts Up: {hosts_up}")
                    #print(f"Time Taken: {time_taken} seconds")

                    #print("NMAP DONE Complete" + line)

            if current_host:
                parsed_data.append(current_host)

            #return parsed_data
            #print(parsed_data)

            emit('deep_scan_results',  parsed_data)
            #print("DeepScan Complete")
            
            #emit('cve_array', {'target': target, 'last_seen_port': last_seen_port, 'cve_array': cve_array})

            #sorted_cve_array = sorted(cve_array, key=lambda x: x['score'], reverse=True)

            # Filter out CVEs with a score below 7.0
            #filtered_cve_array = [cve for cve in sorted_cve_array if cve['score'] >= 7.0]
            emit('cve_array', {'target': target, 'last_seen_port': last_seen_port, 'cve_array': cve_array})

            #exploit_text = """..."""  # Your exploit text here
            #exploit_list = parse_exploit_data(exploit_text)
            #emit('exploit_list', {'exploit_list': exploit_list})

            # Convert the filtered list to JSON
            #filtered_cve_json = json.dumps(filtered_cve_array)

            # Emit the filtered and sorted CVE list to the frontend
            #emit('cve_array', {"target": target, "cves": filtered_cve_json})
            
            #print("cve_array : ", cve_array)
            
            # Take screenshots for queued ports
            #for ip, port in screenshot_ports:
             #   print("Screenshot_Port : " + ip + ":" + port)
            #    try:
            #        driver.get(f'http://{ip}:{port}')
            #        time.sleep(5)  # Add a delay to ensure the page is fully loaded
            #        driver.save_screenshot(f'{ip}_port_{port}.png')
            #    except Exception as e:
            #        emit('screenshot', str(e))

            driver.quit()  # Quit the webdriver after all scans
            
            #sprint(len(parsed_data))

            # we need to detect if the port open, and has html before trying to grab.
#            try:
#                driver.get(f'http://{target}:80')
#                time.sleep(1)
#                driver.save_screenshot(f'{target}_port_80.png')
#                driver.quit()
#            except Exception as e:
#                emit('screenshot', str(e))


            #for host in parsed_data:
            #    print(f'IP: {host["ip"]}, OS: {host["os"]}')
            #    for port_info in host['ports']:
            #        print(f'  Port: {port_info["port"]}, State: {port_info["state"]}, Service: {port_info["service"]}')
    except Exception as e:
        emit('scan_error', str(e))
    print("Complete Deep Scan.")


@socketio.on('start_scan')
def start_scan(target):
    generate_pdf()
    report = PDFPSReporte('psreport.pdf')
    try:
        # Run the Nmap scan and capture the output
        # fast scan the subnet
        print("nmap -sn " + target)
        output = subprocess.check_output(['nmap', '-sn', target]).decode('utf-8')

        # Parse the Nmap output to extract relevant information
        #parsed_data = parse_nmap_output(output)
        parsed_data = []
        #print(output)
        lines = output.split('\n')
        #print(lines)
        scan_report_regex = re.compile(r'^Nmap scan report for ([^\s]+)')
        open_port_regex = re.compile(r'^\s*(\d+)\/tcp\s+(\w+)\s+(\w+)')
        open_port_regex_b = re.compile(r'.*Open\s+(\d+)/')

        # Regular expressions
        ip_regex = re.compile(r'Nmap scan report for ([^\s]+)')
        host_status_regex = re.compile(r'Host is (up|down) \(([\d.]+s latency\))')
        open_port_regex = re.compile(r'(\d+)\/tcp\s+(\w+)\s+(\w+)')

        # Data structure to store host information
        hosts = []

        current_host = None
        #print(len(lines))

        # Loop through the Nmap output
        for line in lines:
            # Match IP address line
            #print(line)
            ip_match = ip_regex.match(line)
            if ip_match:
                current_host = {'ip': ip_match.group(1), 'status': None, 'ports': []}
                hosts.append(current_host)
                #print(hosts)
            elif "Nmap done:" in line:
                #print("NMAP DONE" + line)
                # Regular expression to match the number of hosts and time
                pattern = re.compile(r'Nmap done: (\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds')
                #print("post pattern")
                # Use re.search to find matches
                match = re.search(pattern, line)
                #print("Post Match")
                if match:
                    total_ips = int(match.group(1))
                    hosts_up = int(match.group(2))
                    time_taken = float(match.group(3))

                    print(f"Total IPs: {total_ips}")
                    print(f"Hosts Up: {hosts_up}")
                    print(f"Time Taken: {time_taken} seconds")
                else:
                    print("No match found")
                emit('quickscan', {'total_ips': total_ips, 'hosts_up': hosts_up, 'time_taken': time_taken })
            else:
                # Match host status and latency
                host_status_match = host_status_regex.match(line)
                if host_status_match:
                    current_host['status'] = host_status_match.group(1)
                else:
                    # Match open ports
                    open_port_match = open_port_regex.match(line)
                    if open_port_match and current_host:
                        port = open_port_match.group(1)
                        state = open_port_match.group(2)
                        service = open_port_match.group(3)
                        version = open_port_match.group(4)
                        current_host['ports'].append({'port': port, 'state': state, 'service': service, 'version': version})

        # Sort hosts by IP address
        #sorted_hosts = sorted(hosts, key=lambda x: x['ip'])
        sorted_hosts = sorted(hosts, key=lambda x: ipaddress.IPv4Address(x['ip']))

        #print(sorted_hosts)
        # Print the sorted hosts
        #for host in hosts:
        #    print(f'IP: {host["ip"]}, Status: {host["status"]}')
        #    for port_info in host['ports']:
        #        print(f'  Port: {port_info["port"]}, State: {port_info["state"]}, Service: {port_info["service"]}')

        #emit('scan_results', hosts)
        emit('scan_results', sorted_hosts)

        targets = [host['ip'] for host in sorted_hosts]

        #print("Targets : ", targets)

        start_deep_scan(targets)

    except Exception as e:
        emit('scan_error', str(e))

if __name__ == '__main__':
    socketio.run(app, debug=True)
