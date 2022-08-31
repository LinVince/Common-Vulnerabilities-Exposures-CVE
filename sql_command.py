import sqlite3
import datetime
import xml.etree.ElementTree as ET
import codecs
import urllib.request, urllib.parse, urllib.error
import re
from bs4 import BeautifulSoup


def initial_posts():
    year=input('Enter Year')
    if year == 'all':
        handle=urllib.request.urlopen('https://cve.mitre.org/data/downloads/allitems-cvrf.xml')
        read=handle.read()
        read=read.decode('utf-8','ignore')
        root=ET.fromstring(read)
        NS={"cve_ns":"http://www.icasi.org/CVRF/schema/vuln/1.1"}
        cve_lis=root.findall("cve_ns:Vulnerability", namespaces=NS)
        con=sqlite3.connect("Database.sqlite3")
        cur=con.cursor()
        print (datetime.datetime.now())

        for cve in cve_lis:
            title=cve.find("cve_ns:Title",namespaces=NS).text
            notes=cve.find("cve_ns:Notes",namespaces=NS)
            descnode=notes.find("cve_ns:Note[@Type='Description']",namespaces=NS)
            pubnode=notes.find("cve_ns:Note[@Title='Published']",namespaces=NS)
            modnode=notes.find("cve_ns:Note[@Title='Modified']",namespaces=NS)
            desc = descnode.text
    
            if pubnode is not None:
                pub = pubnode.text
            else:
                pub = ""
            if modnode is not None:
                mod = modnode.text
            else:
                mod = ""
            cur.execute("DELETE FROM mainsite_post WHERE title=?",(title,))
            cur.execute("insert into mainsite_post (title, desc, pub) values (?, ?, ?)", (title, desc, pub))
            con.commit()
            print (title,'Done')

        cur.close()
        con.close()
        print (datetime.datetime.now())

    else:
        handle=urllib.request.urlopen('https://cve.mitre.org/data/downloads/allitems-cvrf-year-'+year+'.xml')
        read=handle.read()        
        root=ET.fromstring(read)
        NS={"cve_ns":"http://www.icasi.org/CVRF/schema/vuln/1.1"}
        cve_lis=root.findall("cve_ns:Vulnerability", namespaces=NS)
        con=sqlite3.connect("Database.sqlite3")
        cur=con.cursor()
        print (datetime.datetime.now())

        for cve in cve_lis:
            title=cve.find("cve_ns:Title",namespaces=NS).text
            notes=cve.find("cve_ns:Notes",namespaces=NS)
            descnode=notes.find("cve_ns:Note[@Type='Description']",namespaces=NS)
            pubnode=notes.find("cve_ns:Note[@Title='Published']",namespaces=NS)
            modnode=notes.find("cve_ns:Note[@Title='Modified']",namespaces=NS)
            desc = descnode.text
    
            if pubnode is not None:
                pub = pubnode.text
            else:
                pub = ""
            if modnode is not None:
                mod = modnode.text
            else:
                mod = ""
            cur.execute("DELETE FROM mainsite_post WHERE title=?",(title,))
            cur.execute("insert into mainsite_post (title, desc, pub) values (?, ?, ?)", (title, desc, pub))
            con.commit()           
            print (title,'Done')
            
        cur.close()
        con.close()
        print (datetime.datetime.now())


def update_posts():
    year=input("Enter Year")
    if year == "all":
        handle=urllib.request.urlopen('https://cve.mitre.org/data/downloads/allitems-cvrf.xml')
        read=handle.read()
        read=read.decode('utf-8','ignore')
        root=ET.fromstring(read)
        NS={"cve_ns":"http://www.icasi.org/CVRF/schema/vuln/1.1"}
        cve_lis=root.findall("cve_ns:Vulnerability", namespaces=NS)
        con=sqlite3.connect("Database.sqlite3")
        cur=con.cursor()    
        print (datetime.datetime.now())

        for cve in cve_lis:
            title=cve.find("cve_ns:Title",namespaces=NS).text
            notes=cve.find("cve_ns:Notes",namespaces=NS)
            descnode=notes.find("cve_ns:Note[@Type='Description']",namespaces=NS)
            pubnode=notes.find("cve_ns:Note[@Title='Published']",namespaces=NS)
            modnode=notes.find("cve_ns:Note[@Title='Modified']",namespaces=NS)
            desc = descnode.text
    
            if pubnode is not None:
                pub = pubnode.text
            else:
                pub = ""
            if modnode is not None:
                mod = modnode.text
            else:
                mod = ""
            
        
            cur.execute("UPDATE mainsite_post SET desc=? WHERE title=?", (desc, title))
            cur.execute("UPDATE mainsite_post SET pub=? WHERE title=?", (pub, title))
            con.commit()           

        cur.close()
        con.close()
        print (datetime.datetime.now())

    else:
        handle=urllib.request.urlopen('https://cve.mitre.org/data/downloads/allitems-cvrf-year-'+year+'.xml')
        read=handle.read()
        read=read.decode('utf-8','ignore')
        root=ET.fromstring(read)
        NS={"cve_ns":"http://www.icasi.org/CVRF/schema/vuln/1.1"}
        cve_lis=root.findall("cve_ns:Vulnerability", namespaces=NS)
        con=sqlite3.connect("Database.sqlite3")
        cur=con.cursor()    
        print (datetime.datetime.now())

        for cve in cve_lis:
            title=cve.find("cve_ns:Title",namespaces=NS).text
            notes=cve.find("cve_ns:Notes",namespaces=NS)
            descnode=notes.find("cve_ns:Note[@Type='Description']",namespaces=NS)
            pubnode=notes.find("cve_ns:Note[@Title='Published']",namespaces=NS)
            modnode=notes.find("cve_ns:Note[@Title='Modified']",namespaces=NS)
            desc = descnode.text
    
            if pubnode is not None:
                pub = pubnode.text
            else:
                pub = ""
            if modnode is not None:
                mod = modnode.text
            else:
                mod = ""
            
        
            cur.execute("UPDATE mainsite_post SET desc=? WHERE title=?", (desc, title))
            cur.execute("UPDATE mainsite_post SET pub=? WHERE title=?", (pub, title))
            con.commit()           

        cur.close()
        con.close()
        print (datetime.datetime.now())
        


def update_posts_info():
    headers = {}
    headers['User-Agent'] = "Mozilla/5.0 (X11; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0"    
    con=sqlite3.connect('Database.sqlite3')
    con.row_factory=lambda cursor, row: row[0]
    c=con.cursor()
    
    reserve="""** RESERVED **
This candidate has been reserved by an organization or individual that
will use it when announcing a new security problem.  When the
candidate has been publicized, the details for this candidate will be
provided.
"""
    
    title_list=c.execute("SELECT title FROM mainsite_post WHERE vul_type IS NULL AND desc != ?",(reserve,)).fetchall()
    for title in title_list:
        
        url='https://nvd.nist.gov/vuln/detail/'+title
        req=urllib.request.Request(url,headers=headers)
        html=urllib.request.urlopen(req)
        doc=html.read()
        soup=BeautifulSoup (doc,'html.parser')
        tag=soup.find(attrs={"data-testid":"vuln-technical-details-0-link"})        
        vendors=[]
        products=[]
        
        if tag is not None:
            vultyp=tag.get_text()    
        else:
            vultyp= None            
    
                    
        tag2=soup.find_all(attrs={"target":"blank"})
            
        for tag in tag2:
            line=tag.get_text()    
            v=re.compile('.+?:.+?:.+?:(\S+?):.+?:.+?')
            if v.search(line).group(1) not in vendors:
                vendors.append(v.search(line).group(1))
            else:
                continue
    
            p=re.compile('.+?:.+?:.+?:.+?:(\S+?):')
            if p.search(line).group(1) not in products:
                products.append(p.search(line).group(1))
            else:
                continue


        #start to write into the db

        c.execute("UPDATE mainsite_post SET vul_type=? WHERE title=?", (vultyp, title,))
        c.execute("UPDATE mainsite_post SET vendors=? WHERE title=?", ("".join([str(x)+', ' for x in vendors]), title,))
        c.execute("UPDATE mainsite_post SET products=? WHERE title=?",("".join([str(y)+', ' for y in products]), title,))
        con.commit()
        print (title,'Done')


def ctype():
    con=sqlite3.connect('Database.sqlite3')
    con.row_factory=lambda cursor, row: row[0]
    c=con.cursor()
    year=input('Enter Year')
    counts=dict()
    
    if year != 'all':
        yearNo='CVE-'+year+'%'
        vultype_list=c.execute("SELECT vul_type FROM mainsite_post WHERE vul_type != 'Vulnerability Type Awaiting Analysis' AND title LIKE ?",(yearNo,)).fetchall()            
        for vultype in vultype_list:
            counts[vultype]=counts.get(vultype, 0) + 1

    elif year== 'all':
        vultype_list=c.execute("SELECT vul_type FROM mainsite_post WHERE vul_type != 'Vulnerability Type Awaiting Analysis'").fetchall()
        for vultype in vultype_list:
            counts[vultype]=counts.get(vultype, 0) + 1
            
    # result "counts"
    

def cvendor():
    con=sqlite3.connect('Database.sqlite3')
    con.row_factory=lambda cursor, row: row[0]
    c=con.cursor()
    year=input('Enter Year')

    if year != 'all':
        yearNo='CVE-'+year+'%'
        vendor_list=c.execute("SELECT vendors FROM mainsite_post WHERE title LIKE ?",(yearNo,))
        x=''
        counts={}        
        for vendor in vendor_list:            
            if vendor is not None:
                x=x+vendor
            else:
                pass        
        vendor_list=x.split(', ')
        for vendor in vendor_list:            
            counts[vendor]=counts.get(vendor, 0)+1
        
        
    elif year == 'all':
        vendor_list=c.execute("SELECT vendors FROM mainsite_post WHERE pub != ''")
        x=''        
        counts={}
        for vendor in vendor_list:            
            if vendor is not None:
                x=x+vendor
                
            else:
                pass
            
        vendor_list=x.split(', ')
        for vendor in vendor_list:            
            counts[vendor]=counts.get(vendor, 0)+1

    # result "counts"
        
            

                


