#!/usr/bin/env python
# -*- coding: UTF-8 -*-

#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.

#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
from optparse import OptionParser
import requests
from urllib.parse import urlparse
import datetime
import json
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import re

__author__="sinkmanu"
__date__ ="$15.12.2015$"
__version__ = "1.0"

user_agent = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0' }
requests.packages.urllib3.disable_warnings()

# Colors
blue = "\033[94m"
white = "\033[0m"
red = "\033[91m"

def headersURL(line, info, nocolor, formatoutput):
    """ Load page and print data"""
    if nocolor:
        # Set to white
        color_blue = white
        color_red = white
    else:
        color_blue = blue
        color_red = red
    url = line.strip()
    if (urlparse(url).scheme == ''):
        url = 'http://%s'%url
    try:
        r = requests.get(url, verify=False, allow_redirects=True)
        if (formatoutput == "normal"):
            printNormal(line, r.cookies, nocolor, info)
        elif (formatoutput == "json"):
            printJson(line, r.cookies, info)
        elif (formatoutput == "xml"):
            printXML(line, r.cookies, info)
        elif (formatoutput == "csv"):
            printCsv(line, r.cookies, info)
        elif (formatoutput == "grepable"):
            printGrepable(line, r.cookies, info)
    except:
        print("[ERR] %s - Connection failed."% url)


def readFile(filename, info, nocolor, formatoutput):
    """ Read file with the url list (one per line)"""
    try:
        with open(filename, "r") as f:
            for line in f:
                headersURL(line, info, nocolor, formatoutput)
    except FileNotFoundError:
        print("[ERR] File not found.")


def printNormal(line, cookies, nocolor, info):
    if nocolor:
        # Set to white
        color_blue = white
        color_red = white
    else:
        color_blue = blue
        color_red = red
    print("%s[*] URL: %s%s"%(color_blue,line.strip(),white))
    for cookie in cookies:
        name = cookie.name
        secure = cookie.secure
        httponly = cookie.has_nonstandard_attr("HttpOnly")
        if not httponly:
            httponlyResult = '%sHttpOnly: %s%s'%(color_red, str(httponly), white)
        else:
            httponlyResult = 'HttpOnly: %s%s'%(str(httponly), white)
        if not secure:
            secureResult = '%ssecure: %s%s'%(color_red, str(secure), white)
        else:
            secureResult = 'Secure: %s'%str(secure)
        print("%s[*] Name: %s\n\t%s\n\t%s%s%s"%(white, name, secureResult, white, httponlyResult, white))
        # If info, print all
        if info:
            if cookie.expires is not None:
                expires = datetime.datetime.fromtimestamp(cookie.expires).strftime('%Y-%m-%d %H:%M:%S')
            else:
                expires = "Never"
            print("\tValue: %s\n\tPath: %s\n\tExpire: %s"%(cookie.value, cookie.path, expires))



def printGrepable(line, cookies, info):
    for cookie in cookies:
        name = cookie.name
        secure = cookie.secure
        httponly = cookie.has_nonstandard_attr("HttpOnly")
        if not httponly:
            httponlyResult = "NO"
        else:
            httponlyResult = "YES"
        if not secure:
            secureResult = "NO"
        else:
            secureResult = "YES"
        # If info, print all
        if info:
            if cookie.expires is not None:
                expires = datetime.datetime.fromtimestamp(cookie.expires).strftime('%Y-%m-%d %H:%M:%S')
            else:
                expires = "Never"
            print("URL: %s: Cookie: %s : Secure: %s : Httponly: %s : value: %s : path: %s : expires: %s"%(line.strip(), name, secureResult, httponlyResult, cookie.value, cookie.path, expires))
        else:
            print("URL: %s: Cookie: %s : Secure: %s : Httponly: %s"%(line.strip(), name, secureResult, httponlyResult))


def indent(elem, level=0):
    """ XML pretty print"""
    i = "\n" + level*"  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i


def printXML(line, cookies, info):
    allxml = ET.Element('url', {'site': line.strip()})
    for cookie in cookies:
        child = ET.SubElement(allxml, 'cookie')
        secure = cookie.secure
        httponly = cookie.has_nonstandard_attr("HttpOnly")
        if not httponly:
            httponlyResult = "NO"
        else:
            httponlyResult = "YES"
        if not secure:
            secureResult = "NO"
        else:
            secureResult = "YES"
        ET.SubElement(child, 'name').text = cookie.name
        ET.SubElement(child, 'secure').text = secureResult
        ET.SubElement(child, 'httponly').text = httponlyResult
        if info:
            if cookie.expires is not None:
                expires = datetime.datetime.fromtimestamp(cookie.expires).strftime('%Y-%m-%d %H:%M:%S')
            else:
                expires = "Never"
            ET.SubElement(child, 'value').text = cookie.value
            ET.SubElement(child, 'path').text = cookie.path
            ET.SubElement(child, 'expires').text = expires
    indent(allxml)
    ET.dump(allxml)


def printJson(line, cookies, info):
    cookies_output = []
    for cookie in cookies:
        secure = cookie.secure
        httponly = cookie.has_nonstandard_attr("HttpOnly")
        if not httponly:
            httponlyResult = "NO"
        else:
            httponlyResult = "YES"
        if not secure:
            secureResult = "NO"
        else:
            secureResult = "YES"
        data = {
            'name': cookie.name,
            'secure': secureResult,
            'httponly': httponlyResult
        }
        cookies_output.append(data)
        if info:
            if cookie.expires is not None:
                expires = datetime.datetime.fromtimestamp(cookie.expires).strftime('%Y-%m-%d %H:%M:%S')
            else:
                expires = "Never"
            data['value'] = cookie.value
            data['path'] = cookie.path
            data['expire'] = expires
    json_output = {
            'url': line.strip(),
            'cookies': cookies_output
        }
    print(json.dumps(json_output, indent=4, separators=(',', ': ')))


def printCsv(line, cookies, info):
    if info:
        print("url,cookie name,secure,httponly,value,path,expires")
    else:
        print("url,cookie name,secure,httponly")
    for cookie in cookies:
        name = cookie.name
        secure = cookie.secure
        httponly = cookie.has_nonstandard_attr("HttpOnly")
        if not httponly:
            httponlyResult = "NO"
        else:
            httponlyResult = "YES"
        if not secure:
            secureResult = "NO"
        else:
            secureResult = "YES"
        # If info, print all
        if info:
            if cookie.expires is not None:
                expires = datetime.datetime.fromtimestamp(cookie.expires).strftime('%Y-%m-%d %H:%M:%S')
            else:
                expires = "Never"
            print("%s,\"%s\",%s,%s,\"%s\",%s,%s"%(line.strip(), name, secureResult, httponlyResult, cookie.value, cookie.path, expires))
        else:
            print("%s,\"%s\",%s,%s"%(line.strip(), name, secureResult, httponlyResult))


def googleSearch(domain, info, nocolor, formatoutput):
    """ Google search, find subdomains and load pages"""
    g_url = "http://www.google.com/search?hl=es&q=site:%s&btnG=Google+Search"%domain
    r = requests.get(g_url, verify=False, headers=user_agent)
    soup = BeautifulSoup(r.text, "html.parser")
    domains = []
    g_pages = []
    top = soup.find('tr' , attrs={'valign': 'top'})
    for page in top.find_all('a', attrs={'class': 'fl'}):
        g_pages.append('https://www.google.com%s'% page.get('href'))
    for site in soup.find_all('cite'):
        if re.match('^([a-z0-9]*)(.?)%s$'%domain, urlparse('//%s'% site.text).netloc) is not None:
            domains.append(urlparse('//%s'% site.text).netloc)
    for sites in g_pages:
            r = requests.get(sites, verify=False, headers=user_agent)
            soup2 = BeautifulSoup(r.text, "html.parser")
            for site in soup2.find_all('cite'):
                if re.match('^([a-z0-9]*)(.?)%s$'%domain, urlparse('//%s'% site.text).netloc) is not None:
                    domains.append(urlparse('//%s'% site.text).netloc)
    for url in set(domains):
        headersURL(url, info, nocolor, formatoutput)



def opciones():
        parser = OptionParser("usage: %prog [options] \nExample: ./%prog -i ips.txt")
        parser.add_option("-i", "--input",
                  action="store", type="string", dest="input", help="File input with the list of webservers")
        parser.add_option("-I", "--info",
                  action="store_true", dest="info", default=False, help="More info")
        parser.add_option("-u", "--url",
                  action="store", type="string", dest="url", help="URL")
        parser.add_option("-f", "--format",
                  action="store", type="string", dest="format", default="normal", help="Output format (json, xml, csv, normal, grepable)")
        parser.add_option("--nocolor",
                  action="store_true", dest="nocolor", default=False, help="Disable color (for the normal format output)")
        parser.add_option("-g", "--google",
                  action="store", dest="google", help="Search in google by domain")
        (options, args) = parser.parse_args()
        if (len(sys.argv) == 1):
            parser.print_help()
        elif (options.input is not None):
            readFile(options.input, options.info, options.nocolor, options.format)
        elif (options.url is not None):
            headersURL(options.url, options.info, options.nocolor, options.format)
        elif (options.google is not None):
            googleSearch(options.google, options.info, options.nocolor, options.format)


if __name__ == "__main__":
    opciones()