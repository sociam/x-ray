#!/usr/bin/env python
#
# Simple script showing how to read a mitmproxy dump file
#

# dependent git repo: https://github.com/mitmproxy/mitmproxy
# doc: 
# manual about mitmproxy: 

from mitmproxy import flow
import pprint
import sys
import re
from datetime import datetime
import json


def format_cookies(obj):
    if obj:
        return [{"name": k.strip(), "value": v[0]} for k, v in obj.items()]
    return ""


def format_headers(obj):
    if obj:
        return [{"name": k, "value": v} for k, v in obj.fields]
    return ""

def findHosts (freader):

    countHost = set()
    try:
        for f in freader.stream():

            request = f.request

            host = request.host 

            request_query_string = [{"name": k, "value": v}
                for k, v in request.query or {}]
            
            method = request.method
            url = request.url

            bodysize = len(request.content)


            #header = f.request.headers
            header = format_headers(f.request.headers)
            cookies = format_cookies(f.request.cookies)
            # print "Header of the request "
            # print header
            # # print "Header of the request " + header
            # print "Content of the request "
            # print cookies
            if host not in countHost:
                print "Host " + host
                countHost.add(host)


            if request.headers.get('Referer'):
                print "Referer " + request.headers['Referer']
                    
            #pp.pprint(f.get_state())
            #print("")
            
        print "found " + str(len(countHost)) + " hosts"
    except flow.FlowReadError as v:
        print "Flow file corrupted. Stopped loading."

def findDataOfHost (freader,hostname,outfile):
    
    try:
        for f in freader.stream():

            request = f.request

            host = request.host 

            if (host == hostname) & len(request.content)>0:


                request_query_string = {}
                if f.request.query is not None:
                    request_query_string = [{"name": k, "value": v}
                        for k, v in f.request.query]

                request_http_version = f.request.http_version
                # Cookies are shaped as tuples by MITMProxy.
                request_cookies = [{"name": k.strip(), "value": v[0]}
                    for k, v in f.request.cookies.items()]
            
                request_headers = {}
                if f.request.headers:
                    for k, v in f.request.headers.fields:
                        request_headers["name"] = k
                        request_headers["value"] = v

                request_headers_size = len(str(f.request.headers))
                request_body_size = len(f.request.content)

                print "found " + hostname
                # print request.content

                data = {

                    "request": {
                        "method": f.request.method,
                        "url": f.request.url,
                        "httpVersion": request_http_version,
                        "cookies": request_cookies,
                        # headers are key value pairs 
                        "headers": format_headers(f.request.headers),
                        "queryString": request_query_string,
                        "headersSize": request_headers_size,
                        "bodySize": request_body_size,
                        "content": request.content.decode('utf-8', 'replace')
                    }
                }

                # print data

                json.dump(data, outfile)

    except flow.FlowReadError as v:
        print "Flow file corrupted. Stopped loading."

def findName (freader):

    hosts = set()

    try:
        for f in freader.stream():
            if re.search('junvivek', f.request.content):
                # print("Flow matches filter: Zhao" )
                # print("Host: " + f.request.host)
                print("accessed data: " + f.request.content)
                if not f.request.headers.get('Referer'):
                    # print "Referer " + f.request.headers['Referer']
                    host = f.request.host
                    if host not in hosts:
                        hosts.add(host)
                        print("Host: " + host)

                
            # else:
            #     print(flow.get_state())
    except flow.FlowReadError as v:
        print "Flow file corrupted. Stopped loading."

def main():

    # with open('/Users/junhao/Desktop/captures/pinterest00103', "rb") as logfile:
        
        # pp = pprint.PrettyPrinter(indent=4)

        ## find the hosts accessing the data during the session
        # findHosts(freader)

    hostnames = ('app.adjust.com',
        'e.crashlytics.com',
        'trk.pinterest.com',
        'media-cache-ec0.pinimg.com',
        'api.pinterest.com',
        'media-cache-ak0.pinimg.com',
        'graph.facebook.com',
        'p05-ckdatabase.icloud.com',
        'www.google.com',
        'init-p01st.push.apple.com',
        's-media-cache-ak0.pinimg.com',
        'bcp.crwdcntrl.net',
        'x.skimresources.com',
        'securepubads.g.doubleclick.net',
        'p.skimresources.com',
        'ads.rubiconproject.com',
        'js.moatads.com',
        'ssp.virool.com',
        'nestor.virool.com',
        'gum.criteo.com',
        'optimized-by.rubiconproject.com',
        'battleunits.s3.amazonaws.com',
        'tags.mathtag.com',
        'pixel.rubiconproject.com',
        'loadm.exelator.com',
        'rb-validation.virool.com',
        'pixel.adsafeprotected.com',
        'api.virool.com',
        'fw.adsafeprotected.com',
        'sc.iasds01.com',
        'dt.adsafeprotected.com',
        'secure.flashtalking.com',
        'mathid.mathtag.com',
        'tap2-cdn.rubiconproject.com',
        'passets-ak.pinterest.com',
        'iphone-ld.apple.com'
    )    

    for hostname in hostnames:
        logfile = open('/home/junhao/workspace/x-ray/captures/pinterest00103', "rb")
        outfile = open('data.txt', 'a')
        freader = flow.FlowReader(logfile)
        findDataOfHost(freader,hostname,outfile)
        # findName(freader)


if __name__ == "__main__":
    main()
