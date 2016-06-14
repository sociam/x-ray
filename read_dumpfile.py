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
from harparser import HAR
from datetime import datetime
import json

class _HARLog(HAR.log):
    # The attributes need to be registered here for them to actually be
    # available later via self. This is due to HAREncodable linking __getattr__
    # to __getitem__. Anything that is set only in __init__ will just be added
    # as key/value pair to self.__classes__.
    __page_list__ = []
    __page_count__ = 0
    __page_ref__ = {}

    def __init__(self, page_list):
        self.__page_list__ = page_list
        self.__page_count__ = 0
        self.__page_ref__ = {}

        HAR.log.__init__(self, {"version": "1.2",
                                "creator": {"name": "MITMPROXY HARExtractor",
                                            "version": "0.1",
                                            "comment": ""},
                                "pages": [],
                                "entries": []})

    def reset(self):
        self.__init__(self.__page_list__)

    def add(self, obj):
        if isinstance(obj, HAR.pages):
            self['pages'].append(obj)
        if isinstance(obj, HAR.entries):
            self['entries'].append(obj)
            # print "I am here"

    def create_page_id(self):
        self.__page_count__ += 1
        return "autopage_%s" % str(self.__page_count__)

    def set_page_ref(self, page, ref):
        self.__page_ref__[page] = ref

    def get_page_ref(self, page):
        return self.__page_ref__.get(page, None)

    def get_page_list(self):
        return self.__page_list__

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
            # print "Header of the request " + header
            # print "Content of the request "
            # print cookies
            if host not in countHost:
                print "Host " + host
                countHost.add(host)
            #pp.pprint(f.get_state())
            #print("")
            
        # print "found " + str(len(countHost)) + " hosts"
    except flow.FlowReadError as v:
        print "Flow file corrupted. Stopped loading."



def findName (flow):


    # print(flow)

    if flow.get_state().match('junvivek'):
        print("Flow matches filter: Zhao" )
        print(flow)
    # else:
    #     print(flow.get_state())

def findEmail (freader):
    
    email = 'sociam'
    try:
        for f in freader.stream():

            request = f.request

            host = request.host 

            content = request.get_decoded_content()

            if 'sociamox' in content:
                print "Hosts requesting my email: " + host
                print "Request content: " + content


            if f.response.headers:
                for k, v in f.response.headers.fields:
                    if 'sociamox' in v:
                        print "Host: " + host
                        print "Response header " + v 

            if 'sociamox' in f.response.get_decoded_content():
                print "Hosts requesting my email: " + host
                print "Response content: " + content
            
    except flow.FlowReadError as v:
        print "Flow file corrupted. Stopped loading."


def findDevice (freader):
    
    email = 'sociam'
    try:
        for f in freader.stream():

            request = f.request

            host = request.host 

            header = format_headers(f.request.headers)

            if f.request.headers:
                for k, v in f.request.headers.fields:
                    if 'GB' in v:
                        print "Host: " + host
                        print "Request header " + v 
            
            
    except flow.FlowReadError as v:
        print "Flow file corrupted. Stopped loading."


# def findLocation ():


# def findBehaviour ():


def main():

    # context.HARLog = _HARLog(['https://github.com'])

    with open('/home/junhao/workspace/x-ray/capture-gummies/gummies-android-20160513', "rb") as logfile:
        freader = flow.FlowReader(logfile)
        pp = pprint.PrettyPrinter(indent=4)

    ## find the hosts accessing the data during the session

        findHosts(freader)
        # findEmail(freader)
        # findDevice(freader)
 
if __name__ == "__main__":
    main() 