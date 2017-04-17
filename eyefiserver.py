#!/usr/bin/env python

"""
Adapted by Tom Lee <thomas.j.lee@gmail.com> (c) 2017.
Original copyright notice follows:

* Copyright (c) 2009, Jeffrey Tchang
* Additional *pike
* All rights reserved.
*
*
* THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


import cgi
import time
from datetime import timedelta

import random
import sys
import os
import socket
import thread
import StringIO
import traceback
import errno
import tempfile
import multiprocessing

import hashlib
import binascii
import select
import tarfile

import xml.sax
from xml.sax.handler import ContentHandler
import xml.dom.minidom

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import BaseHTTPServer
import httplib

import SocketServer

import logging
import logging.handlers

import atexit
from signal import SIGTERM
import signal

#pike
from datetime import datetime
import ConfigParser

import math

DEFAULTS = {'geotag_enable': '0'}

"""
General architecture notes


This is a standalone Eye-Fi Server that is designed to take the place of the Eye-Fi Manager.


Starting this server creates a listener on port 59278. I use the BaseHTTPServer class included
with Python. I look for specific POST/GET request URLs and execute functions based on those
URLs.

"""


# Create the main logger
eyeFiLogger = logging.Logger("eyeFiLogger", logging.DEBUG)

# Create two handlers. One to print to the log and one to print to the console
consoleHandler = logging.StreamHandler(sys.stdout)

# Set how both handlers will print the pretty log events
eyeFiLoggingFormat = logging.Formatter("[%(asctime)s][%(funcName)s] - %(message)s",'%m/%d/%y %I:%M%p')
consoleHandler.setFormatter(eyeFiLoggingFormat)

# Append both handlers to the main Eye Fi Server logger
eyeFiLogger.addHandler(consoleHandler)

# Eye Fi XML SAX ContentHandler
class EyeFiContentHandler(ContentHandler):

    # These are the element names that I want to parse out of the XML
    elementNamesToExtract = ["macaddress","cnonce","transfermode","transfermodetimestamp","fileid","filename","filesize","filesignature"]

    # For each of the element names I create a dictionary with the value to False
    elementsToExtract = {}

    # Where to put the extracted values
    extractedElements = {}


    def __init__(self):
        self.extractedElements = {}

        for elementName in self.elementNamesToExtract:
            self.elementsToExtract[elementName] = False

    def startElement(self, name, attributes):
        # If the name of the element is a key in the dictionary elementsToExtract
        # set the value to True
        if name in self.elementsToExtract:
            self.elementsToExtract[name] = True

    def endElement(self, name):
        # If the name of the element is a key in the dictionary elementsToExtract
        # set the value to False
        if name in self.elementsToExtract:
            self.elementsToExtract[name] = False


    def characters(self, content):
        for elementName in self.elementsToExtract:
            if self.elementsToExtract[elementName] == True:
                self.extractedElements[elementName] = content

# Implements an EyeFi server
class EyeFiServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):

    def __init__(self, config={}, *args, **kwargs):
        self.config = config
        BaseHTTPServer.HTTPServer.__init__(self, *args, **kwargs)

    def serve_forever(self):
        while self.run:
            try:
                self.handle_request()
            except select.error, e:
                if e[0] != errno.EINTR:
                    raise e

    def stop_server(self, signum, frame):
        try:
            for q in self.worker_queues:
                q.put(None)
            eyeFiLogger.info("Eye-Fi server stopped ")
            self.stop()
        except Exception as e:
            eyeFiLogger.error("Error stopping server", str(e))
        sys.exit(0)

    def server_bind(self):
        BaseHTTPServer.HTTPServer.server_bind(self)
        self.socket.settimeout(None)
        signal.signal(signal.SIGTERM, self.stop_server)
        signal.signal(signal.SIGINT, self.stop_server)
        self.run = True

    def get_request(self):
        while self.run:
            try:
                connection, address = self.socket.accept()
                eyeFiLogger.debug("Incoming connection from client %s" % address[0])

                connection.settimeout(None)
                return (connection, address)

            except socket.timeout:
                self.socket.close()
                pass

    def stop(self):
        self.run = False

# wrap EyeFiRequestHandler w/ Flickr API object handy
def EyeFiRequestHandlerFactory(config, flickr):

    # This class is responsible for handling HTTP requests passed to it.
    # It implements the two most common HTTP methods, do_GET() and do_POST()
    class EyeFiRequestHandler(BaseHTTPRequestHandler):

        def __init__(self, *args, **kwargs):
            self.flickr = flickr
            self.config = config

            # set up uploader worker processes
            if self.flickr is not None:
                self.workers = []
                self.worker_queues = []
                for i in range(self.config.getint('EyeFiServer', 'flickr_concurrency')):
                    q = multiprocessing.Queue()
                    self.worker_queues.append(q)
                    self.workers.append(multiprocessing.Process(target=self.flickr_upload, args=(q,)))
                    self.workers[-1].start()

            BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

        def queue_upload(self, target):
            """
            Upload to shortest(ish) worker queue
            """
            shortest_q_i = 0
            shortest_q = 9999
            for (i, q) in enumerate(self.worker_queues):
                if q.qsize() < shortest_q:
                    shortest_q_i = i
            self.worker_queues[shortest_q_i].put(target)

        def flickr_upload(self, q):
            while True:
                target = q.get(True)
                if target is None:
                    break
                self.flickr.upload(photo_file=target.get('path'), title=target.get('title', datetime.now().isoformat()))

        def do_QUIT (self):
            eyeFiLogger.debug("Got StopServer request .. stopping server")
            self.send_response(200)
            self.end_headers()
            self.server.stop()

        def do_GET(self):
            try:
                eyeFiLogger.debug(self.command + " " + self.path + " " + self.request_version)

                SOAPAction = ""
                eyeFiLogger.debug("Headers received in GET request:")
                for headerName in self.headers.keys():
                    for headerValue in self.headers.getheaders(headerName):
                        eyeFiLogger.debug(headerName + ": " + headerValue)
                        if( headerName == "soapaction"):
                            SOAPAction = headerValue

                self.send_response(200)
                self.send_header('Content-type','text/html')
                # I should be sending a Content-Length header with HTTP/1.1 but I am being lazy
                # self.send_header('Content-length', '123')
                self.end_headers()
                self.wfile.write(self.client_address)
                self.wfile.write(self.headers)
                self.close_connection = 0
            except:
                eyeFiLogger.error("Got an an exception:")
                eyeFiLogger.error(traceback.format_exc())
                raise


        def do_POST(self):
            try:
                eyeFiLogger.debug(self.command + " " + self.path + " " + self.request_version)

                SOAPAction = ""
                contentLength = ""

                # Loop through all the request headers and pick out ones that are relevant

                eyeFiLogger.debug("Headers received in POST request:")
                for headerName in self.headers.keys():
                    for headerValue in self.headers.getheaders(headerName):

                        if( headerName == "soapaction"):
                            SOAPAction = headerValue

                        if( headerName == "content-length"):
                            contentLength = int(headerValue)

                        eyeFiLogger.debug(headerName + ": " + headerValue)


                # Read contentLength bytes worth of data
                eyeFiLogger.debug("Attempting to read " + str(contentLength) + " bytes of data")
                # postData = self.rfile.read(contentLength)
                try:
                    from StringIO import StringIO
                    import tempfile
                except ImportError:
                    eyeFiLogger.debug("No StringIO module")
                chunksize = 1048576 # 1MB
                mem = StringIO()
                while 1:
                    remain = contentLength - mem.tell()
                    if remain <= 0: break
                    chunk = self.rfile.read(min(chunksize, remain))
                    if not chunk: break
                    mem.write(chunk)
                postData = mem.getvalue()
                mem.close()

                eyeFiLogger.debug("Finished reading " + str(contentLength) + " bytes of data")

                # Perform action based on path and SOAPAction
                # A SOAPAction of StartSession indicates the beginning of an EyeFi
                # authentication request
                if((self.path == "/api/soap/eyefilm/v1") and (SOAPAction == "\"urn:StartSession\"")):
                    eyeFiLogger.debug("Got StartSession request")
                    response = self.startSession(postData)
                    contentLength = len(response)

                    eyeFiLogger.debug("StartSession response: " + response)

                    self.send_response(200)
                    self.send_header('Date', self.date_time_string())
                    self.send_header('Pragma','no-cache')
                    self.send_header('Server','Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
                    self.send_header('Content-Type','text/xml; charset="utf-8"')
                    self.send_header('Content-Length', contentLength)
                    self.end_headers()

                    self.wfile.write(response)
                    self.wfile.flush()
                    self.handle_one_request()

                # GetPhotoStatus allows the card to query if a photo has been uploaded
                # to the server yet
                if((self.path == "/api/soap/eyefilm/v1") and (SOAPAction == "\"urn:GetPhotoStatus\"")):
                    eyeFiLogger.debug("Got GetPhotoStatus request")

                    response = self.getPhotoStatus(postData)
                    contentLength = len(response)

                    eyeFiLogger.debug("GetPhotoStatus response: " + response)

                    self.send_response(200)
                    self.send_header('Server','Eye-Fi UnderTheSea OSX/3.0.2')
                    self.send_header('Connection', 'Keep-Alive')
                    self.send_header('Keep-Alive', 'timeout=300, max=10')
                    self.send_header('Date', self.date_time_string())
                    self.send_header('Content-Type', 'text/xml; charset="utf-8"')
                    self.send_header('Content-Length', contentLength)
                    self.end_headers()

                    self.wfile.write(response)
                    self.wfile.flush()


                # If the URL is upload and there is no SOAPAction the card is ready to send a picture to me
                if((self.path == "/api/soap/eyefilm/v1/upload") and (SOAPAction == "")):
                    eyeFiLogger.debug("Got upload request")
                    response = self.uploadPhoto(postData)
                    contentLength = len(response)

                    eyeFiLogger.debug("Upload response: " + response)

                    self.send_response(200)
                    self.send_header('Date', self.date_time_string())
                    self.send_header('Pragma','no-cache')
                    self.send_header('Server','Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
                    self.send_header('Content-Type','text/xml; charset="utf-8"')
                    self.send_header('Content-Length', contentLength)
                    self.end_headers()

                    self.wfile.write(response)
                    self.wfile.flush()

                # If the URL is upload and SOAPAction is MarkLastPhotoInRoll
                if((self.path == "/api/soap/eyefilm/v1") and (SOAPAction == "\"urn:MarkLastPhotoInRoll\"")):
                    eyeFiLogger.debug("Got MarkLastPhotoInRoll request")
                    response = self.markLastPhotoInRoll(postData)
                    contentLength = len(response)

                    eyeFiLogger.debug("MarkLastPhotoInRoll response: " + response)
                    self.send_response(200)
                    self.send_header('Date', self.date_time_string())
                    self.send_header('Pragma','no-cache')
                    self.send_header('Server','Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
                    self.send_header('Content-Type','text/xml; charset="utf-8"')
                    self.send_header('Content-Length', contentLength)
                    self.send_header('Connection', 'Close')
                    self.end_headers()

                    self.wfile.write(response)
                    self.wfile.flush()

                    eyeFiLogger.debug("Connection closed.")
            except:
                eyeFiLogger.error("Got an an exception:")
                eyeFiLogger.error(traceback.format_exc())
                raise


        # Handles MarkLastPhotoInRoll action
        def markLastPhotoInRoll(self,postData):
            # Create the XML document to send back
            doc = xml.dom.minidom.Document()

            SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
            SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")
            SOAPBodyElement = doc.createElement("SOAP-ENV:Body")

            markLastPhotoInRollResponseElement = doc.createElement("MarkLastPhotoInRollResponse")

            SOAPBodyElement.appendChild(markLastPhotoInRollResponseElement)
            SOAPElement.appendChild(SOAPBodyElement)
            doc.appendChild(SOAPElement)

            return doc.toxml(encoding = "UTF-8")


        # Handles receiving the actual photograph from the card.
        # postData will most likely contain multipart binary post data that needs to be parsed
        def uploadPhoto(self,postData):

            # Take the postData string and work with it as if it were a file object
            postDataInMemoryFile = StringIO.StringIO(postData)

            # Get the content-type header which looks something like this
            # content-type: multipart/form-data; boundary=---------------------------02468ace13579bdfcafebabef00d
            contentTypeHeader = self.headers.getheaders('content-type').pop()
            eyeFiLogger.debug(contentTypeHeader)

            # Extract the boundary parameter in the content-type header
            headerParameters = contentTypeHeader.split(';')
            eyeFiLogger.debug('headers %s' % headerParameters)

            boundary = headerParameters[-1].split('=')
            boundary = boundary[1].strip()
            eyeFiLogger.debug('Extracted boundary: %s' % boundary)

            # Parse the multipart/form-data
            form = cgi.parse_multipart(postDataInMemoryFile, {"boundary":boundary,"content-disposition":self.headers.getheaders('content-disposition')})
            eyeFiLogger.debug("Available multipart/form-data: %s" % str(form.keys()))

            # Parse the SOAPENVELOPE using the EyeFiContentHandler()
            soapEnvelope = form['SOAPENVELOPE'][0]
            eyeFiLogger.debug("SOAPENVELOPE: " + soapEnvelope)
            handler = EyeFiContentHandler()
            parser = xml.sax.parseString(soapEnvelope,handler)

            eyeFiLogger.debug("Extracted elements: %s" % str(handler.extractedElements))

            imageTarfileName = handler.extractedElements["filename"]

            geotag_enable = int(self.server.config.getint('EyeFiServer','geotag_enable'))
            if geotag_enable:
                geotag_accuracy = int(self.server.config.get('EyeFiServer','geotag_accuracy'))

            imageTarPath = os.path.join(tempfile.gettempdir(), imageTarfileName)
            eyeFiLogger.debug("Generated path %s" % imageTarPath)

            fileHandle = open(imageTarPath, 'wb')
            eyeFiLogger.debug("Opened file %s for binary writing" % imageTarPath)

            fileHandle.write(form['FILENAME'][0])
            eyeFiLogger.debug("Wrote file " + imageTarPath)

            fileHandle.close()
            eyeFiLogger.debug("Closed file %s" % imageTarPath)

            eyeFiLogger.debug("Extracting TAR file %s" % imageTarPath)
            try:
                imageTarfile = tarfile.open(imageTarPath)
            except ReadError, error:
                eyeFiLogger.error("Failed to open %s" % imageTarPath)
                raise

            for member in imageTarfile.getmembers():
                # If timezone is a daylight savings timezone, and we are
                # currently in daylight savings time, then use the altzone
                if time.daylight != 0 and time.localtime().tm_isdst != 0:
                    timeoffset = time.altzone
                else:
                    timeoffset = time.timezone
                timezone = timeoffset / 60 / 60 * -1
                imageDate = datetime.fromtimestamp(member.mtime) - timedelta(hours = timezone)
                uploadDir = imageDate.strftime(self.server.config.get('EyeFiServer','upload_dir'))

                f = imageTarfile.extract(member, uploadDir)
                imagePath = os.path.join(uploadDir, member.name)
                os.utime(imagePath, (member.mtime + timeoffset, member.mtime + timeoffset))

                # if flickr is enabled, add image to queue
                if self.flickr is not None:
                    eyeFiLogger.debug("queueing %s for upload" % imagePath)
                    self.queue_upload({"title": member.name, "path": imagePath})

                if geotag_enable>0 and member.name.lower().endswith(".log"):
                    eyeFiLogger.debug("Processing LOG file " + imagePath)
                    try:
                        imageName = member.name[:-4]
                        shottime, aps = list(self.parselog(imagePath,imageName))
                        aps = self.getphotoaps(shottime, aps)
                        loc = self.getlocation(aps)
                        if loc['status'] =='OK' and float(loc['accuracy']) <= geotag_accuracy:
                            xmpName = imageName+".xmp"
                            xmpPath = os.path.join(uploadDir, xmpName)
                            eyeFiLogger.debug("Writing XMP file " + xmpPath)
                            self.writexmp(xmpPath,float(loc['location']['lat']),float(loc['location']['lng']))
                            fix_ownership(xmpPath, uid, gid)
                            if file_mode != "":
                                os.chmod(xmpPath, int(file_mode))
                    except:
                        eyeFiLogger.error("Error processing LOG file " + imagePath)

            eyeFiLogger.debug("Closing TAR file " + imageTarPath)
            imageTarfile.close()

            eyeFiLogger.debug("Deleting TAR file " + imageTarPath)
            os.remove(imageTarPath)

            # Create the XML document to send back
            doc = xml.dom.minidom.Document()

            SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
            SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")
            SOAPBodyElement = doc.createElement("SOAP-ENV:Body")

            uploadPhotoResponseElement = doc.createElement("UploadPhotoResponse")
            successElement = doc.createElement("success")
            successElementText = doc.createTextNode("true")

            successElement.appendChild(successElementText)
            uploadPhotoResponseElement.appendChild(successElement)

            SOAPBodyElement.appendChild(uploadPhotoResponseElement)
            SOAPElement.appendChild(SOAPBodyElement)
            doc.appendChild(SOAPElement)

            return doc.toxml(encoding = "UTF-8")

        def parselog(self,logfile,filename):
            shottime = 0
            aps = {}
            for line in open(logfile):
                time, timestamp, act = line.strip().split(",", 2)
                act = act.split(",")
                act, args = act[0], act[1:]
                if act in ("AP", "NEWAP"):
                    aps.setdefault(args[0], []).append({"time": int(time),"pwr": int(args[1])})
                elif act == "NEWPHOTO":
                    if filename == args[0]:
                        shottime = int(time)
                elif act == "POWERON":
                    if shottime>0:
                        return shottime, aps
                    shottime = 0
                    aps = {}
            if shottime>0:
                return shottime, aps

        def getphotoaps(self, time, aps):
            geotag_lag = int(self.server.config.get('EyeFiServer','geotag_lag'))
            newaps = []
            for mac in aps:
                lag = min([(abs(ap["time"] - time), ap["pwr"]) for ap in aps[mac]], key = lambda a: a[0])
                if lag[0] <= geotag_lag:
                    newaps.append({"mac": mac, "pwr": lag[1]})
            return newaps

        def getlocation(self, aps):
            try:
                geourl = 'maps.googleapis.com'
                headers = {"Host": geourl}
                params = "?browser = none&sensor = false"
                for ap in aps:
                    params += '&wifi = mac:'+'-'.join([ap['mac'][2*d:2*d+2] for d in range(6)])+'|ss:'+str(int(math.log10(ap['pwr']/100.0)*10-50))
                conn = httplib.HTTPSConnection(geourl)
                conn.request("GET", "/maps/api/browserlocation/json"+params, "", headers)
                resp = conn.getresponse()
                result = resp.read()
                conn.close()
            except:
                eyeFiLogger.debug("Error connecting to geolocation service")
                return None
            try:
                try:
                    import simplejson as json
                except ImportError:
                    import json
                return json.loads(result)
            except:
                try:
                    import re
                    result = result.replace("\n"," ")
                    loc = {}
                    loc['location'] = {}
                    loc['location']['lat'] = float(re.sub(r'.*"lat"\s*:\s*([\d.]+)\s*[,}\n]+.*',r'\1',result))
                    loc['location']['lng'] = float(re.sub(r'.*"lng"\s*:\s*([\d.]+)\s*[,}\n]+.*',r'\1',result))
                    loc['accuracy'] = float(re.sub(r'.*"accuracy"\s*:\s*([\d.]+)\s*[,\}\n]+.*',r'\1',result))
                    loc['status'] = re.sub(r'.*"status"\s*:\s*"(.*?)"\s*[,}\n]+.*',r'\1',result)
                    return loc
                except:
                    eyeFiLogger.debug("Geolocation service response contains no coordinates: " + result)
                    return None

        def writexmp(self,name,latitude,longitude):
            if latitude>0:
                ref = "N"
            else:
                ref = "S"
            latitude = str(abs(latitude)).split('.')
            latitude[1] = str(float('0.'+latitude[1])*60)
            latitude = ','.join(latitude)+ref

            if longitude>0:
                ref = "E"
            else:
                ref = "W"
            longitude = str(abs(longitude)).split('.')
            longitude[1] = str(float('0.'+longitude[1])*60)
            longitude = ','.join(longitude)+ref

            FILE = open(name,"w")
            FILE.write("<?xpacket begin = '\xef\xbb\xbf' id = 'W5M0MpCehiHzreSzNTczkc9d'?>\n<x:xmpmeta xmlns:x = 'adobe:ns:meta/' x:xmptk = 'EyeFiServer'>\n<rdf:RDF xmlns:rdf = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\n<rdf:Description rdf:about = '' xmlns:exif = 'http://ns.adobe.com/exif/1.0/'>\n<exif:GPSLatitude>"+latitude+"</exif:GPSLatitude>\n<exif:GPSLongitude>"+longitude+"</exif:GPSLongitude>\n<exif:GPSVersionID>2.2.0.0</exif:GPSVersionID>\n</rdf:Description>\n</rdf:RDF>\n</x:xmpmeta>\n<?xpacket end = 'w'?>\n")
            FILE.close()

        def getPhotoStatus(self,postData):
            eyeFiLogger.debug('postData: %s' % str(postData))

            handler = EyeFiContentHandler()
            parser = xml.sax.parseString(postData,handler)

            # Create the XML document to send back
            doc = xml.dom.minidom.Document()

            SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
            SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")
            SOAPBodyElement = doc.createElement("SOAP-ENV:Body")

            getPhotoStatusResponseElement = doc.createElement("GetPhotoStatusResponse")
            getPhotoStatusResponseElement.setAttribute("xmlns","EyeFi/SOAP/EyeFilmService")

            fileidElement = doc.createElement("fileid")
            fileidElementText = doc.createTextNode("0")
            fileidElement.appendChild(fileidElementText)

            offsetElement = doc.createElement("offset")
            offsetElementText = doc.createTextNode("0")
            offsetElement.appendChild(offsetElementText)

            modeElement = doc.createElement("mode")
            modeElementText = doc.createTextNode("0")
            modeElement.appendChild(modeElementText)

            getPhotoStatusResponseElement.appendChild(fileidElement)
            getPhotoStatusResponseElement.appendChild(offsetElement)
            getPhotoStatusResponseElement.appendChild(modeElement)

            SOAPBodyElement.appendChild(getPhotoStatusResponseElement)

            SOAPElement.appendChild(SOAPBodyElement)
            doc.appendChild(SOAPElement)

            return doc.toxml(encoding = "UTF-8")

        def _get_mac_uploadkey_dict(self):
            macs = {}
            upload_keys = {}
            for key, value in self.server.config.items('EyeFiServer'):
                if key.find('upload_key_') == 0:
                    index = int(key[11:])
                    upload_keys[index] = value
                elif key.find('mac_') == 0:
                    index = int(key[4:])
                    macs[index] = value
            d = {}
            for key in macs.keys():
                d[macs[key]] = upload_keys[key]
            return d

        def startSession(self, postData):
            eyeFiLogger.debug("Delegating the XML parsing of startSession postData to EyeFiContentHandler()")
            handler = EyeFiContentHandler()
            parser = xml.sax.parseString(postData,handler)

            eyeFiLogger.debug("Extracted elements: " + str(handler.extractedElements))

            # Retrieve it from C:\Documents and Settings\<User>\Application Data\Eye-Fi\Settings.xml
            mac_to_uploadkey_map = self._get_mac_uploadkey_dict()
            mac = handler.extractedElements["macaddress"]
            upload_key = mac_to_uploadkey_map[mac]
            eyeFiLogger.debug("Got MAC address of " + mac)
            eyeFiLogger.debug("Setting Eye-Fi upload key to " + upload_key)

            credentialString = mac + handler.extractedElements["cnonce"] + upload_key
            eyeFiLogger.debug("Concatenated credential string (pre MD5): " + credentialString)

            # Return the binary data represented by the hexadecimal string
            # resulting in something that looks like "\x00\x18V\x03\x04..."
            binaryCredentialString = binascii.unhexlify(credentialString)

            # Now MD5 hash the binary string
            m = hashlib.md5()
            m.update(binaryCredentialString)

            # Hex encode the hash to obtain the final credential string
            credential = m.hexdigest()

            # Create the XML document to send back
            doc = xml.dom.minidom.Document()

            SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
            SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")
            SOAPBodyElement = doc.createElement("SOAP-ENV:Body")


            startSessionResponseElement = doc.createElement("StartSessionResponse")
            startSessionResponseElement.setAttribute("xmlns","http://localhost/api/soap/eyefilm")

            credentialElement = doc.createElement("credential")
            credentialElementText = doc.createTextNode(credential)
            credentialElement.appendChild(credentialElementText)

            snonceElement = doc.createElement("snonce")
            snonceElementText = doc.createTextNode("%x" % random.getrandbits(128))
            snonceElement.appendChild(snonceElementText)

            transfermodeElement = doc.createElement("transfermode")
            transfermodeElementText = doc.createTextNode(handler.extractedElements["transfermode"])
            transfermodeElement.appendChild(transfermodeElementText)

            transfermodetimestampElement = doc.createElement("transfermodetimestamp")
            transfermodetimestampElementText = doc.createTextNode(handler.extractedElements["transfermodetimestamp"])
            transfermodetimestampElement.appendChild(transfermodetimestampElementText)

            upsyncallowedElement = doc.createElement("upsyncallowed")
            upsyncallowedElementText = doc.createTextNode("true")
            upsyncallowedElement.appendChild(upsyncallowedElementText)

            startSessionResponseElement.appendChild(credentialElement)
            startSessionResponseElement.appendChild(snonceElement)
            startSessionResponseElement.appendChild(transfermodeElement)
            startSessionResponseElement.appendChild(transfermodetimestampElement)
            startSessionResponseElement.appendChild(upsyncallowedElement)

            SOAPBodyElement.appendChild(startSessionResponseElement)

            SOAPElement.appendChild(SOAPBodyElement)
            doc.appendChild(SOAPElement)

            return doc.toxml(encoding = "UTF-8")

    return EyeFiRequestHandler

def stopEyeFi():
    configfile = sys.argv[2]
    eyeFiLogger.info("Reading config " + configfile)

    config = ConfigParser.SafeConfigParser(defaults = DEFAULTS)
    config.read(configfile)

    port = config.getint('EyeFiServer','host_port')

    """send QUIT request to http server running on localhost:<port>"""
    conn = httplib.HTTPConnection("127.0.0.1:%d" % port)
    conn.request("QUIT", "/")
    conn.getresponse()

def runEyeFi():
    configfile = 'eyefiserver.conf'
    eyeFiLogger.info("Reading config " + configfile)

    config = ConfigParser.SafeConfigParser(defaults=DEFAULTS)
    config.read(configfile)

    # check whether flickr needs to be set up
    if config.getint('EyeFiServer', 'flickr_enable') > 0:
        if len(config.get('EyeFiServer', 'flickr_key')) and len(config.get('EyeFiServer', 'flickr_secret')):
            eyeFiLogger.info('Flickr uploading enabled')
            import flickr_api
            flickr_api.set_keys(config.get('EyeFiServer', 'flickr_key'), config.get('EyeFiServer', 'flickr_secret'))
            try:
                a = flickr_api.auth.AuthHandler.load('./flickr.verifier')
                flickr_api.set_auth_handler(a)
                eyeFiLogger.info('loaded Flickr credentials')
            except:
                a = flickr_api.auth.AuthHandler()
                url = a.get_authorization_url('write')
                print 'Please visit this URL and grant access:'
                print url
                a.set_verifier(raw_input('Enter the value of <oauth_verifier>: '))
                a.save('/tmp/src/flickr.verifier')
                print 'Thanks! This process will now exit. You should then rebuild the Docker image according to the README instructions.'
                sys.exit(0)
        else:
            eyeFiLogger.error('Flickr upload enabled, but flickr_key/flickr_secret not set. Exiting...')
            sys.exit(1)
    else:
        flickr_api = None


    server_address = (config.get('EyeFiServer','host_name'), config.getint('EyeFiServer','host_port'))

    # Create an instance of an HTTP server. Requests will be handled
    # by the class EyeFiRequestHandler
    eyeFiServer = EyeFiServer(config, server_address, EyeFiRequestHandlerFactory(config, flickr_api))
    eyeFiLogger.info("Eye-Fi server started listening on port " + str(server_address[1]))
    eyeFiServer.serve_forever()

def main():
    runEyeFi()

if __name__ == "__main__":
    main()
