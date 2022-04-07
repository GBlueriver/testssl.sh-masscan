#!/usr/bin/python3
# Import testssl.sh CSV to ELasticSearch

from elasticsearch_dsl import Document, Object, Date, Text, Keyword, Integer, Short, Boolean
from datetime import datetime
from tzlocal import get_localzone
import csv
import re
import pprint     # for debugging purposes only

pp = pprint.PrettyPrinter(indent=4)

tz = get_localzone()
reDefaultFilename = re.compile("(?:^|/)(?P<ip>\d+\.\d+\.\d+\.\d+)(:(?P<port>\d+))?-(?P<datetime>\d{8}-\d{4})\.csv$")
reProtocol = re.compile("^(?:SSLv\\d|TLS\\d(?:_\\d)?)$")
reCipherTests = re.compile("^std_(.*)$")
reIpHostColumn = re.compile("^(.*)/(.*)$")
reCipherColumnName = re.compile("(^cipher_)(?!negotiated)")

reCipherDetails = re.compile("^\\S+\\s+(\\S+)")
reCipherTests = re.compile("^std_(.*)$")
reDefaultProtocol = re.compile("^Default protocol (\\S+)")
reDefaultCipher = re.compile("(.*?)(?:$|[,\\s])")
reKeySize = re.compile("(\\d+) bits")
reSignAlgorithm = re.compile("(.*)")
reFPMD5 = re.compile("(\\S+)")
reFPSHA1 = re.compile("(\\S+)")
reFPSHA256 = re.compile("(\\S+)")
reCN = re.compile("(.*)")
reSAN = re.compile("(.*)")
reIssuer = re.compile("(.*)")
reAll = re.compile("(.*)")
#reIssuer = re.compile("'issuer= (.*?)' \\(")
reExpiration = re.compile("(.*)")
reOCSPURI = re.compile("(?!--*)(.*)")

reOffers = re.compile("(?<!not )offered")
reNotOffered = re.compile("not offered")
reOk = re.compile("OK")
reYes = re.compile("yes", re.IGNORECASE)
#reVulnerable = re.compile("(?![OK])(.*)", re.IGNORECASE)
reVulnerable = re.compile("(?![OK])(?![INFO])(.*)", re.IGNORECASE)

class DocTestSSLResult(Document):

    source = Text(fields={'raw': Keyword()})
    result = Boolean()
    timestamp = Date()
    ip = Keyword()
    hostname = Keyword()
    port = Integer()
    svcid = Keyword()
    protocols = Keyword(multi=True)
    ciphers = Text(multi=True, fields={'raw': Keyword()})
    ciphertests = Keyword(multi=True)
    serverpref = Object(
            properties = {
                "cipher_order": Boolean(),
                "protocol": Keyword(),
                "cipher": Text(fields={'raw': Keyword()})
                })
    cert = Object(
            properties = {
                "keysize": Short(),
                "signalgo": Text(fields={'raw': Keyword()}),
                "md5_fingerprint": Keyword(),
                "sha1_fingerprint": Keyword(),
                "sha256_fingerprint": Keyword(),
                "cn": Text(fields={'raw': Keyword()}),
                "san": Text(multi=True, fields={'raw': Keyword()}),
                "issuer": Text(fields={'raw': Keyword()}),
                "ev": Boolean(),
                "expiration": Date(),
                "ocsp_uri": Text(fields={'raw': Keyword()}),
                "Crl_url": Text(fields={'raw': Keyword()}),
                "ocsp_stapling": Boolean(),
                })
    vulnerabilities = Keyword(multi=True)

    def parseCSVLine(self, line):
        if line['id'] == "id":
            return
                
        if not self.ip or not self.hostname or not self.port:   # host, ip and port
            m = reIpHostColumn.search(line['fqdn/ip'])
            if m:
                self.hostname, self.ip = m.groups()
            self.port = int(line['port'])

        if reProtocol.search(line['id']) and reOffers.search(line['finding']):     # protocols
            self.result = True
            m = reProtocol.search(line['id'])
            if m:
                self.protocols.append(line['id'].upper())
        

        elif reCipherColumnName.search(line['id']):                  # ciphers IT WORKS
            m = reCipherDetails.search(line['finding'])
            if m:
                self.ciphers.append(m.group(1))
        


        elif reCipherTests.search(line['id']) and reVulnerable.search(line['finding']):                       # cipher tests
            m = reCipherTests.search(line['id'])
            print(m)
            if m:
                self.ciphertests.append(m.group(1))
        
        
        if line['id'] == "cipher_order":                                 # server prefers cipher IT WORKS
            self.serverpref.cipher_order = bool(reOk.search(line['severity']))
        
        
        elif line['id'] == "protocol_negotiated":                           # preferred protocol IT WORKS
            m = reDefaultProtocol.search(line['finding'])
            
            if m:
                self.serverpref.protocol = m.group(1)
        

        elif line['id'] == "cipher_negotiated":                          # preferred cipher  IT WORKS
            m = reDefaultCipher.search(line['finding'])
            if m:
                self.serverpref.cipher = m.group(1)
        

        elif line['id'] == "cert_keySize":                              # certificate key size IT WORKS
            m = reKeySize.search(line['finding'])
            if m:
                self.cert.keysize = int(m.group(1))
        

        elif line['id'] == "cert_signatureAlgorithm":                             # certificate sign algorithm IT WORKS
            m = reSignAlgorithm.search(line['finding'])
            if m:
                self.cert.signalgo = m.group(1)
        


        elif line['id'] == "cert_fingerprintSHA1":                           # certificate fingerprints SHA1 IT WORKS
            
            m = reFPSHA1.search(line['finding'])
            if m:
                self.cert.sha1_fingerprint = m.group(1)
            
        

        elif line['id'] == "cert_fingerprintSHA256":                           # certificate fingerprints SHA256 IT WORKS
            
            m = reFPSHA256.search(line['finding'])
            if m:
                self.cert.sha256_fingerprint = m.group(1)

        elif line['id'] == "cert_fingerprintMD5":                           # certificate fingerprints MD5 IT WORKS
            m = reFPMD5.search(line['finding'])
            if m:
                self.cert.md5_fingerprint = m.group(1)


        elif line['id'] == "cert_commonName":                                    # certificate CN IT WORKS
            m = reCN.search(line['finding'])
            if m:
                self.cert.cn = m.group(1)
        

        elif line['id'] == "cert_subjectAltName":                                   # certificate SAN KINDA WORKS NEEDS REVISION
            m = reSAN.search(line['finding'])
            #print(m)
            if m:
            	self.cert.san = m.group(1)

				#sans = m.group(1)
                #for san in sans.split(" "):
                #    if san != "--":
                #        self.cert.san.append(san)"""
        		

        elif line['id'] == "cert_caIssuers":                                # certificate issuer IT WORKS
            m = reIssuer.search(line['finding'])
            if m:
                self.cert.issuer = m.group(1)

        

        elif line['id'] == "ev":                                    # certificate extended validation NOT SUERE
            self.cert.ev = bool(reYes.search(line['finding']))
        

        elif line['id'] == "cert_notAfter":                            # certificate expiration IT WORKS
            m = reExpiration.search(line['finding'])
            if m:
                unparsedDate = m.group(1)
                self.cert.expiration = datetime.strptime(unparsedDate, "%Y-%m-%d %H:%M") 
        

        elif line['id'] == "cert_ocspURL":                              # certificate OCSP URI IT WORKS ELSE NEEDS REWORK
            m = reOCSPURI.search(line['finding'])
            #print(m)
            if m:
                self.cert.ocsp_uri = m.group(1)
            else:
                self.cert.ocsp_uri = "-"

        
        elif line['id'] == "cert_crlDistributionPoints":                              # certificate CRL WORKS
            m = reAll.search(line['finding'])
            #print(m)
            if m:
                self.cert.Crl_url = m.group(1)
            else:
                self.cert.Crl_url = "-"
        

        elif line['id'] == "OCSP_stapling":                         # certificate OCSP stapling
            self.cert.ocsp_stapling = not bool(reNotOffered.search(line['finding']))
        

        elif line['id'] in ("heartbleed", "CCS", "secure_renego", "secure_client_renego", "CRIME_TLS", "SWEET32", "POODLE_SSL", "fallback_SCSV", "FREAK", "DROWN", "LOGJAM" , "BEAST", "LUCKY13", "RC4") and reVulnerable.search(line['severity']):
            m = reVulnerable.search(line['severity'])
            if str(m.group(1)) != '':
            	self.vulnerabilities.append(line['id'].upper())

    


    def parseCSV(self, csvfile):
        if self.source:
            m = reDefaultFilename.search(self.source)
            if m:
                self.ip = m.group('ip')
                self.port = int(m.group('port') or 0)
                self.timestamp = datetime.strptime(m.group('datetime'), "%Y%m%d-%H%M")
        csvReader = csv.DictReader(csvfile, fieldnames=("id", "fqdn/ip", "port", "severity", "finding", "cve", "cwe"), delimiter=',', quotechar='"')
        for line in csvReader:
            self.parseCSVLine(line)

    def save(self, **kwargs):
        if not self.timestamp:
            self.timestamp = datetime.now(tz)
        if not self.port:
            raise ValueError("Empty scan result")

        self.svcid = "%s:%d" % (self.ip, int(self.port) or 0)
        if not self.result:
            self.result = False

        if 'debug' in kwargs and kwargs['debug']:
            pp.pprint(self.to_dict())
        return super().save()
