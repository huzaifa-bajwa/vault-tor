import os
import sys
import ssl
import re
# 
from functools import partial
import random
from http.server import HTTPServer, BaseHTTPRequestHandler, SimpleHTTPRequestHandler
import string
from socket import gethostname
from OpenSSL import crypto, SSL
from time import gmtime, mktime, sleep

class MyHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        print(self.__dict__)
        print("I am here")
        print(self.headers.__dict__)

        file = self.rfile
        content = (file.read(int(self.headers['Content-Length']))).decode("utf-8")
        # print(content)
        password = re.split(r'name="password"\r\n\r\n(.*)\r\n',content)[1]
        assert password == "123"
        filename = re.split(r'filename="(.*)"\r\n',content)[1]
        print(filename)
        text = re.split(r'Content-Type: text/plain\r\n\r\n(.*)\n\r\n------WebKit',content)[1]
        print(text)
        
        sys.stdout.flush()
        

        sys.stdout.flush()
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()

        message = "Hello, World! Here is a POST response"
        self.wfile.write(bytes(message, "utf8"))

def tohex(b):
    return ''.join(format(x, '02x') for x in b)

def getQuote(data):

    if not os.path.exists("/dev/attestation/user_report_data"):
        print("Cannot find `/dev/attestation/user_report_data`; "
            "are you running under SGX?")
        return ""
    
    with open("/dev/attestation/user_report_data", "wb") as f:
        for i in range(len(data)):
            if(i < len(data) and i < 64):
                f.write(data[i].to_bytes(1,'little'))
            else:
                f.write(b'\0')
        
    with open("/dev/attestation/quote", "rb") as f:
        quote = f.read()

    return quote
def printQuote(quote):
    if not quote:
        print("QUOTE DOESN'T EXIST")
        return
    print(f"Extracted SGX quote with size = {len(quote)} and the following fields:")
    print(f"  ATTRIBUTES.FLAGS: {quote[96:104].hex()}  [ Debug bit: {quote[96] & 2 > 0} ]")
    print(f"  ATTRIBUTES.XFRM:  {quote[104:112].hex()}")
    print(f"  MRENCLAVE:        {quote[112:144].hex()}")
    print(f"  MRSIGNER:         {quote[176:208].hex()}")
    print(f"  ISVPRODID:        {quote[304:306].hex()}")
    print(f"  ISVSVN:           {quote[306:308].hex()}")
    print(f"  REPORTDATA:       {quote[368:400].hex()}")
    print(f"                    {quote[400:432].hex()}")
    return

def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def create_self_signed_certificate(certFileName = "certificate.crt", privKeyName = "private.key", password = "hello"):
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().CN = gethostname()
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    password = password.encode()
    
    with open("/tmp/" + certFileName, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open("/tmp/" + privKeyName, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert), k

#### CREATE AN OPENSSL CERTIFICATE
certFileName = "certificate.crt"
privKeyName = "privKey.key"
password = get_random_string(64)
cert, privKey = create_self_signed_certificate(certFileName, privKeyName)

print("certificate generated")

signature = bytes(crypto.sign(privKey, cert, "sha256"))
quote = getQuote(signature)

with open("/tmp/quote.txt", "wb") as f:
    f.write(quote)

#printQuote(quote)

print("quote written")

sys.stdout.flush()

# sleep(2)

html = """
<html>
<form method="post" enctype="multipart/form-data">
  <label for="password">Password:</label><br>
  <input type="text" id="password" name="password"><br>
  <label for="myfile">Select a file:</label>
  <input type="file" id="myfile" name="myfile">
  <div>
    <button>Submit</button>
  </div>
</form>
</html>
"""
with open("/scripts/assets/addnew.html", "w") as f:
    f.write(html)


dir = os.path.join(os.path.dirname(__file__), 'assets')
handler = partial(MyHTTPRequestHandler, directory=dir)
httpd = HTTPServer(('localhost', 4443), handler)



# httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="/tmp/" + privKeyName, certfile="/tmp/" + certFileName, server_side=True)

httpd.serve_forever()




# When someone connects send quote file (quote.txt)