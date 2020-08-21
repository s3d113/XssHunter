import requests
import argparse
import sys
import hashlib
import urllib.parse
import json
import os
from urllib.parse import urlsplit

G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white
def banner():
    print("""   
 __  ______ ____    _   _             _            
 \ \/ / ___/ ___|  | | | |_   _ _ __ | |_ ___ _ __ 
  \  /\___ \___ \  | |_| | | | | '_ \| __/ _ \ '__|
  /  \ ___) |__) | |  _  | |_| | | | | ||  __/ |   
 /_/\_\____/____/  |_| |_|\__,_|_| |_|\__\___|_|   
                                                                                                          
 Coded by: saad113 @aldawsari_saad                                                      


    """) 
    
def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()

def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -e endpoints.txt -p payloads.txt -o output.txt")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-e', '--endpoints', help='Endpoints file', nargs='?', required=True)
    parser.add_argument('-p', '--payloads', help='Payloads file')
    parser.add_argument('-o', '--output', help='Save output to a file')
    return parser.parse_args()


def write_file(filename, result):
    # saving result in output
    with open(str(filename), 'a') as f:
            f.write(result + os.linesep)




def main(endpoints, payloads, output):
    endpointsfile = open(endpoints, 'rb') 
    paths = endpointsfile.readlines() 
    for p in paths:
        decodedp = str(p, encoding='utf-8').strip()
        
        payloadfile = open(payloads, 'rb') 
        lines = payloadfile.readlines() 
        for line in lines:
            decodedline=str(line,'utf-8')
            result = []
            url_parts = list(urllib.parse.urlparse(p))
            query = dict(urllib.parse.parse_qsl(url_parts[4]))
            length = len(query)
            for x in range(length):
                #change the param value to the payload 
                text = (list(query.keys())[x])
                query[text] = decodedline.strip()
                modifiedUrl = urllib.parse.urlencode(query)
                url = urllib.parse.unquote(modifiedUrl)
                split_url = urlsplit(decodedp)
                #reconstruct the URL 
                decodedp = split_url.scheme + "://" + split_url.netloc + split_url.path
                decodedp = decodedp + "?" + url
                #send the attack
                attack = requests.get(decodedp)
                # if the response body contains these kaywords 
                cleanoutput = decodedp + decodedline.strip()
                if decodedline.strip() in attack.text:
                   print(G + "XSS Found: " + R + "At %s%s" % (decodedp,decodedline.strip()))
                   if output: 
                      write_file(output, cleanoutput)




def hunt():
    args = parse_args()
    endpoints = args.endpoints
    payloads = args.payloads 
    output = args.output   
    start = main(endpoints, payloads, output)


if __name__ == "__main__":
    hunt()
