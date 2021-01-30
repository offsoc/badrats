from itertools import cycle
import random
import os
import sys


def gen_key():
    alphanum = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789"
    return(''.join(random.choice(alphanum) for choice in range(64))) 

def ekript_js(js_source, key):
    crypted = ""
    for(x,y) in zip(js_source, cycle(key)):
        crypted += (str(x ^ ord(y))) + ","
    return crypted[:len(crypted)-1] # Cut off the last "," since im a retard

def make_loader_template(crypted_js, key):
    code1 = """
var data = "{}"
var x = "{}"
""".format(crypted_js, key)
    code2 = """
function dk(data, x) {
	var d = ""
	data = data.split(",")
	for(var i = 0; i < data.length; i++) {
		d += String.fromCharCode((data[i]) ^ x.charCodeAt(i%x.length))
	}
	return d
}
eval(dk(data, x))
"""
    return(code1 + code2)
 
if __name__ == "__main__":
    try:
        sys.argv[1]
    except:
        print("eKirmani eKript: xor encryption for JS payloads. Thank you to eKirmani for being a huge inspiration for this project.")
        print("Usage: python3 ekript.py payload.js")
        print("[!] No input file specified. Exiting")
        exit()
    with open(sys.argv[1], "rb") as fd:
        js_source = fd.read()

    key = gen_key()
    crypted_js = ekript_js(js_source, key)
    print(make_loader_template(crypted_js, key))
