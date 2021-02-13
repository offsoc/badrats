# Badrats

Badrat C2 -- Python server, JScript, HTA, Powershell, and C# implants. HTTP(S) comms. Not a good C2.

Badrat v1.6.9

**Supported Features**

* 4 different rat types (HTA, JScript, Powershell, C#), for operational flexibility. All rats support all features below
* Command shell access via Powershell.exe or cmd.exe
* Spawn new rats
* File upload and download capability for binary or text files
* Download and run powershell scripts mostly in memory
* Download and run compiled C# (.NET) assemblies mostly in memory
* Create a new process and run shellcode inside of it
* Interact with all rats simultaneously
* Quit and gracefully clean up rats 
* Payloads served at a random URI accessable via POST or GET

Read the blog post here: https://henpeebin.com/kevin/blog/badrats-c2-initial-access-payloads.html

![image](/uploads/55cacc2c41463365ee6b86171b4ce5cc/image.png)

Viewing current rats and running a command

![image](/uploads/c9ac3ed3548edaf8550f007e487bf1aa/image.png)

Running a Powershell script on an HTA rat with msbuild.exe

![image](/uploads/2704d05148ed58402a8a3509da693cac/image.png)

Running a C Sharp program on a js rat using the `cs` keyword

![image](/uploads/be43bcb34c075851dd77da0da35eaffb/image.png)

Downloading an lsass minidump:

![image](/uploads/0947aaeb26deb423f4ba5de43c39fe31/image.png)

![image](/uploads/a82934014ffc695d8224a59c0036a7bc/image.png)

To do:

~~Add python readline~~

~~Add ps1 client~~

~~Format js to fit into hta file~~

~~Add C client~~

~~Add ability to load Powershell scripts (like scriptimport/scriptcmd)~~

Fix powershell errors not showing up with psh

~~Add psh to hta rat (I'm lazy)~~

~~Fix psh output files not being deleted from %temp%~~ Fixed in #081256ba

~~modify `psh` to allow extra Powershell commands after the imported file~~

~~Add `cs` to ps1 rats~~ Fixed in #e11e33a8

~~Add C Sharp rat (instead of python rat (nobody wants that))~~ Fixed in #2c40c41

Change C# spawn to create a whole new process instead of just appdomain

Prevent loaded .NET assemblies from calling either Environment.Exit() or ExitProcess() and killing the rat

**Special Thanks**

* Joe Route (@rowdyjoe)
* RJ Stallkamp (@rstallkamp)

A decent portion of code was written by them and with their help. Thank you guys.
