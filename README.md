# Badrats

Badrat C2 -- Python server, JScript, HTA, Powershell, and C# implants. HTTP(S) and SMB comms. Not a good C2.

![image](/uploads/583cdbaa77b8697afb06e78d13469403/image.png)

Badrat v2.1.2 (beta)

Written by Kevin Clark -- Tweet me your implant development opinions at [@GuhnooPlusLinux](https://twitter.com/GuhnooPlusLinux)

Requires Python 3.7 or higher

For help setting up Badrat and other information, read: https://gitlab.com/KevinJClark/badrats/-/wikis/Badrats-Help#getting-started

Read the blog post here: https://henpeebin.com/kevin/blog/badrats-c2-initial-access-payloads.html

![image](/uploads/cbfcd07a4fd7e45f041ae767a0140fee/image.png)

Viewing current rats

![image](/uploads/3e8994413ee9361481a8ff3e716808f4/image.png)

Running a Powershell script on a JScript rat

![image](/uploads/eff101c935bad844f983c3b26c798b58/image.png)

Executing a .NET assembly on an HTA rat

![image](/uploads/7591708ca4153e19eeb6ea60fc5c6348/image.png)

Spawning a new JScript rat

![image](/uploads/34f5577456977583be9c5da7be7bf281/image.png)

Running a shell command and downloading an lsass minidump:

![image](/uploads/dc969beaab3c738b00d1b07730af63a1/image.png)

Linking a JScript rat to a C# rat and executing an assembly

![image](/uploads/e244425daf0f5c069703c4a238578a79/image.png)



To do:

~~Add python readline~~

~~Add ps1 client~~

~~Format js to fit into hta file~~

~~Add C client~~

~~Add ability to load Powershell scripts (like scriptimport/scriptcmd)~~

~~Fix powershell errors not showing up with psh~~

~~Add psh to hta rat (I'm lazy)~~

~~Fix psh output files not being deleted from %temp%~~ Fixed in #081256ba

~~modify `psh` to allow extra Powershell commands after the imported file~~

~~Add `cs` to ps1 rats~~ Fixed in #e11e33a8

~~Add C Sharp rat (instead of python rat (nobody wants that))~~ Fixed in #2c40c41

Change C# spawn to create a whole new process instead of just appdomain

Prevent loaded .NET assemblies from calling either Environment.Exit() or ExitProcess() and killing the rat

~~Support Peer to peer rats over SMB file shares (2.0 release goal)~~

**Special Thanks**

* Forrest Kasler (@FKasler)
* Joe Route (@r0wdyjoe)
* RJ Stallkamp (@Z3rO_C00L)
* Skyler Knecht (@skylerknecht)

A decent portion of code was written by them and with their help. Thank you guys.
