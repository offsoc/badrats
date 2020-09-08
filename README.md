# Badrats

Badrat C2 -- Python server, JScript, HTA, Powershell, and C implants. HTTP(S) comms. Not a good C2.

Badrat v1.0 Stable

Read the blog post here: https://henpeebin.com/kevin/blog/badrats-c2-initial-access-payloads.html

![image](/uploads/55cacc2c41463365ee6b86171b4ce5cc/image.png)

Viewing current rats and running a command

![image](/uploads/55fb1a39bafee727bf216e45e7e04ee2/image.png)

Running a Powershell script on an HTA rat with msbuild.exe

![image](/uploads/2704d05148ed58402a8a3509da693cac/image.png)

Running a C Sharp program on a js rat using the `cs` keyword

![image](/uploads/be43bcb34c075851dd77da0da35eaffb/image.png)

To do:

~~Add python readline~~

~~Add ps1 client~~

~~Format js to fit into hta file~~

~~Add C client~~

Add Python client

~~Add ability to load Powershell scripts (like scriptimport/scriptcmd)~~

Fix powershell errors not showing up with psh

~~Add psh to hta rat (I'm lazy)~~

~~Fix psh output files not being deleted from %temp%~~ Fixed in #081256ba

~~modify `psh` to allow extra Powershell commands after the imported file~~

Add `cs` to ps1 rats

Add C Sharp rat (instead of python rat (nobody wants that))
