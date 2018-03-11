# Universal Dynamic Virtual Channel connector for Remote Desktop Services (UDVC) #
Terminal Services (or Remote Desktop Services) are offering many hidden features for those who want to dig deeper. One of these services is the Dynamic Virtual Channel that enables us to communicate over an open RDP connection without the need to open a new socket, connection or a port on a firewall. These channels can be used to hide data from active network devices, to bypass firewalls, to implement device drivers over networks or just to help penetration testers to transfer data. The possibilities  are endless.

The real reason why this project was created is [XFLTReaT](https://github.com/earthquake/XFLTReaT). This could be used to build up a "VPN" over segregated networks and finally it enables testing over jumpboxes without requesting firewall changes. In a nutshell it makes penetration testers' life easier.

### How does this work? ###
You need to install a plugin (*.dll*) on your client computer that you use to connect to the RDP server. On the RDP server you need to use the other half of the project the *.exe*, which creates the channel between the plugin and the server executable. 
If you want to know more details, please scroll down.

### Installation ###
**It is Windows only.** Dynamic Virtual Channels were introduced in **Window Server 2008 & Windows Vista SP1**. These **and** anything **newer** than these should be good to go.

You can grab the whole project and compile it by yourself or just use the compiled binaries from the [Releases section](https://github.com/earthquake/UniversalDVC/releases). It is important that the correct binary is used in all cases, please select the correct one for the corresponding architecture (if your client is 32bit but the server is 64bit then grab the 32bit dll and 64bit exe).
The *.dll* needs to be placed on the client computer in any directory (for long-term use, you can put it into the %SYSROOT%\\system32\\ or %SYSROOT%\\SysWoW64\\) and install it with the following command as an elevated user (a.k.a Administrator): 
`regsvr32.exe UDVC-Plugin.dll`
If you wish to remove it: 
`regsvr32.exe /u UDVC-Plugin.dll`
**Every time you connect to an RDP server from now on, this plugin will be loaded and will configure itself as it was specified in the registry (see below).**

The *.exe* needs to be put on the RDP server and run as any user.

### Modes supported ###
Both sides support three modes at the moment: 
#### Socket server mode (0 - default)
When this mode is enabled, then a listener will be set up on the defined port and interface (IP address).
#### Socket client mode (1)
In this mode a connection will be made towards a listener on the defined IP address and port.
#### Named Pipe mode (2)
This mode sets up a Named Pipe with the specified name. As an example: this mode can be used for other tools to do IPC communication over RDP. Unfortunately, Named Pipes are written to the disk so it is considered slow compared to the socket modes. **If you care about the bandwith, please use the socket modes.**

### Options/Configuration ###
Both the client and the server binary act the same way and it can be configured with the same options.
* **mode**: *0* for listen(), *1* for connect() and *2* for creating a Named Pipe
* **ip**: which UP to connect to or bind to
* **port**: which port to connect to or bind to
* **namedpipename**: name of the named pipe
* **priority** (server binary only) *LOW, MEDIUM, HIGH, REAL* priorities for data transmission. *REAL* priority could severely affect the accessibility of the session in case of an intense data transfer, since the protocol prioritizes data over the control. 

The server binary will read the options from the command line.
```
PS C:\Users\UDVC\> .\UDVC-Server.exe -h
Universal Dynamic Virtual Channel server application

Usage: C:\Users\UDVC\UDVC-Server.exe [-s | -c [-p port [-h ip]] | -m [-n name]] [-0 | -1 | -2 | -3]
Socket server mode -s (default) OR
Socket client mode -c:
        -p port   port to bind the listener
        -i ip     ip to bind the listener (default: 127.0.0.1)

Named pipe mode -m:
        -n name   name of the named pipe (by default: "\\.\pipe\UDVC_{RDP SESSION NUMBER}")

Data transfer priority parameters:
        -0        real time             (WTS_CHANNEL_OPTION_DYNAMIC_PRI_REAL)
        -1        high priority         (WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH) - default
        -2        medium priority       (WTS_CHANNEL_OPTION_DYNAMIC_PRI_MED)
        -3        low priority          (WTS_CHANNEL_OPTION_DYNAMIC_PRI_LOW)
```

The client *.dll*  reads all the options from the registry, the values can be found under the following key:
`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Terminal Server Client\Default\AddIns\UDVC-Plugin`

### Usage
The listeners, connections or named pipes are only created when the server executable was able to connect to the plugin dll. It depends on your configuration, but by default when the Virtual Channel connection was made (the plugin was loaded properly, the server binary was executed) it listens on the localhost:31337 on both endpoints. When you connect to these ports and send data through the socket, it will show up on the other side.

### Issues
In case the plugin does not load or the executable does not run because it is missing some DLLs for example the VCRUNTIME140.DLL, you might want to install the [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145) package.

