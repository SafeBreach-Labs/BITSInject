# BITSInject

A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service). Use this tool to inject a job with LocalSystem rights (NT AUTHORITY\SYSTEM), and set a command line to run at session 0, as LocalSystem.
This tool introduces a new undocumented way of controlling BITS jobs.
The program you set as the command line will be executed by the svchost.exe that runs BITS, using CreateProcessAsUserW.

Executing this tool requires local Administrator rights.

* This tool performs the suggested queue injection method that was presented at DEF CON 25
* The new general technique presented allows injection and wide manipulation on the queue. This tool is using this technique specifically to gain LocalSystem execution. The injected SYSTEM job gets the properties from the given parameters

## References

* [White Paper](https://go.safebreach.com/rs/535-IXZ-934/images/BITSINJECT.pdf)
* [DEF CON 25 Talk Brief - BITSInject](https://defcon.org/html/defcon-25/dc-25-speakers.html#Azouri)
* [Talk Slides](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20Dor-Azouri-BITSInject.pdf)
* [SimpleBITSServer](https://github.com/SafeBreach-Labs/SimpleBITSServer) - an optional complementary tool to be used in conjuction with this tool
* [Behavior:Win32/BitsInject.A!attk](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Behavior:Win32/BitsInject.A!attk&ThreatID=-2147244170) - Windows Defender Threat Signature

## Folders in this rep:
* **\bt_templates** - An *010 Editor* template to parse and easily edit your desired state file.
* **\job_payloads** - The base job payloads that were crafted and are edited according to the parameters you specify, before injecting to the BITS queue.
* **\state_files** - Sample pre-made state files to examine or to overwrite your own.

## Usage

Quick & Easy mode - to run a program as SYSTEM:

```
python BITSInject.py --S "C:\\Windows\\System32\\cmd.exe"
```

Full Usage example:

```
python BITSInject.py I_WANT_YOUR_SYSTEM http://127.0.0.1:8080/exe.exe c:\\temp\\exe.exe "C:\\Windows\\System32\\cmd.exe" --vol_path "\\?\Volume{417e8a50-0000-0000-0000-501f00000000}\\" --args "C:\\temp\\inputfile.txt" --localhost_server_port 8080
```

* BITSInject.py -h
* Must run on a Windows OS to use the Microsoft Windows BITS Service. Currently supports Windows 7 and Windows 10. Support for Windows 8 not tested, can be added upon request.
* Optionally run SimpleBITSServer in background and set the job's RemoteURL to that server to accept a file or intentionally drive the job into the ERROR mode (explained in white paper above).
* See references about setting a program in the command line to execute - Interactive VS non-interactive (UI0Detect)



## Authors

**Dor Azouri** - *Initial work*

See also the list of [contributors](https://github.com/SafeBreach-Labs/BITSInject/graphs/contributors) who participated in this project.

## License

[BSD 3](https://github.com/SafeBreach-Labs/BITSInject/blob/master/LICENSE) - clause "New" or "Revised" License
