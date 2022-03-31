# NixWatch

## *Nix Indicator of Compromise (IOC) Assessment Tool

## The purpose of this tool is to quickly assess a Linux system suspected of being compromised with the following areas in mind:

- Processes
- Directories
- Files
- Users
- Logs (TODO)

## For more information on what Craig Rowland identifies as the "Big Five Areas for Linux Forensics", please visit the below link:

- https://www.sandflysecurity.com/blog/compromised-linux-cheat-sheet/

## Example

Check folder of your choice for suspicious file extensions
```
[*] Folder not empty, prcoeeding...


[*] If a file extension match is found, file is sent to VirusTotal. Exits if none...

File: 123.js with hash: 0bb96c30652b8aebe4ded637b8291a5d07fb1797e7140553202a885229c79963 found!
Upload files to VirusTotal? (Y)es or (N)o
```

