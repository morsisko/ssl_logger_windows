# ssl_logger_windows
Decrypts and logs a process's OpenSSL encrypted traffic

This is modified version of https://github.com/google/ssl_logger for Microsoft Windows operating system. Thanks to this tool you can sniff SSL (HTTPS) traffic without messing with certificate pinning.

# How does it work
It hooks OpenSSL functions that are used to perform SSL encryption/decryption using [frida](https://frida.re/)

# Installation
You need Python3 and following packages:
```
pip install frida
pip install hexdump
```

# Usage
`python ssl_logger.py [-pcap <path>] [-verbose] <process id>`

```
-pcap <path>                 Name of PCAP file to write
-verbose                     Show verbose output
<process id>                 Process whose SSL calls to log
```
Example:
`ssl_logger.py -pcap ssl.pcap 1337`

# Limitations
* It works only for dynamic linked OpenSSL, this means your target **must** import `ssleay32.dll`
* There are problems with logging the ip & port of source and destination
