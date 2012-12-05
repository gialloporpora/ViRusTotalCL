ViRusTotalCL
============

Python script to upload files to VirusTotal and getting report.

##Usage

1. If you don't have the *simplejson* module install it, the easy way is to use *pip*: `pip install simplejson`.
2. Edit the file *vtcl.py* and insert your VirusTotal's API key.
3. You're ready to go. 

To upload a file:

```
vtcl.py filename
```

Wait some minutes since VirusTotal perform the scan report and issue the same command to see the report.

To force VirusTotal to rescan the file:

```
vtcl.py filename -r
```

To save the log in a file use:

```
vtcl.py filename -l
```

Type:

```
vtcl.py --help
```

to get help as usual.


