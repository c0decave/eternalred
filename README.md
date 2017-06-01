# ETERNALRED

smb_enum - samba share scanner looking for shares accessable without authentication
payload - test payload for upload

# NOTE

Exploit code for eternal red not included, for obvious reasons ;)

# USAGE

usage: smb_enum.py [-h] [-l HOST] [-L HOSTLIST] [-p PORT] [-t THRCNT]
                   [-T TIMEOUT] [-o OUTFILE] [-r UNRANDOM] [-P PAYL]

smb public share enumerator 0.1 by the dash

optional arguments:
  -h, --help            show this help message and exit
  -l HOST, --host HOST  host to check version
  -L HOSTLIST, --hostlist HOSTLIST
                        hostlist to check version
  -p PORT, --port PORT  ipmi port
  -t THRCNT, --threads THRCNT
                        how many threads
  -T TIMEOUT, --timeout TIMEOUT
                        timeout of socket recv
  -o OUTFILE, --outfile OUTFILE
                        outfile in txt format
  -r UNRANDOM, --unrandom UNRANDOM
                        disable random targetlist
  -P PAYL, --payload PAYL
                        payload to upload

Use against one target:
./smb_enum.py -l 1.1.1.1
Hostmode: 1.1.1.1
Targets: 1
1.1.1.1:139 READ public .
1.1.1.1:139 READ public ..
1.1.1.1:139 READ public no
1.1.1.1:139 READ public such
1.1.1.1:139 READ public agency
1.1.1.1:139 WRITE public

Read like that:
Ip Address:Port,READ/WRITE Access, Name of the Share, Name of the File 

Output is easily grepable. If you want to check for all found WRITEable shares in your network.

For WRITE check there is a easy payload file delivered, called payload. You can replace it, if you wish.
Use option -o for generating a logfile.
