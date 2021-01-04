# pureldap
Tools to assist with mapping LDAP to AD RFC2307

# Tools/Mapper
Takes an LDIF dump of both LDAP and AD, and outputs PowerShell commands necessary to push Uid & Gid From LDAP -> AD, in occordance to RFC2307.

```
usage: mapper.py [-h] [--ldapsearch] --ad <AD LDIF ldapsearch outputfile>
                 --ldap <LDAP LDIF ldapsearch outputfile>
                 [--group-prefix <i.e. ldapmap_>] --group-ou-dn < i.e.
                 ou=ldapmap,dc=test,dc=com>
                 [--undo <filename to save undo cmds to>] [--allusers]
                 [-u USERS [USERS ...]]

optional arguments:
  -h, --help            show this help message and exit
  --ldapsearch          Print ldapsearch command you can use to pull ldap data
                        for --ad & --ldap
  --ad <AD LDIF ldapsearch outputfile>
                        Active Directory LDIF Dump file
  --ldap <LDAP LDIF ldapsearch outputfile>
                        LDAP LDIF Dump file
  --group-prefix <i.e. ldapmap_>
                        prefix for the imported ldap groups into AD
  --group-ou-dn < i.e. ou=ldapmap,dc=test,dc=com>
                        Full DN for the OU to create groups into
  --undo <filename to save undo cmds to>
                        Write a list of undo command to file which will
                        reverse the changes.
  --allusers            Look at ALL users in LDAP, ignores --users
  -u USERS [USERS ...], --users USERS [USERS ...]
                        Provide users to be mapped, seperated by spaces
```


# Proxy
LDAP Proxy to sit in front of AD, pull linux UID/GID mappings from NIS and present as AD RFC2307.   Built on the python twisted library.


# Pre-Req
 - Python 2.7.x (sorry it's Twisted's fault.)
 - pip install -r requirements.txt
 - Have to install the lastest ldaptor library directly to get latest updates(required):
 ```
 git clone https://github.com/sile16/pureldap.git
 cd ldaptor_proxy
 git clone https://github.com/twisted/ldaptor.git
 ```
 
 - All LDAP traffic needs to be intercepted, easiest is to use a firewall rule on the gateway, where all traffic from {host} with destination port of 389, forward to host this proxy is running on.

 - NIS configured on proxy server. (standard way to setup NIS)
 
 - Proxy host will receive the packet even though it destination is the real LDAP IP.  Have to use iptables to rewrite the dst to be local proxy inbound, and make replies re-write so they appear to come from real LDAP server.
 
 ## NAT rules needed on the proxy server
  ```/sbin/sysctl -w net.ipv4.ip_forward=1
  iptables -t nat -F POSTROUTING
  iptables -t nat -F PREROUTING
  #pre
  iptables -t nat -A PREROUTING -p tcp -d {ldap_server}  --dport 389 -j DNAT --to-destination {local_ip}
  #post
  iptables -t nat -A POSTROUTING -p tcp  -s {local_ip} --sport 389 -j SNAT --to {ldap_server}
  ```

# Usage
```
usage: proxy.py [-h] [-p PORT] server

Usermapping NIS LDAP Proxy.

positional arguments:
  server                IP or Hostname of LDAP server to send queries to.

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  port for backend LDAP server
  ```


