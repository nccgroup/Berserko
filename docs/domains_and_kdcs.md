# Domain DNS names, NETBIOS names, KDC hostnames and all that ##

Berserko needs to know the domain DNS name, and the hostname (or IP address) of a KDC in order to work correctly. You might not have these, so here are some hints and tips for getting hold of them. We'll assume that you have domain credentials in the form of username and password. You might also have one or more of {domain DNS name, domain NETBIOS name, KDC hostname} (but not both the domain DNS name and the DC hostname, because if that were the case you already have everything you need).

We'll use the term *KDC* below, although bear in mind that if you're working with a Windows domain, this is going to be a domain controller. And we'll also say *KDC hostname* as shorthand for *KDC hostname or IP address*, but you should note that Berserko is equally happy with either hostname or IP address.

Most of what follows is specific to Windows domains.

### If you have the FQDN for a KDC ####

You should be able to obtain the domain DNS name just by removing the first component (i.e. the hostname).

### If you are on a domain-joined Windows machine (or have access to one) ####

Check the `USERDOMAIN` and `LOGONSERVER` environment variables. These should contain the domain DNS name and KDC hostname respectively, and you'll be done.

There's also a good chance that your DNS server is itself a KDC.

###  If your DNS server is in the domain ####

Check the DNS suffix for your network connection. This might well be the domain DNS name.
There are instructions below on how to use this to get the KDC hostname.

###  If you can reach a server in the domain which supports NTLM authentication ####

There's a handy nmap script (`http-ntlm-info`) you can use here.
Note this will need to be a server that actually returns `WWW-Authenticate: NTLM`. If it only returns `WWW-Authenticate: Negotiate` that's not sufficient. Of course if the web server you're interested in supports NTLM then maybe you don't need Berserko in the first place.
You'll also need to know the root URL for an application on the server (and provide this as the `http-ntlm-info.root` parameter).

```
nmap -n -Pn -sS -p80 --script http-ntlm-info --script-args http-ntlm-info.root=/path_to_app/ 192.168.1.1

Starting Nmap 7.00 ( https://nmap.org ) at 2017-06-28 13:24 GMT Daylight Time
Nmap scan report for 192.168.1.1
Host is up (0.00s latency).
PORT   STATE SERVICE
80/tcp open  http
| http-ntlm-info:
|   Target_Name: MYDOMAIN
|   NetBIOS_Domain_Name: MYDOMAIN
|   NetBIOS_Computer_Name: WEB1
|   DNS_Domain_Name: mydomain.local
|   DNS_Computer_Name: WEB1.mydomain.local
|   DNS_Tree_Name: mydomain.local
|_  Product_Version: 6.3 (Build 9600)
```

The `DNS_Domain_Name` field contains the value you're looking for. There are instructions below on how to use this to get the KDC hostname.

###  If you have the domain DNS name but not the KDC hostname ####

Assuming your DNS server is in the domain, a SRV query should get the hostname of a KDC for you.

You can do this using *dig*. Append the DNS domain name to `_kerberos._tcp`:

```
dig SRV _kerberos._tcp.mydomain.local

<snip>

;; ANSWER SECTION:
_kerberos._tcp.mydomain.local. 600 IN   SRV     0 100 88 dc1.mydomain.local.

<snip>
```

Get what you need (`dc1.mydomain.local` in this case) from the answer section.

Or with *nslookup*:

```
nslookup -type=SRV _kerberos._tcp.mydomain.local
Server:  UnKnown
Address:  192.168.1.1

_kerberos._tcp.mydomain.local   SRV service location:
          priority       = 0
          weight         = 100
          port           = 88
          svr hostname   = dc1.mydomain.local
dc1.mydomain.local      internet address = 192.168.1.1
```

`svr_hostname` is what you need here.

But the easiest thing to do is probably to use Berserko's *Autolocate KDC* button, which will make the SRV query for you, assuming you have filled in the *Domain DNS Name* box.

###  If you only have the domain NETBIOS name, but don't know the domain DNS name or the hostname of a KDC ####

This is quite a common situation - you might be given credentials for ```DOMAIN\username``` but nothing else.
Here you can try to obtain the hostname of a KDC using NBNS.
Note that this is what Internet Explorer will do on a non-domain-joined machine when you give it ```DOMAIN\username``` credentials for a site requesting Negotiate authentication. It sends an NBNS query of type <1c>, specifying the NETBIOS name of the domain (and the DC will respond to it). Unfortunately there doesn't seem to be an easy way of doing this from the command line in Windows.

Instead, you can use the [nbtscan-1.0.35 tool](http://www.unixwiz.net/tools/nbtscan.html). Use it to scan the IP range where you think the KDC might be, and look for <1c> entries that match.

```
nbtscan-1.0.35.exe -f 192.168.1.0/24
<snip>

192.168.1.1  MYD\DC1                         SHARING DC
  DC1            <00> UNIQUE Workstation Service
  MYD            <00> GROUP  Domain Name
  MYD            <1c> GROUP  Domain Controller
  DC1            <20> UNIQUE File Server Service
  MYD            <1b> UNIQUE Domain Master Browser
  00:0c:29:11:22:33   ETHER  DC1
```

This shows that `DC1` (at 192.168.1.1) is the domain controller for the domain with NETBIOS name `MYD`.

On Linux, `nbtscan` with the `-f` flag will do a very similar job. You could also try the `auxiliary/scanner/netbios/nbname` module in Metasploit.

Hopefully one of these tools will get you the KDC hostname or IP address, then you can use the steps below.

###  If you have the hostname (or IP address) of a KDC, but not the domain DNS name ####

There are a variety of things you can do here. The simplest thing is probably to use nmap's 'smb-os-discovery' script. You can run this against a KDC (or indeed against any domain-joined machine with port 445 open).

```
nmap -n -Pn -p445 --script smb-os-discovery 192.168.1.1

Starting Nmap 7.00 ( https://nmap.org ) at 2017-08-07 22:41 GMT Daylight Time
Nmap scan report for 192.168.1.1
Host is up (0.00s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:00:00:00 (VMware)

Host script results:
| smb-os-discovery:
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: DC1
|   NetBIOS computer name: DC1
|   Domain name: mydomain.local
|   Forest name: mydomain.local
|   FQDN: DC1.mydomain.local
|_  System time: 2017-08-07T22:41:54+01:00
```

The `Domain name` field is what you need.

Alternatively, you could use PowerShell, against a DC:

```
PS C:\Windows\system32\WindowsPowerShell\v1.0> $de = new-object System.DirectoryServices.DirectoryEntry "LDAP://192.168.1.1/rootDSE","",""
PS C:\Windows\system32\WindowsPowerShell\v1.0> $de.Properties.defaultNamingContext
DC=mydomain,DC=local
```

Join the various *DC* components with dots to get the DNS domain name (```mydomain.local``` here).

Or use an LDAP client application such as *ldp*, connect to the DC (you don't have to bind) and read out the *defaultNamingContext* attribute.

###  If you have none of the above ####

You'll have to start from scratch!

You could try the various NBNS techniques described above.
Alternatively, perform an nmap scan across a suitable range to find hosts with port 88/tcp open. These should be KDCs.

With a bit of luck, one of these ideas will get you a KDC hostname and then you can proceed as described above.