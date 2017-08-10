# Berserko - Kerberos authentication for Burp Suite
Released as open source by NCC Group Plc - http://www.nccgroup.trust/

Developed by Richard Turnbull, richard [dot] turnbull [at] nccgroup [dot] trust

http://www.github.com/nccgroup/Berserko

Released under AGPL, see LICENSE for more information

### Introduction ###
Berserko is a Burp extension to add support for performing Kerberos authentication. This is useful for testing in a Windows domain when NTLM authentication is not supported (Burp already handles NTLM). Berserko does not require that the machine running Burp be domain-joined (or even that it is running Windows). 

The only existing solution that we are currently aware of for testing Kerberos applications using Burp is to chain through [Fiddler](http://www.telerik.com/fiddler), with authentication set up according to [these instructions](http://stackoverflow.com/questions/26499875/kerberos-authentication-with-burp-proxy). But Fiddler is Windows-only, and chaining proxies adds complexity and hinders performance, so it's nice to have Kerberos capability within Burp itself. 

### System Requirements ###
* Burp Suite - tested on version 1.7.05 (both Pro and Free)
* Tested on Windows and Linux (Kali)

### Installation ###
Get the latest Berserko jar file from the Releases tab, or from the `berserko\releases` folder

Go to the *Extender* tab in Burp, select *Add*, make sure *Java* is selected as the *Extension type*, and then point it at the jar file. All being well, the *Berserko* tab should be added to the Burp UI.

### Quick Start ###
* Go the *Berserko* tab and tick the *Do Kerberos authentication* checkbox.
* Click the *Change* button in the *Domain Settings* panel and supply the DNS name of the domain (**not** the NETBIOS name) and the hostname (or IP address) of a KDC (domain controller).
* Hit the *Test domain settings* button and check that you get a *Successfully contacted Kerberos service* response.
* Click the *Change* button in the *Domain Credentials* panel and supply a username and password for a domain account (just the plain username, not *MYDOMAIN\user* or *user@mydomain.local* or anything like that).
* Enable Kerberos delegation by letting Berserko create a *krb5.conf* file for you. Click the *Create krb5.conf file* button in the *Delegation* panel and choose a suitable location where the file can be created. Anywhere will do. You don't want to overwrite any existing system-level *krb5.conf* file. Say yes when Berserko asks if you want to set this as the *krb5.conf* file. It sucks that we have to do this (create a file) but it's not Berserko's fault and not Burp's fault - it's a limitation of the Java Kerberos APIs. For more information see the notes on Delegation below.
* Hit the *Test credentials* button and check that you get a *"TGT successfully acquired"* response. Hopefully it will also say *"TGT is forwardable so delegation should work"*.
* Kerberos authentication should now be operational for hosts in the specified domain.

### Settings ###
There are various controls on the *Berserko* tab in Burp.

The *Do Kerberos authentication* checkbox is a master switch. Until it is enabled, Berserko won't do anything at all.

The *Restore defaults* button will return Berserko to the default configuration (in which no domain details or user credentials are present).

The *Clear Kerberos state* button will clear out all Kerberos tickets and other state on the client. There only reason you might need to use this would be if changes had been made to the Kerberos configuration on the server side and you wanted to start from a fresh state.

Some controls have a help button that will pop up more information.

#### Domain Settings ####
Specify the **Domain DNS Name** and the **KDC Host** using the controls in this section. The textboxes can't be edited directly; you have to use the 'Change' button to modify them.

The *Domain DNS Name* should be the DNS name of the domain you wish to authenticate against (to be precise, this is actually the Kerberos realm). This should be something like `mydomain.acme.local`. It should not be the NETBIOS name of the domain (which would be something like `MYDOMAIN`).

The *KDC Host* should be the hostname (or IP address) of a Kerberos KDC (Key Distribution Center). In a Windows domain, a KDC is simply a domain controller.

Having supplied the *Domain DNS Name*, you can use the *Auto* button to try to automatically locate a KDC. It does this by sending a DNS SRV query for the Kerberos service. If one of your DNS servers is a domain controller for the correct domain, this should work. If not, it won't. 

When the *Domain DNS Name* and *KDC Host* have been entered, use the *Test domain settings* button to test connectivity. All being well, you will get a *Successfully contacted Kerberos service* response. 

See the section at the end of this README for lots more information about obtaining the correct values for these Domain Settings.

#### Domain Credentials ####
Specify the **Username** and **Password** for a domain account using the controls in this section. The textboxes can't be edited directly; you have to use the 'Change' button to modify them.

The *Username* should just be the plain username. This should be something like `bob`. It should not be `MYDOMAIN\bob` or `bob@mydomain.acme.local` or similar.

Having supplied the credentials, you can use the *Test credentials* button. This will attempt to acquire a Kerberos ticket-granting ticket for the specified user. If successful, you will get a *TGT successfully acquired* response. If not successful, note that this is a domain authentication attempt, so be careful not to lock out your account.

The password will not be saved in the Berserko config for next time unless the *Save password in Burp config?* checkbox is ticked. All other settings will be saved though.

#### Delegation ####
Some applications use Kerberos delegation on the server side to forward the client's identity to other servers (but there isn't an easy way to determine from the client side if this is in use).

Berserko does support this, but there is a catch. Delegation only works if the user has a *forwardable* TGT (ticket-granting ticket). The Java implementation of Kerberos sadly doesn't provide a way to programmatically specify that a forwardable ticket should be acquired. This can only be done by adding an appropriate entry to the *krb5.conf* configuration file. 

So, for delegation to work, Berserko has to be pointed at a suitable *krb5.conf* file, and there are two possible approaches here. 

The easiest thing to do, and the **recommended approach** is to use the *Create krb5.conf file* button. This will create a suitable file for you at a location of your choice. You can put it in a temporary directory, or your project directory, or wherever. But the same file can be reused indefinitely, so it might make sense to put it somewhere more permanent. The *Change* button lets you select a different file to be used.

If you're interested, the *krb5.conf* file which is created is very simple, and will have the following contents:

    [libdefaults]
	    forwardable = true
		
Alternatively, you could use the *Change* button to point at an existing *krb5.conf* file on the system. The only reason you might want to do this would be if there were other important Kerberos settings in this file that you wanted to be picked up by Berserko (which should work OK in theory, but has not been tested in practice). Note that the default location for this file on Linux is `/etc/krb5.conf` - other operating systems are less likely to have one. If you are pointing to an existing *krb5.conf* file, make sure you edit it to enable forwarding - add `forwardable = true` to the `[libdefaults]` section (or individually for each realm). But be careful. Asking Berserko to create the file for you is going to be the better option 99% of the time.

If you want to know whether your delegation configuration is successful, use the *Check current config* button. This will tell you whether the *krb5.conf* file has been located, and whether the *forwardable* setting is correct. Note also that Berserko will tell you whether or not it successfully acquired a forwardable TGT when you use the *Test credentials* button. 

It's a good idea to make sure that you have a forwardable ticket *before* you start to use an application. It seems that IIS can cache the authentication status of a user on the server side in such a way that switching from a non-forwardable ticket to a forwardable one won't work.

#### Authentication Strategy ####
The settings in this section control whether Berserko attempts Kerberos authentication 'reactively' (i.e. wait to get a 401 response from the server and then resend the request with a Kerberos authentication header added) or 'proactively' (i.e. add the Kerberos authentication header to the outgoing request).

The advantage of proactive authentication is that it only requires one HTTP round trip, while reactive authentication requires two. The disadvantage of proactive authentication is that it is possible that Kerberos authentication headers will be sent to hosts which aren't expecting them. Berserko is also better able to diagnose authentication errors when using the reactive strategy. 

The *Proactive Kerberos authentication, only after initial 401 received* option is a hybrid of these two approaches, where Berserko will authenticate reactively on the first request to a host, but will thereafter be proactive.

#### Scope ####
In this section, you can define which hosts are considered to be in scope for Kerberos authentication.

By default, the *All hosts in this Kerberos domain in scope for Kerberos* box will be ticked. This means that Berserko will attempt Kerberos authentication only to web servers whose hostname ends with the domain DNS name. In many situations this will be sufficient. However, it is possible to have Kerberos-enabled web applications with a hostname which doesn't take this form (assuming that the administrator has set up a suitable Service Principal Name). To take account of this, you can add *additional* hosts to be considered in scope using the list box on the right. Note that wildcards can be used (* matches zero or more characters, ? matches any character except a dot).

Alternatively, you can tick the *All hosts in scope for Kerberos authentication* box. Obviously this has the advantage that you don't need to bother specifying the scope manually. The potential disadvantage of this configuration is that it might lead to Berserko sending Kerberos requests to the KDC to acquire service tickets for hosts which are not in the domain. This might cause performance issues, and might cause privacy issues (if you don't want this information leaked to the KDC). This is likely to be a particular problem with the *Proactive Kerberos authentication* strategy, in which case Berserko is going to try to add a Kerberos authentication header to every request passing through Burp. This combination of options is not recommended, and Berserko will warn you if it is selected (but not actually prevent it).

If neither *All hosts in this Kerberos domain in scope for Kerberos* nor *All hosts in scope for Kerberos authentication* are selected, the only hosts in scope will be those added to the list box.

The *Plain hostnames considered part of domain* option, if selected, means that 'plain hostnames' (i.e. hostnames which consist only of a single component) will be considered part of the domain (and hence automatically in scope if *All hosts in this Kerberos domain in scope for Kerberos* is selected). The main reason you might want to disable this would be if your machine was joined to a different domain from the one being authenticated against using Berserko (in which case, plain hostnames probably refer to hosts in the domain to which you are joined).

If selected, the *Do not perform Kerberos authentication to servers which support NTLM* option will instruct Berserko not to attempt Kerberos authentication against hosts which support NTLM in addition to Kerberos (i.e. hosts that return both `WWW-Authenticate: NTLM` and `WWW-Authenticate: Negotiate` headers).

#### Logging ####
The *Alert Level* and *Logging Level* can be configured here, to either NONE, NORMAL or VERBOSE.

*Alert Level* controls the amount of information sent to Burp's *Alerts* tab.

*Logging Level* controls the amount of information sent to Berserko's standard output (this can be viewed on the *Extender* tab). Note that increasing the *Logging Level* to VERBOSE will cause more information to be provided about any errors or exceptions that might occur.

### Bugs ###
* If the UI for the Berserko tab doesn't display properly, try using Burp's Metal theme.

### Limitations ###
* Berserko won't play particularly nicely with Burp's own *Platform Authentication* feature. It's OK to have Platform Authentication enabled, but don't configure it for any of the hosts that require Kerberos (rather than NTLM) authentication. 
* Berserko can't make use of any custom host mappings defined using Burp's *Hostname Resolution* feature when resolving a KDC hostname. If this is a problem, just specify the IP address of the KDC in the *KDC host* box. Note this isn't an issue for the actual requests being sent from Burp, only for Berserko's own communications with the KDC.

### (Possible) Future plans ###
* Use of already acquired Kerberos tickets on domain-joined machines (not sure if this is possible or not)
* Capability to authenticate to multiple domains at the same time (this should work fine)
* Better control over forwardable tickets and delegation

## Domain DNS names, NETBIOS names, KDC hostnames and all that ##

Berserko needs to know the domain DNS name, and the hostname (or IP address) of a KDC in order to work correctly. You might not have these, so here are some hints and tips for getting hold of them. We'll assume that you have domain credentials in the form of username and password. You might also have one or more of {domain DNS name, domain NETBIOS name, KDC hostname} (but not both the domain DNS name and the DC hostname, because if that were the case you already have everything you need).

We'll use the term *KDC* below, although bear in mind that if you're working with a Windows domain, this is going to be a domain controller. And we'll also say *KDC hostname* as shorthand for *KDC hostname or IP address*, but you should note that Berserko is equally happy with either hostname or IP address.

Most of what follows is specific to Windows domains.

#### If you have the FQDN for a KDC ####

You should be able to obtain the domain DNS name just by removing the first component (i.e. the hostname).

#### If you are on a domain-joined Windows machine (or have access to one) ####

Check the `USERDOMAIN` and `LOGONSERVER` environment variables. These should contain the domain DNS name and KDC hostname respectively, and you'll be done.

There's also a good chance that your DNS server is itself a KDC.

####  If your DNS server is in the domain ####

Check the DNS suffix for your network connection. This might well be the domain DNS name.
There are instructions below on how to use this to get the KDC hostname.

####  If you can reach a server in the domain which supports NTLM authentication ####

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

####  If you have the domain DNS name but not the KDC hostname ####

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

####  If you only have the domain NETBIOS name, but don't know the domain DNS name or the hostname of a KDC ####

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

####  If you have the hostname (or IP address) of a KDC, but not the domain DNS name ####

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

####  If you have none of the above ####

You'll have to start from scratch!

You could try the various NBNS techniques described above.
Alternatively, perform an nmap scan across a suitable range to find hosts with port 88/tcp open. These should be KDCs.

With a bit of luck, one of these ideas will get you KDC hostname and then you can proceed as described above.