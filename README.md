# Berserko - Kerberos authentication for Burp Suite
### Introduction ###
Berserko is a Burp extension to add support for performing Kerberos authentication. This is useful for testing in a Windows domain when NTLM authentication is not supported (Burp already handles NTLM). Berserko does not require that the machine running Burp be domain-joined (or even that it is running Windows). 

The only existing solution that we are currently aware of for testing Kerberos applications using Burp is to chain through [Fiddler](http://www.telerik.com/fiddler), with authentication set up according to [these instructions](http://stackoverflow.com/questions/26499875/kerberos-authentication-with-burp-proxy). But Fiddler is Windows-only, and chaining proxies adds complexity and hinders performance, so it's nice to have Kerberos capability within Burp itself. 

### System Requirements ###
* Burp Suite - tested on version 1.7.05 (both Pro and Free)
* Tested on Windows and Linux (Kali)

### Installation ###
Get the Berserko jar file from the `berserko\jar` folder in this repository.

Go to the *Extender* tab in Burp, select *Add*, make sure *Java* is selected as the *Extension type*, and then point it at the jar file. All being well, the *Berserko* tab should be added to the Burp UI.

### Quick Start ###
* Go the *Berserko* tab and tick the *Do Kerberos authentication* checkbox
* Click the *Change* button in the *Domain Settings* panel and supply the DNS name of the domain (**not** the NETBIOS name) and the hostname (or IP address) of a KDC (domain controller)
* Hit the *Test domain settings* button and check that you get a *Successfully contacted Kerberos service* response
* Click the *Change* button in the *Domain Credentials* panel and supply a username and password for a domain account (just the plain username, not *MYDOMAIN\user* or *user@mydomain.local* or anything like that)
* Hit the *Test credentials* button and check that you get a *TGT successfully acquired* response
* Kerberos authentication should now be operational for hosts in the specified domain

### Settings
There are various controls on the *Berserko* tab in Burp.

The *Do Kerberos authentication* checkbox is a master switch. Until it is enabled, Berserko won't do anything at all.

The *Restore defaults* button will return Berserko to the default configuration (in which no domain details or user credentials are present).

Some controls have a help button that will pop up more information.

#### Domain Settings
Specify the **Domain DNS Name** and the **KDC Host** using the controls in this section. The textboxes can't be edited directly; you have to use the 'Change' button to modify them.

The *Domain DNS Name* should be the DNS name of the domain you wish to authenticate against (to be precise, this is actually the Kerberos realm). This should be something like `mydomain.acme.local`. It should not be the NETBIOS name of the domain (which would be something like `MYDOMAIN`).

The *KDC Host* should be the hostname (or IP address) of a Kerberos KDC (Key Distribution Center). In a Windows domain, a KDC is simply a domain controller.

Having supplied the *Domain DNS Name*, you can use the *Auto* button to try to automatically locate a KDC. It does this by sending a DNS SRV query for the Kerberos service. If one of your DNS servers is a domain controller for the correct domain, this should work. If not, it won't. 

When the *Domain DNS Name* and *KDC Host* have been entered, use the *Test domain settings* button to test connectivity. All being well, you will get get a *Successfully contacted Kerberos service* response. 

#### Domain Credentials
Specify the **Username** and **Password** for a domain account using the controls in this section. The textboxes can't be edited directly; you have to use the 'Change' button to modify them.

The *Username* should just be the plain username. This should be something like `bob`. It should not be `MYDOMAIN\bob` or `bob@mydomain.acme.local` or similar.

Having supplied the credentials, you can use the *Test credentials* button. This will attempt to acquire a Kerberos ticket-granting ticket for the specified user. If successful, you will get a *TGT successfully acquired* response. If not successful, note that this is a domain authentication attempt, so be careful not to lock out your account.

The password will not be saved in the Berserko config for next time unless the *Save password in Burp config?* checkbox is ticked. All other settings will be saved though.

#### Authentication Strategy
The settings in this section control whether Berserko attempts Kerberos authentication 'reactively' (i.e. wait to get a 401 response from the server and then resend the request with a Kerberos authentication header added) or 'proactively' (i.e. add the Kerberos authentication header to the outgoing request).

The advantage of proactive authentication is that it only requires one HTTP round trip, while reactive authentication requires two. The disadvantage of proactive authentication is that it is possible that Kerberos authentication headers will be sent to hosts which aren't expecting them. Berserko is also better able to diagnose authentication errors when using the reactive strategy. 

The *Proactive Kerberos authentication, only after initial 401 received* option is a hybrid of these two approaches, where Berserko will authenticate reactively on the first request to a host, but will thereafter be proactive.

#### Options
If selected, the *Do not perform Kerberos authentication to servers which support NTLM* option will instruct Berserko not to attempt Kerberos authentication against hosts which support NTLM in addition to Kerberos (i.e. hosts that return both `WWW-Authenticate: NTLM` and `WWW-Authenticate: Negotiate` headers).

The *Plain hostnames considered part of domain* option, if selected, means that Kerberos authentication will be attempted against hosts which are specified by 'plain hostnames' (i.e. hostnames that are not qualified with the domain). The main reason you might want to disable this would be if your machine was joined to a different domain from the one being authenticated against using Berserko (in which case, plain hostnames probably refer to hosts in the domain to which you are joined).

#### Logging
The *Alert Level* and *Logging Level* can be configured here, to either NONE, NORMAL or VERBOSE.

*Alert Level* controls the amount of information sent to Burp's *Alerts* tab.

*Logging Level* controls the amount of information sent to Berserko's standard output (this can be viewed on the *Extender* tab). Note that increasing the *Logging Level* to VERBOSE will cause more information to be provided about any errors or exceptions that might occur.

### Limitations ###
* Berserko won't play particularly nicely with Burp's own *Platform Authentication* feature. It's OK to have Platform Authentication enabled, but don't configure it for any of the hosts that require Kerberos (rather than NTLM) authentication. 
* Berserko has not been tested against any Kerberos instances except Windows. In theory it should work successfully against other Kerberos implementations, but that is not the focus of development.
* Behaviour when a TGT (ticket-granting ticket) expires is so far untested. Normal lifetime of these tickets is 10 hours. If ticket expiry causes any problem, then disabling and re-enabling the Berserko extension should solve the problem (by forcing Berserko to acquire a new TGT).
* Berserko can't make use of any custom host mappings defined using Burp's *Hostname Resolution* feature when resolving a KDC hostname. If this is a problem, just specify the IP address of the KDC in the *KDC host* box. Note this isn't an issue for the actual requests being sent from Burp, only for Berserko's own communications with the KDC.

### (Possible) Future plans ###
* Use of already acquired Kerberos tickets on domain-joined machines (not sure if this is possible or not)
* Capability to authenticate to multiple domains at the same time (this should work fine)