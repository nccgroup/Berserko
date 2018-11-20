# Domain Trusts

Domain trusts are common in enterprise Kerberos deployments, and are one of the many ways in which increased complexity of the Kerberos setup can make things difficult for Berserko. When domain trusts are in use, the domain in which your credentials live is not necessarily the same domain in which the target web server lives. Sometimes you can determine (or at least suspect) this based on the hostnames that you observe, but things are not always that simple.

Berserko *does* support domain trusts - this has been successfully tested in a lab environment (Windows Server 2016). However, your mileage may vary in real life scenarios, and at the very least you might have to make some additions to your `krb5.conf` file (see [here](../README.md#Delegation) for general information on this file).

Note that the presence of a `Message stream modified (41)` error or `host is in a different realm?` message in the Berserko logs *may* indicate that a domain trust is in use for which Berserko is not configured.

### Configuring Berserko With Domain Trusts

To authenticate to a server in another domain via a domain trust, there are not many changes that have to be made to the Berserko configuration options. In particular, the *Domain Settings* and *Domain Credentials* sections are used in the same way as before - don't be tempted to try to specify the domain where the server lives as the *Domain DNS Name*. This should always be the domain where your *account* lives. However, you will have to add the server(s) you are trying to access to the Berserko scope. As described [here](../README.md#Scope), you can either use the *All hosts in scope for Kerberos authentication* setting, or stick with the default *All hosts in this Kerberos domain in scope for Kerberos* setting and add the servers you are trying to access to the *Additional hosts in scope* box.

The tricky part of all this is that it is necessary to tell Berserko where to find the KDC (domain controller) for each of the other domains involved in the domain trust. Unfortunately the Java Kerberos libraries won't try to do this automatically, so we need to configure it via the `krb5.conf` file.

For each domain, it is necessary to add an entry to the `[realms]` section of the file (create it if it doesn't already exist), providing the IP address (or hostname) of a domain controller for that domain. This is illustrated in the example below.

```
[libdefaults]
    forwardable = true

[realms]
    DOMAIN4.DOMAIN2.LOCAL = {
        kdc = 192.168.136.132
    }
    DOMAIN2.LOCAL = {
        kdc = 192.168.136.11
    }	
    DOMAIN5.LOCAL = {
        kdc = 192.168.136.12
    }
```

Advice on how best to find the domain controller for a particular domain can be found [here](domains_and_kdcs.md).

It is important to note that there may be intermediate domains involved in a trust relationship between the domain where your credentials live and the domain where your target server lives. Each of those intermediate domains will also need an entry in `krb5.conf`.

For example, assume the following:
* Your credentials live in `DOMAIN1.LOCAL` (and therefore you will be providing details of a domain controller for this domain in the Berserko *Domain Settings* section)
* `DOMAIN1.LOCAL` has a trust relationship with `DOMAIN2.LOCAL`
* `DOMAIN4.DOMAIN2.LOCAL` is a child domain of `DOMAIN2.LOCAL` (and the trust relationships are transitive such that accounts in `DOMAIN1.LOCAL` can authenticate in `DOMAIN4.DOMAIN2.LOCAL`)

In this case, your `krb5.conf` will need to include an entry for a domain controller in `DOMAIN2.LOCAL` (which is an intermediate domain) as well as for a domain controller in the target domain of `DOMAIN4.DOMAIN2.LOCAL`.