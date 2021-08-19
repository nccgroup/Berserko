//Released as open source by NCC Group Plc - http://www.nccgroup.trust/
//
//Developed by Richard Turnbull, Richard [dot] Turnbull [at] nccgroup [dot] trust
//
//http://www.github.com/nccgroup/Berserko
//
//Released under AGPL see LICENSE for more information

package burp;

import java.awt.Component;
import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.naming.Context;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import com.sun.security.jgss.ExtendedGSSContext;

// XXX: what about streaming responses?

public class BurpExtender implements IBurpExtender, IHttpListener, ITab,
		IExtensionStateListener {
	private enum AuthStrategy {
		PROACTIVE, PROACTIVE_AFTER_401, REACTIVE_401
	};

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	private PrintWriter stdout = null;
	
	private boolean unlimitedJCE = false;

	private GSSManager manager;
	private LoginContext loginContext = null;
	private boolean kerberosConfigSetUp = false;
	private boolean loginFailed = false;
	// private boolean incorrectCreds = false;
	private boolean gotTGT = false;

	private final String extensionName = "Berserko";
	private final String versionString = "1.2";
	private final String tabName = "Berserko";

	private List<String> workingSet = null;
	private Map<String, String> hostnameToSpnMap = null;
	private List<String> failedSpns = null;
	private Map<String, List<String>> failedSpnsForHost = null;
	private List<String> hostnamesWithUnknownSpn = null;
	private ContextCache contextCache = null;
	private Map<String,Pattern> scopeStringRegexpMap = null;
	
	// config
	private String domainDnsName;
	private String kdcHost;
	private String username;
	private String password;

	private boolean masterSwitch;
	
	private boolean plainhostExpand;
	private boolean ignoreNTLMServers;
	private boolean everythingInScope;
	private boolean wholeDomainInScope;
	private List<String> hostsInScope;

	private boolean savePassword;

	private int logLevel;
	private int alertLevel;

	private AuthStrategy authStrategy;

	private String krb5File;
	// end config

	private Object contextLock = new Object();

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		helpers = callbacks.getHelpers();

		// set our extension name
		callbacks.setExtensionName(extensionName);

		stdout = new PrintWriter(callbacks.getStdout(), true);

		callbacks.registerHttpListener(this);

		callbacks.registerExtensionStateListener(this);

		if (savedConfigAvailable()) {
			loadConfig();
			setDomainAndKdc(domainDnsName, kdcHost);
		} else {
			setDefaultConfig();
		}

		setupGUI();

		manager = GSSManager.getInstance();

		log(1, "Berserko version " + versionString);
		
		scopeStringRegexpMap = new HashMap<String, Pattern>();
		unlimitedJCE = isUnlimitedJCE();
		
		if( !unlimitedJCE)
		{
			alertAndLog( 1, "Warning: JCE Unlimited Strength Jurisdiction Policy does not appear to be installed in your JRE. This restricts the set of cryptographic algorithms available to Burp and could lead to failure to perform Kerberos authentication in some domains. See http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#importlimits. Also note that newer versions of Burp seem to have a workaround for this.");
		}

		/*
		 * clearLoginContext(); workingSet = Collections.synchronizedList(new
		 * ArrayList<String>()); // this should be sufficient for synchronizing
		 * access to workingSet given that we are never iterating over it
		 * hostnameToSpnMap = new ConcurrentHashMap<String, String>();
		 * failedSpns = Collections.synchronizedList(new ArrayList<String>());
		 * failedSpnsForHost = new ConcurrentHashMap<String, List<String>>();
		 * hostnamesWithUnknownSpn = Collections.synchronizedList(new
		 * ArrayList<String>()); contextCache = new ContextCache();
		 */
	}

	public void extensionUnloaded() {
		saveConfig();
	}

	private void alert(int level, String message) {
		if (alertLevel >= level) {
			callbacks.issueAlert(message);
		}
	}

	private void log(int level, String message) {
		if (logLevel >= level) {
			stdout.println(message);
		}
	}

	private void logWithTimestamp(int level, String message) {
		if (logLevel >= level) {
			java.util.Date date = new java.util.Date();
			stdout.println(String.format("%s: %s",
					new Timestamp(date.getTime()), message));
		}
	}

	private void alertAndLog(int level, String message) {
		alert(level, message);
		log(level, message);
	}

	private void logException(int level, Exception e) {
		if (logLevel >= level) {
			e.printStackTrace(stdout);
		}
	}
	
	private boolean everythingInScopeDefault = false;
	private boolean wholeDomainInScopeDefault = true;

	private void setDefaultConfig() {
		masterSwitch = false;
		setDomainAndKdc("", "");
		setCredentials("", "");
		savePassword = false;
		alertLevel = logLevel = 1;
		plainhostExpand = true;
		ignoreNTLMServers = false;
		everythingInScope = everythingInScopeDefault;
		wholeDomainInScope = wholeDomainInScopeDefault;
		hostsInScope = new ArrayList<String>();
		authStrategy = AuthStrategy.REACTIVE_401;
		krb5File = "";
		System.setProperty("java.security.krb5.conf", "");
	}

	private void saveSetting(String a, String b) {
		callbacks.saveExtensionSetting(extensionName + "_" + a, b);
	}

	private String loadSetting(String a) {
		return callbacks.loadExtensionSetting(extensionName + "_" + a);
	}
	
	private List<String> hostsListFromString( String s)
	{
		List<String> hosts = new ArrayList<String>();
		
		String[] tokens = s.split( ";");
		
		for( String t : tokens)
		{
			if( t.length() > 0)
			{
				hosts.add( t);
			}				
		}
		
		return hosts;
	}
	
	private String hostsStringFromList( List<String> hostsList)
	{
		String s = "";
		
		for(int ii=0; ii<hostsList.size() - 1; ii++)
		{
			s += hostsList.get( ii) + ";";
		}
		
		if( hostsList.size() > 0)
		{
			s += hostsList.get( hostsList.size() - 1);
		}
		
		return s;
	}

	private void logConfig() {
		log(1, "Domain DNS Name     : " + domainDnsName);
		log(1, "KDC Host            : " + kdcHost);
		log(1, "Username            : " + username);
		log(1, "Password            : " + (password.isEmpty() ? "" : "****"));
		log(1, "Save password       : " + String.valueOf(savePassword));
		log(1, "Everything in scope : " + String.valueOf(everythingInScope));
		log(1, "Domain in scope     : " + String.valueOf(wholeDomainInScope));
		log(1, "Hosts in scope      : " + hostsStringFromList( hostsInScope));
		log(1, "Include plainhosts  : " + String.valueOf(plainhostExpand));
		log(1, "Ignore NTLM servers : " + String.valueOf(ignoreNTLMServers));
		log(1, "Alert level         : " + String.valueOf(alertLevel));
		log(1, "Logging level       : " + String.valueOf(logLevel));
		log(1, "Auth strategy       : " + authStrategy.toString());
	}

	private void saveConfig() {
		saveSetting("saved_config_marker", "x");
		saveSetting("domain_dns_name", domainDnsName);
		saveSetting("kdc_host", kdcHost);
		saveSetting("username", username);
		if (savePassword) {
			saveSetting("password", password);
		} else {
			saveSetting("password", null);
		}
		saveSetting("plainhost_expand", String.valueOf(plainhostExpand));
		saveSetting("everything_in_scope", String.valueOf( everythingInScope));
		saveSetting("domain_in_scope", String.valueOf( wholeDomainInScope));
		saveSetting("hosts_in_scope", hostsStringFromList( hostsInScope));
		saveSetting("ignore_ntlm_servers", String.valueOf(ignoreNTLMServers));
		saveSetting("alert_level", String.valueOf(alertLevel));
		saveSetting("log_level", String.valueOf(logLevel));
		saveSetting("auth_strategy", authStrategy.toString());
		saveSetting("krb5_file", krb5File);

		logWithTimestamp(1, "Saving config...");
		logConfig();
	}

	private boolean savedConfigAvailable() {
		if (loadSetting("saved_config_marker") == null) {
			return false;
		} else {
			return true;
		}
	}

	private void loadConfig() {
		// we don't restore the masterSwitch setting from the saved config - it
		// always starts as Off
		domainDnsName = loadSetting("domain_dns_name");
		kdcHost = loadSetting("kdc_host");
		username = loadSetting("username");
		if (loadSetting("password") != null) {
			password = loadSetting("password");
		} else {
			password = "";
		}
		plainhostExpand = loadSetting("plainhost_expand").equals("true") ? true
				: false;
		ignoreNTLMServers = loadSetting("ignore_ntlm_servers").equals("true") ? true
				: false;
		if( loadSetting( "everything_in_scope") != null)
		{
			everythingInScope = loadSetting("everything_in_scope").equals("true") ? true
					: false;
		}
		else
		{
			everythingInScope = everythingInScopeDefault;
		}
		if( loadSetting( "domain_in_scope") != null)
		{
			wholeDomainInScope = loadSetting("domain_in_scope").equals("true") ? true
					: false;
		}	
		else
		{
			wholeDomainInScope = wholeDomainInScopeDefault;
		}
		if( loadSetting( "hosts_in_scope") != null)
		{
			hostsInScope = hostsListFromString(loadSetting("hosts_in_scope"));
		}	
		else
		{
			hostsInScope = new ArrayList<String>();
		}
		alertLevel = Integer.parseInt(loadSetting("alert_level"));
		logLevel = Integer.parseInt(loadSetting("log_level"));
		authStrategy = AuthStrategy.valueOf(loadSetting("auth_strategy"));
		try {
			krb5File = loadSetting("krb5_file");
		} catch (NullPointerException e) {
			krb5File = "";
		}

		logWithTimestamp(1, "Loaded config...");
		logConfig();
	}

	private void addSpnToListIfNotInvalid(List<String> l,
			String hostname, int port, String realm) {
		
		List<String> spns = new ArrayList<String>();
		
		spns.add( "HTTP/" + hostname.toLowerCase() + "@" + realm);
		spns.add( "http/" + hostname.toLowerCase() + "@" + realm);
		
		if( port != 80 && port != 443)
		{
			spns.add( "HTTP/" + hostname.toLowerCase() + ":" + port + "@" + realm);
			spns.add( "http/" + hostname.toLowerCase() + ":" + port + "@" + realm);
		}
		
		for( String spn : spns)
		{
			if (!failedSpns.contains(spn)) {
				if (failedSpnsForHost.containsKey(hostnameColonPort( hostname, port).toLowerCase())) {
					if (failedSpnsForHost.get(hostnameColonPort( hostname, port).toLowerCase()).contains(spn)) {
						return;
					}
				}
				if( !l.contains(spn))
				{
					l.add(spn);
				}
			}
		}
	}
	
	private String getCNAME( String hostname)
	{
		try
		{
			Hashtable<String, String> envProps = new Hashtable<String, String>();
			envProps.put(Context.INITIAL_CONTEXT_FACTORY,
					"com.sun.jndi.dns.DnsContextFactory");
			DirContext dnsContext = new InitialDirContext(envProps);
			Attributes dnsEntries = dnsContext.getAttributes(hostname, new String[] { "CNAME" });

			if (dnsEntries != null) {
				Attribute attr = dnsEntries.get("CNAME");

				if (attr != null) {
					if( attr.size() > 0)
					{
						String s = (String) attr.get(0);
						return s.substring(0, s.length()-1);
					}
				}
			}
		}
		catch( Exception e)
		{
			logException( 2, e);
		}

		return "";
	}


	private List<String> hostnameToSpn(String hostname, int port) {
		List<String> ret = new ArrayList<String>();

		if (hostnameToSpnMap.containsKey(hostnameColonPort(hostname, port).toLowerCase())) {
			ret.add(hostnameToSpnMap.get(hostnameColonPort(hostname, port).toLowerCase()));
		} else {
			if (!hostnamesWithUnknownSpn.contains(hostnameColonPort(hostname, port).toLowerCase())) {
				hostnamesWithUnknownSpn.add(hostnameColonPort(hostname, port).toLowerCase());
			}

			// do a DNS lookup here, and if the result is a CNAME then do the below both with the uncanonicalised name and the canonicalised name
			// might need to roll our own to do it over SOCKS - see https://github.com/callumdmay/java-dns-client

			String canonicalHostname = getCNAME( hostname);

			if (isPlainhostname(hostname)) {
				addSpnToListIfNotInvalid(ret, expandHostname(hostname).toLowerCase(), port, getRealmName());
				addSpnToListIfNotInvalid(ret, hostname.toLowerCase(), port, getRealmName());
			}

			if( !canonicalHostname.equals("") && isPlainhostname(canonicalHostname))
			{
				addSpnToListIfNotInvalid(ret, expandHostname(canonicalHostname).toLowerCase(), port, getRealmName());
				addSpnToListIfNotInvalid(ret, canonicalHostname.toLowerCase(), port, getRealmName());
			}

			if( !isPlainhostname(hostname))
			{
				addSpnToListIfNotInvalid(ret, hostname.toLowerCase(), port, getRealmName());
			}

			if( !canonicalHostname.equals("") && !isPlainhostname(canonicalHostname))
			{
				addSpnToListIfNotInvalid(ret, canonicalHostname.toLowerCase(), port, getRealmName());
			}

			if( !isPlainhostname(hostname))
			{
				String[] tokens = hostname.split( "\\.");
				if( tokens.length >= 3)
				{
					for( int ii=1; ii<tokens.length - 1; ii++)
					{
						String realm = String.join( ".", Arrays.copyOfRange( tokens, ii, tokens.length));
						
						if( realm.toUpperCase() != getRealmName().toUpperCase())
						{
							addSpnToListIfNotInvalid(ret, hostname.toLowerCase(), port, realm.toUpperCase());
						}
					}
				}

				if( hostname.toLowerCase().endsWith(getRealmName().toLowerCase()))
				{
					addSpnToListIfNotInvalid(ret, getPlainHostname(hostname).toLowerCase(), port, getRealmName());
				}		
			}

			if( !canonicalHostname.equals("") && !isPlainhostname(canonicalHostname))
			{
				String[] tokens = canonicalHostname.split( "\\.");
				if( tokens.length >= 3)
				{
					for( int ii=1; ii<tokens.length - 1; ii++)
					{
						String realm = String.join( ".", Arrays.copyOfRange( tokens, ii, tokens.length));

						if( realm.toUpperCase() != getRealmName().toUpperCase())
						{
							addSpnToListIfNotInvalid(ret, canonicalHostname.toLowerCase(), port, realm.toUpperCase());
						}
					}
				}

				if( canonicalHostname.toLowerCase().endsWith(getRealmName().toLowerCase()))
				{
					addSpnToListIfNotInvalid(ret, getPlainHostname(canonicalHostname).toLowerCase(), port, getRealmName());
				}
			}
		}

		return ret;
	}

	private String usernameToPrincipal(String username) {
		// XXX: is it correct to always make the username lowercase?
		return username.toLowerCase() + "@" + getRealmName();
	}

	private boolean hostnameIsInWorkingSet(String hostname, int port) {
		return workingSet.contains(hostnameColonPort(expandHostname(hostname), port).toLowerCase());
	}

	private void addHostnameToWorkingSet(String hostname, int port) {
		if (!workingSet.contains(hostnameColonPort(expandHostname(hostname), port).toLowerCase())) {
			log(2, String.format("Adding %s to working set", hostnameColonPort( hostname, port)));
			workingSet.add(hostnameColonPort(expandHostname(hostname), port).toLowerCase());
		}
	}

	private Pattern getPatternForScopeString( String s)
	{
		if( scopeStringRegexpMap.containsKey(s))
		{
			return scopeStringRegexpMap.get(s);
		}
		else
		{
			// transform the "regexp" from the scope box to an actual hostname
			String r = s.replace( ".", "\\.");		// dots in hostnames should be treated as literal dots
			r = s.replace( "-", "\\-");				// same for hyphens
			r = r.replace( "*", ".*");				// our "regexp" says that * matches zero or more characters. Needs to be ".*"
			r = r.replace( "?", "[^.]");			// question mark is to match anything but a dot
			
			Pattern p = Pattern.compile(r); 
			scopeStringRegexpMap.put( s, p);
			return p;
		}
	}
	
	private boolean hostnameIsInScope(String hostname) {
		if( everythingInScope)
		{
			return true;
		}
		else
		{
			if( isPlainhostname(hostname) && plainhostExpand && wholeDomainInScope)
			{
				return true;
			}
			
			if( wholeDomainInScope && hostname.toLowerCase().endsWith(domainDnsName.toLowerCase()))
			{
				return true;
			}
			
			for( String s : hostsInScope)
			{
				Pattern p = getPatternForScopeString(s);
				Matcher m = p.matcher(hostname);
				if( m.matches())
				{
					return true;
				}
			}
		}
			
		if (plainhostExpand && isPlainhostname(hostname)) {
			return true;
		} else {
			return hostname.toLowerCase().endsWith(domainDnsName.toLowerCase());
		}
	}	

	private String expandHostname(String hostname) {
		if (isPlainhostname(hostname)) {
			return hostname + "." + domainDnsName.toLowerCase();
		} else {
			return hostname;
		}
	}

	private String getPlainHostname(String hostname) {
		int i = hostname.indexOf(".");

		if (i == -1) {
			return hostname;
		} else {
			return hostname.substring(0, i);
		}
	}

	private boolean isPlainhostname(String hostname) {
		return (hostname.length() > 0) && (hostname.indexOf('.') == -1);
	}

	private String buildAuthenticateHeaderFromToken(String token) {
		return String.format("Authorization: Negotiate %s", token);
	}

	private String getTokenFromAuthenticateNegotiateResponseHeader(
			String headerLine) {
		String pattern = "WWW-Authenticate:\\s*Negotiate\\s*(.*)";
		Pattern r = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);

		Matcher m = r.matcher(headerLine);
		if (m.find()) {
			return m.group(1);
		} else {
			return "";
		}
	}

	private String getTokenFromAuthorizationNegotiateRequestHeader(
			String headerLine) {
		String pattern = "Authorization:\\s*Negotiate\\s*(.*)";
		Pattern r = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);

		Matcher m = r.matcher(headerLine);
		if (m.find()) {
			return m.group(1);
		} else {
			return "";
		}
	}

	private boolean checkHostnameRegexp(String input) {
		// http://stackoverflow.com/questions/1418423/the-hostname-regex
		String pattern = "^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?$";
		Pattern r = Pattern.compile(pattern);

		Matcher m = r.matcher(input);

		return m.find();
	}

	private boolean isMultiComponentHostname(String input) {
		return input.contains(".");
	}

	/*
	 * private String getSchemeFromAuthenticateResponseHeader( String
	 * headerLine) { String pattern = "WWW-Authenticate:\\s*(.*)\\s*."; Pattern
	 * r = Pattern.compile(pattern);
	 * 
	 * // Now create matcher object. Matcher m = r.matcher(headerLine); if
	 * (m.find()) { return m.group(1); } else { return ""; } }
	 */

	private String getSchemeFromAuthenticateRequestHeader(String headerLine) {
		String pattern = "Authorization:\\s*(\\S*)\\s*.*";
		Pattern r = Pattern.compile(pattern);

		// Now create matcher object.
		Matcher m = r.matcher(headerLine);
		if (m.find()) {
			return m.group(1);
		} else {
			return "";
		}
	}

	private String getRealmName() {
		return domainDnsName.toUpperCase();
	}

	private void clearLoginContext() {
		log(2, "Clearing login context");

		synchronized (contextLock) {
			loginContext = null;
		}

		gotTGT = false;
		loginFailed = false;
	}

	private void setDomainAndKdc(String domain, String kdc) {
		domainDnsName = domain;
		kdcHost = kdc;

		if (domain.isEmpty()) {
			alertAndLog(1, "No domain DNS name set");

			if (kdc.isEmpty()) {
				alertAndLog(1, "No KDC host set");
			}

			return;
		}

		clearLoginContext();

		System.setProperty("java.security.krb5.realm", domain.toUpperCase());
		System.setProperty("java.security.krb5.kdc", kdcHost);
		workingSet = Collections.synchronizedList(new ArrayList<String>()); // this should be sufficient for synchronizing access to workingSet given that we are never iterating over it
		hostnameToSpnMap = new ConcurrentHashMap<String, String>();
		failedSpns = Collections.synchronizedList(new ArrayList<String>());
		failedSpnsForHost = new ConcurrentHashMap<String, List<String>>();
		hostnamesWithUnknownSpn = Collections
				.synchronizedList(new ArrayList<String>());
		contextCache = new ContextCache();

		log(2, String.format(
				"New domain DNS name (%s) and KDC hostname (%s) set",
				domainDnsName, kdcHost));
	}

	private void setCredentials(String user, String pass) {
		username = user;
		password = pass;

		if (user.isEmpty()) {
			alertAndLog(1, "No username set");
			return;
		}

		clearLoginContext();
		// incorrectCreds = false;

		log(2, String.format("New username (%s) and password set", username));
	}
	
	private String hostnameColonPort( String hostname, int port)
	{
		return String.format( "%s:%d", hostname, port);
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest,
			IHttpRequestResponse messageInfo) {

		if (!masterSwitch) {
			return;
		}

		try {
			if (messageIsRequest) {
				if (authStrategy == AuthStrategy.PROACTIVE) {
					IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
					List<String> headers = reqInfo.getHeaders();
					String hostname = messageInfo.getHttpService().getHost();
					int port = messageInfo.getHttpService().getPort();

					if (hostnameIsInScope(hostname)) {
						try {
							if (headersContainStartswith(headers,
									"Authorization")) {
								String scheme = getSchemeFromAuthenticateRequestHeader(getHeaderStartingWith(
										headers, "Authorization:"));
								alertAndLog(
										1,
										String.format(
												"Authorization header (%s) already applied for in-scope host %s; ignoring this host. Perhaps Burp \"Platform Authentication\" is configured against this host?",
												scheme, hostname));
							} else {
								byte[] body = Arrays.copyOfRange(
										messageInfo.getRequest(),
										reqInfo.getBodyOffset(),
										messageInfo.getRequest().length);
								log(2, "Getting token for " + hostnameColonPort( hostname, port));
								ContextTokenSpnTriple ctst = getToken(hostnameToSpn(hostname, port));

								if (ctst != null) {
									log(2, "Setting token in request to "
											+ hostnameColonPort( hostname, port));
									headers.add(buildAuthenticateHeaderFromToken(ctst
											.getToken()));
									messageInfo.setRequest(helpers
											.buildHttpMessage(headers, body));
									addHostnameToWorkingSet( hostname, port);
									if (hostnamesWithUnknownSpn
											.contains(hostnameColonPort(hostname, port).toLowerCase())) {
										contextCache.AddToCache(ctst);
									}
								}
							}
						} catch (Exception e) {
							log(1,
									String.format(
											"Exception authenticating request using proactive strategy: %s",
											e.getMessage()));
							logException(2, e);
						}
					}
				} else if (authStrategy == AuthStrategy.PROACTIVE_AFTER_401) {
					IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
					List<String> headers = reqInfo.getHeaders();
					String hostname = messageInfo.getHttpService().getHost();
					int port = messageInfo.getHttpService().getPort();

					if (hostnameIsInWorkingSet(hostname, port)) {
						try {
							if (headersContainStartswith(headers,
									"Authorization")) {
								String scheme = getSchemeFromAuthenticateRequestHeader(getHeaderStartingWith(
										headers, "Authorization:"));
								alertAndLog(
										1,
										String.format(
												"Authorization header (%s) already applied for in-scope host %s; ignoring this host. Perhaps Burp \"Platform Authentication\" is configured against this host?",
												scheme, hostname));
							} else {
								log(2, "Getting token for " + hostnameColonPort( hostname, port));
								ContextTokenSpnTriple ctst = getToken(hostnameToSpn(hostname, port));

								if (ctst != null) {
									byte[] body = Arrays.copyOfRange(
											messageInfo.getRequest(),
											reqInfo.getBodyOffset(),
											messageInfo.getRequest().length);
									log(2, "Setting token in request to "
											+ hostnameColonPort( hostname, port));
									headers.add(buildAuthenticateHeaderFromToken(ctst
											.getToken()));
									messageInfo.setRequest(helpers
											.buildHttpMessage(headers, body));
									if (hostnamesWithUnknownSpn
											.contains(hostnameColonPort(hostname, port).toLowerCase())) {
										contextCache.AddToCache(ctst);
									}
								}
							}
						} catch (Exception e) {
							log(1,
									String.format(
											"Exception authenticating request using proactive-after-401 strategy: %s",
											e.getMessage()));
							logException(2, e);
						}
					}
				}
			} else {
				byte[] responseBytes = messageInfo.getResponse();
				IResponseInfo respInfo = helpers.analyzeResponse(responseBytes);
				List<String> headers = respInfo.getHeaders();

				// ok, this is pretty dirty but we don't want to do anything
				// with the responses to our own requests that we make below
				// using makeHttpRequest
				// we'll heuristically identify these based on them being issued
				// by the Extender tool, and containing a Negotiate header
				// alternatively I guess we could add our own marker request
				// header or something
				if (toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER) {
					IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);

					if (headersContainStartswith(reqInfo.getHeaders(),
							"Authorization: Negotiate")) {
						return;
					}
				}

				if (is401Negotiate(respInfo, messageInfo.getHttpService()
						.getHost())) {
					byte[] req = messageInfo.getRequest();
					IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
					String hostname = messageInfo.getHttpService().getHost();
					int port = messageInfo.getHttpService().getPort();
					byte[] body = Arrays.copyOfRange(req,
							reqInfo.getBodyOffset(), req.length);
					List<String> requestHeaders = helpers.analyzeRequest(req)
							.getHeaders();

					if (headersContainStartswith(requestHeaders,
							"Authorization")) // this was a failed authentication...
					{
						if (hostnameIsInWorkingSet(hostname, port)) // ... a failed authentication by us
						{
							String requestToken = getTokenFromAuthorizationNegotiateRequestHeader(getHeaderStartingWith(
									requestHeaders, "Authorization:"));

							ContextTokenSpnTriple ctst = contextCache
									.GetFromCache(requestToken);

							if (ctst != null) {
								contextCache.RemoveFromCache(requestToken);

								String serverToken = getTokenFromAuthenticateNegotiateResponseHeader(getHeaderStartingWith(
										headers, "WWW-Authenticate:"));
								String err = ProcessErrorTokenResponse(
										ctst.getContext(), serverToken);

								if (err.isEmpty()) {
									alertAndLog(
											1,
											String.format(
													"Failed Kerberos authentication to host %s: unknown error",
													hostnameColonPort( hostname, port)));
								} else if (err
										.contains("AP_REP token id does not match")) {
									alertAndLog(
											1,
											String.format(
													"Failed Kerberos authentication to host %s - possibly service ticket for wrong service being used, error message was %s",
													hostnameColonPort( hostname, port), err));
									log(2, String.format(
											"SPN %s incorrect for hostname %s",
											ctst.getSpn(), hostnameColonPort( hostname, port)));

									if (!failedSpnsForHost.containsKey(hostnameColonPort( hostname, port)
											.toLowerCase())) {
										failedSpnsForHost.put(
												hostnameColonPort( hostname, port).toLowerCase(),
												new ArrayList<String>());
									}
									if (!failedSpnsForHost.get(
											hostnameColonPort( hostname, port).toLowerCase()).contains(
											ctst.getSpn())) {
										failedSpnsForHost.get(
												hostnameColonPort( hostname, port).toLowerCase()).add(
												ctst.getSpn());
									}
								} else {
									alertAndLog(
											1,
											String.format(
													"Failed Kerberos authentication to host %s: error %s",
													hostnameColonPort( hostname, port), err));
								}
							} else {
								alertAndLog(
										1,
										String.format(
												"Failed Kerberos authentication to host %s: unknown error",
												hostnameColonPort( hostname, port)));
								log(2,
										"Response from server: "
												+ getHeaderStartingWith(
														headers,
														"WWW-Authenticate"));
							}

						} else if (hostnameIsInScope(hostname)) {
							String scheme = getSchemeFromAuthenticateRequestHeader(getHeaderStartingWith(
									requestHeaders, "Authorization:"));
							alertAndLog(
									1,
									String.format(
											"Authorization header (%s) already applied for in-scope host %s (and was not successful); ignoring this host. Perhaps Burp \"Platform Authentication\" is configured against this host?",
											scheme, hostname));
						}
					} else if (authStrategy == AuthStrategy.REACTIVE_401) {
						try {
							if (hostnameIsInScope(hostname)
									&& !hostnameIsInWorkingSet(hostname, port)) {
								log(2, "Getting token for " + hostnameColonPort( hostname, port));
								ContextTokenSpnTriple ctst = getToken(hostnameToSpn(hostname, port));

								if (ctst != null) {
									requestHeaders
											.add(buildAuthenticateHeaderFromToken(ctst
													.getToken()));
									log(2,
											"Creating new authenticated request to "
													+ hostnameColonPort( hostname, port));
									IHttpRequestResponse resp = callbacks
											.makeHttpRequest(messageInfo
													.getHttpService(), helpers
													.buildHttpMessage(
															requestHeaders,
															body));

									byte[] myResponseBytes = resp.getResponse();
									IResponseInfo myRespInfo = helpers
											.analyzeResponse(myResponseBytes);
									List<String> myResponseHeaders = myRespInfo
											.getHeaders();

									if (myRespInfo.getStatusCode() == 401) {
										if (headersContainStartswith(
												myResponseHeaders,
												"WWW-Authenticate: Negotiate")) {
											String serverToken = getTokenFromAuthenticateNegotiateResponseHeader(getHeaderStartingWith(
													myResponseHeaders,
													"WWW-Authenticate:"));
											String err = ProcessErrorTokenResponse(
													ctst.getContext(),
													serverToken);

											if (err.isEmpty()) {
												alertAndLog(
														1,
														String.format(
																"Failed Kerberos authentication to host %s: unknown error",
																hostnameColonPort( hostname, port)));
											} else if (err
													.contains("AP_REP token id does not match")) {
												alertAndLog(
														1,
														String.format(
																"Failed Kerberos authentication to host %s - possibly service ticket for wrong service being used, error message was %s",
																hostnameColonPort( hostname, port), err));
												log(2,
														String.format(
																"SPN %s incorrect for hostname %s",
																ctst.getSpn(),
																hostnameColonPort( hostname, port)));

												if (!failedSpnsForHost
														.containsKey(hostnameColonPort( hostname, port)
																.toLowerCase())) {
													failedSpnsForHost
															.put(hostnameColonPort( hostname, port)
																	.toLowerCase(),
																	new ArrayList<String>());
												}
												if (!failedSpnsForHost
														.get(hostnameColonPort( hostname, port)
																.toLowerCase())
														.contains(ctst.getSpn())) {
													failedSpnsForHost
															.get(hostnameColonPort( hostname, port)
																	.toLowerCase())
															.add(ctst.getSpn());
												}

												// TODO: maybe try again with the next SPN?
											} else {
												alertAndLog(
														1,
														String.format(
																"Failed Kerberos authentication to host %s: error %s",
																hostnameColonPort( hostname, port), err));
											}
										} else {
											alertAndLog(
													1,
													String.format("Failed Kerberos authentication to host %s: unknown error, server did not supply WWW-Authenticate response header"));
										}
									} else {
										messageInfo.setResponse(resp
												.getResponse());
										if (!hostnameToSpnMap
												.containsKey(hostnameColonPort( hostname, port)
														.toLowerCase())) {
											log(2,
													String.format(
															"Storing hostname->SPN mapping: %s->%s",
															hostnameColonPort( hostname, port).toLowerCase(),
															ctst.getSpn()));
											hostnameToSpnMap.put(
													hostnameColonPort( hostname, port).toLowerCase(),
													ctst.getSpn());
										}
									}
								}
							}
						} catch (Exception e) {
							log(1,
									String.format(
											"Exception processing request using reactive strategy: %s",
											e.getMessage()));
							logException(2, e);
						}
					} else if (authStrategy == AuthStrategy.PROACTIVE_AFTER_401
							&& !hostnameIsInWorkingSet(hostname, port)
							&& hostnameIsInScope(hostname)) {
						try {
							log(2, "Getting token for " + hostnameColonPort( hostname, port));
							ContextTokenSpnTriple ctst = getToken(hostnameToSpn(hostname, port));

							if (ctst != null) {
								requestHeaders
										.add(buildAuthenticateHeaderFromToken(ctst
												.getToken()));

								log(2, "Creating new authenticated request to "
										+ hostnameColonPort( hostname, port));
								IHttpRequestResponse resp = callbacks
										.makeHttpRequest(messageInfo
												.getHttpService(), helpers
												.buildHttpMessage(
														requestHeaders, body));

								byte[] myResponseBytes = resp.getResponse();
								IResponseInfo myRespInfo = helpers
										.analyzeResponse(myResponseBytes);
								List<String> myResponseHeaders = myRespInfo
										.getHeaders();

								if (myRespInfo.getStatusCode() == 401) {
									if (headersContainStartswith(
											myResponseHeaders,
											"WWW-Authenticate: Negotiate")) {
										String serverToken = getTokenFromAuthenticateNegotiateResponseHeader(getHeaderStartingWith(
												myResponseHeaders,
												"WWW-Authenticate:"));
										String err = ProcessErrorTokenResponse(
												ctst.getContext(), serverToken);

										alertAndLog(
												1,
												String.format(
														"Failed Kerberos authentication to host %s - possibly service ticket for wrong service being used, error message was %s",
														hostnameColonPort( hostname, port), err));
										log(2,
												String.format(
														"SPN %s incorrect for hostname %s",
														ctst.getSpn(), hostnameColonPort( hostname, port)));

										if (!failedSpnsForHost
												.containsKey(hostnameColonPort( hostname, port)
														.toLowerCase())) {
											failedSpnsForHost.put(
													hostnameColonPort( hostname, port).toLowerCase(),
													new ArrayList<String>());
										}
										if (!failedSpnsForHost.get(
												hostnameColonPort( hostname, port).toLowerCase())
												.contains(ctst.getSpn())) {
											failedSpnsForHost.get(
													hostnameColonPort( hostname, port).toLowerCase())
													.add(ctst.getSpn());
										}

										// TODO: maybe try again with the next SPN?
									} else {
										alert(1,
												String.format("Failed Kerberos authentication to host %s: unknown error, server did not supply WWW-Authenticate response header", hostnameColonPort( hostname, port)));
									}
								} else {
									addHostnameToWorkingSet( hostname, port);
									log(2,
											String.format(
													"Storing hostname->SPN mapping: %s->%s",
													hostnameColonPort( hostname, port).toLowerCase(),
													ctst.getSpn()));
									hostnameToSpnMap.put(
											hostnameColonPort( hostname, port).toLowerCase(),
											ctst.getSpn());
									messageInfo.setResponse(resp.getResponse());
								}
							}
						} catch (Exception e) {
							log(1,
									String.format(
											"Exception processing initial 401 response using proactive-after-401 strategy: %s",
											e.getMessage()));
							logException(2, e);
						}
					}
				} else {
					if (!contextCache.isEmpty()) {
						byte[] req = messageInfo.getRequest();
						String hostname = messageInfo.getHttpService().getHost();
						int port = messageInfo.getHttpService().getPort();
						List<String> requestHeaders = helpers.analyzeRequest(
								req).getHeaders();

						String requestToken = getTokenFromAuthorizationNegotiateRequestHeader(getHeaderStartingWith(
								requestHeaders, "Authorization:"));

						ContextTokenSpnTriple ctst = contextCache
								.GetFromCache(requestToken);

						if (ctst != null) {
							contextCache.RemoveFromCache(requestToken);
							if (hostnamesWithUnknownSpn.contains(hostnameColonPort(hostname, port)
									.toLowerCase())) {
								log(2,
										String.format(
												"Storing hostname->SPN mapping: %s->%s",
												hostnameColonPort( hostname, port).toLowerCase(),
												ctst.getSpn()));
								hostnamesWithUnknownSpn.remove(hostnameColonPort(hostname, port)
										.toLowerCase());
								hostnameToSpnMap.put(hostnameColonPort(hostname, port).toLowerCase(),
										ctst.getSpn());
							}
						}
					}
				}
			}
		} catch (Exception e) {
			log(1,
					String.format("Exception in processHttpMessage: %s",
							e.getMessage()));
			logException(2, e);
		}
	}

	private boolean headersContainStartswith(List<String> headers, String target) {
		for (String s : headers) {
			if (s.toLowerCase().startsWith(target.toLowerCase())) {
				return true;
			}
		}

		return false;
	}

	private String getHeaderStartingWith(List<String> headers, String target) {
		for (String s : headers) {
			if (s.toLowerCase().startsWith(target.toLowerCase())) {
				return s;
			}
		}

		return "";
	}

	private boolean is401Negotiate(IResponseInfo respInfo, String hostname) {
		if (!(respInfo.getStatusCode() == 401)) {
			return false;
		}

		List<String> headers = respInfo.getHeaders();

		boolean supportsNegotiate = false;
		boolean supportsNTLM = false;

		supportsNegotiate = headersContainStartswith(headers,
				"WWW-Authenticate: Negotiate");
		supportsNTLM = headersContainStartswith(headers,
				"WWW-Authenticate: NTLM");

		if (ignoreNTLMServers) {
			if( supportsNegotiate && supportsNTLM)
			{
				alertAndLog(1, String.format( "Not authenticating to server %s as it supports NTLM", hostname));
			}
			return supportsNegotiate && !supportsNTLM;
		} else {
			return supportsNegotiate;
		}
	}

	// http://stackoverflow.com/questions/24074507/how-to-generate-the-kerberos-security-token
	@SuppressWarnings("rawtypes")
	private class GetTokenAction implements PrivilegedExceptionAction {
		private List<String> spns;

		public GetTokenAction(List<String> s) {
			spns = s;
		}

		@Override
		public Object run() throws TGTExpiredException {

			String encodedToken = "";
			GSSContext context = null;
			
			System.out.println( "SPNs");
			for( String spn : spns)
			{
				log(2, "SPN to try: " + spn);
			}

			for (String spn : spns) {
				log(2, "Trying SPN: " + spn);

				try {
					Oid spnegoMechOid = new Oid("1.3.6.1.5.5.2");

					GSSName gssServerName = manager.createName(spn, null);

					GSSCredential userCreds = manager.createCredential(null,
							GSSCredential.INDEFINITE_LIFETIME, spnegoMechOid,
							GSSCredential.INITIATE_ONLY);

					context = manager.createContext(gssServerName,
							spnegoMechOid, userCreds,
							GSSCredential.INDEFINITE_LIFETIME);
					ExtendedGSSContext extendedContext = null;
					if (context instanceof ExtendedGSSContext) {
						extendedContext = (ExtendedGSSContext) context;
						extendedContext.requestDelegPolicy(true);
					}
					byte spnegoToken[] = new byte[0];
					spnegoToken = context.initSecContext(spnegoToken, 0,
							spnegoToken.length);
					encodedToken = Base64.getEncoder().encodeToString(
							spnegoToken);

					// if( extendedContext != null)
					// {
					// log( 2, String.format( "getDelegPolicyState = %s for %s",
					// extendedContext.getDelegPolicyState(), spn));
					// log( 2, String.format( "getCredDelegState = %s for %s",
					// extendedContext.getCredDelegState(), spn));
					// }

					return new ContextTokenSpnTriple(context, spn, encodedToken);
				} catch (Exception e) {
					if (e.getMessage().contains(
							"Server not found in Kerberos database")) {
						alertAndLog(
								1,
								String.format(
										"Failed to acquire service ticket for %s - service name not recognised by KDC",
										spn));
						if (!failedSpns.contains(spn)) {
							failedSpns.add(spn);
						}
						continue;
					} else if (e.getMessage().contains(
							"Message stream modified")) {
						alertAndLog(
								1,
								String.format(
										"Failed to acquire service ticket for %s - host is in a different realm?",
										spn));
						if (!failedSpns.contains(spn)) {
							failedSpns.add(spn);
						}
						continue;
					} else if (e.getMessage().contains(
							"Failed to find any Kerberos tgt")
							|| e.getMessage().contains("Ticket expired")) {
						alertAndLog(
								1,
								String.format(
										"Failed to acquire token for service %s, TGT has expired? Trying to get a new one...",
										spn));
						throw new TGTExpiredException("TGT Expired");
					} else {
						alertAndLog(
								1,
								String.format(
										"Failed to acquire token for service %s, error message was %s",
										spn, e.getMessage()));
						logException(2, e);
					}

					//return null;
				}
			}

			return null;
		}
	}

	private String ProcessErrorTokenResponse(GSSContext context,
			String returnedToken) {
		byte[] tokenBytes = null;

		try {
			tokenBytes = Base64.getDecoder().decode(returnedToken);
		} catch (Exception e) {
			return "Failed to base64-decode Negotiate token from server";
		}

		try {
			tokenBytes = context.initSecContext(tokenBytes, 0,
					tokenBytes.length);
		} catch (Exception e) {
			// this is an "expected" exception - we're deliberately feeding in
			// an error token from the server to collect the corresponding
			// exception
			return e.getMessage();
		}

		return "";
	}

	@SuppressWarnings("unchecked")
	private ContextTokenSpnTriple getToken(List<String> spns) {
		ContextTokenSpnTriple ctst = null;

		if (!gotTGT) {
			setupLoginContext();
		}

		if (gotTGT) {
			synchronized (contextLock) {
				try {
					GetTokenAction tokenAction = new GetTokenAction(spns);
					ctst = (ContextTokenSpnTriple) Subject.doAs(
							loginContext.getSubject(), tokenAction);
				} catch (PrivilegedActionException e) {
					if (e.getException().getClass().getName()
							.contains("TGTExpiredException")) {
						clearLoginContext();
						setupLoginContext();

						if (!gotTGT) {
							return null;
						}

						try {
							GetTokenAction tokenAction = new GetTokenAction(
									spns);
							ctst = (ContextTokenSpnTriple) Subject.doAs(
									loginContext.getSubject(), tokenAction);
						} catch (PrivilegedActionException ee) {
							alertAndLog(1,
									"Exception thrown when trying to get token with new TGT: "
											+ ee.getMessage());
							logException(2, ee);
							return null;
						}
					} else {
						alertAndLog(
								1,
								"Exception thrown in getToken: "
										+ e.getMessage());
						logException(2, e);
						return null;
					}
				}
			}
		} else {
			return null;
		}

		return ctst;
	}

	private void setupKerberosConfig() {
		if (kerberosConfigSetUp) {
			return;
		}

		Configuration.setConfiguration(null);

		System.setProperty("javax.security.auth.useSubjectCredsOnly", "true"); // necessary to stop it requesting a new service ticket for each request

		try {
			Configuration config = new Configuration() {
				@Override
				public AppConfigurationEntry[] getAppConfigurationEntry(
						String name) {

					Map<String, Object> map = new HashMap<String, Object>();
					map.put("doNotPrompt", "false");
					map.put("useTicketCache", "false");
					map.put("refreshKrb5Config", "true");

					return new AppConfigurationEntry[] { new AppConfigurationEntry(
							"com.sun.security.auth.module.Krb5LoginModule",
							AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
							map) };
				}

				@Override
				public void refresh() {
					// ignored
				}
			};

			Configuration.setConfiguration(config);

			kerberosConfigSetUp = true;
		} catch (Exception e) {
			alertAndLog(
					1,
					"Error setting up Kerberos configuration: "
							+ e.getMessage());
			logException(2, e);
		}
	}

	private boolean checkTgtForwardableFlag(Subject sub) {
		for (Object ob : sub.getPrivateCredentials()) {
			if (ob instanceof KerberosTicket) {
				KerberosTicket kt = (KerberosTicket) ob;
				boolean[] flags = kt.getFlags();
				return flags[1];
			}
		}

		return false;
	}

	private void setKrb5Config() {
		System.setProperty("java.security.krb5.conf", krb5File);
	}
	
	private void clearKerberosState()
	{
		clearLoginContext();
		
		workingSet = new ArrayList<String>();				
		hostnameToSpnMap = new HashMap<String, String>();
		failedSpns = new ArrayList<String>();;
		failedSpnsForHost = new HashMap<String, List<String>>();
		hostnamesWithUnknownSpn = new ArrayList<String>();
	}

	private void setupLoginContext() {
		if (loginFailed) {
			return; // don't keep trying to get a TGT after a failure, until we
					// are provided with new domain details or creds or whatever
		}

		if (domainDnsName.isEmpty()) {
			alertAndLog(1,
					"Domain DNS name is blank - not trying to acquire TGT");
			loginFailed = true;
			return;
		}

		if (kdcHost.isEmpty()) {
			alertAndLog(1, "KDC hostname is blank - not trying to acquire TGT");
			loginFailed = true;
			return;
		}

		if (username.isEmpty()) {
			alertAndLog(1, "User is blank - not trying to acquire TGT");
			loginFailed = true;
			return;
		}

		setKrb5Config();

		setupKerberosConfig();

		synchronized (contextLock) {
			try {
				log(2,
						String.format(
								"Attempting to acquire TGT for realm %s at KDC %s with user %s",
								getRealmName(), kdcHost, username));
				loginContext = new LoginContext("KrbLogin",
						new KerberosCallBackHandler(username, password));
				loginContext.login();
				log(2, "TGT successfully acquired");
				gotTGT = true;

				boolean forwardable = checkTgtForwardableFlag(loginContext
						.getSubject());

				if (forwardable) {
					log(1, "TGT is forwardable - delegation should work OK");
				} else {
					log(1,
							"TGT is not forwardable so delegation will not work.");
				}
			} catch (Exception e) {
				if ((e.getCause() != null)
						&& (e.getCause().getClass().getName() == "java.net.UnknownHostException")) {
					alertAndLog(
							1,
							String.format(
									"Failed to acquire TGT on domain %s with user %s - couldn't find DC %s. Not making further attempts until domain settings are changed.",
									domainDnsName, username, kdcHost));
				} else if (e.getMessage().startsWith(
						"Client not found in Kerberos database")) {
					alertAndLog(
							1,
							String.format(
									"Failed to acquire TGT on domain %s with user %s - username appears to be invalid. Not making further attempts, to avoid account lockout. Try setting new credentials (and checking the domain details)",
									domainDnsName, username));
					// incorrectCreds = true;
				} else if (e.getMessage().startsWith(
						"Pre-authentication information was invalid")) {
					if (password.isEmpty()) {
						alertAndLog(
								1,
								String.format(
										"Failed to acquire TGT on domain %s with user %s - password appears to be invalid (it is blank). Not making further attempts, to avoid account lockout. Try setting new credentials (and checking the domain details)",
										domainDnsName, username));
						// incorrectCreds = true;
					} else {
						alertAndLog(
								1,
								String.format(
										"Failed to acquire TGT on domain %s with user %s - password appears to be invalid. Not making further attempts, to avoid account lockout. Try setting new credentials (and checking the domain details)",
										domainDnsName, username));
						// incorrectCreds = true;
					}
				} else if( e.getMessage().startsWith( "KDC has no support for encryption type"))
				{
					if( unlimitedJCE)
					{
						alertAndLog( 1, "Failed to acquire TGT - encryption algorithm not supported by KDC. This is unexpected, as you appear to have the JCE Unlimited Strength Jurisdiction Policy installed.");
					}
					else
					{
						alertAndLog( 1, "Failed to acquire TGT - encryption algorithm not supported by KDC. This is likely to be because you do not have the JCE Unlimited Strength Jurisdiction Policy installed. See http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#importlimits. Also note that newer versions of Burp seem to have a workaround for this.");
					}
				} else {
					alertAndLog(
							1,
							String.format(
									"Failed to acquire TGT on domain %s with user %s. Not making further attempts until domain settings are changed. Error was: %s",
									domainDnsName, username, e.getMessage()));
					logException(2, e);
				}

				loginFailed = true;
			}
		}
	}

	class KerberosCallBackHandler implements CallbackHandler {

		private final String user;
		private final String password;

		public KerberosCallBackHandler(String user, String password) {
			this.user = user;
			this.password = password;
		}

		public void handle(Callback[] callbacks) throws IOException,
				UnsupportedCallbackException {

			for (Callback callback : callbacks) {

				if (callback instanceof NameCallback) {
					NameCallback nc = (NameCallback) callback;
					if (user == null) {
						nc.setName(usernameToPrincipal("berserkotest"));
					} else {
						nc.setName(usernameToPrincipal(user));
					}
				} else if (callback instanceof PasswordCallback) {
					PasswordCallback pc = (PasswordCallback) callback;
					if (user == null) {
						pc.setPassword("berserkotest".toCharArray());
					} else {
						pc.setPassword(password.toCharArray());
					}
				} else {
					throw new UnsupportedCallbackException(callback,
							"Unknown Callback");
				}

			}
		}
	}

	private class ContextTokenSpnTriple {
		private GSSContext context;
		private String token;
		private String spn;

		public ContextTokenSpnTriple(GSSContext c, String s, String t) {
			context = c;
			token = t;
			spn = s;
		}

		public GSSContext getContext() {
			return context;
		}

		public String getToken() {
			return token;
		}

		public String getSpn() {
			return spn;
		}
	}

	@SuppressWarnings("serial")
	public class TGTExpiredException extends Exception {
		public TGTExpiredException(String message) {
			super(message);
		}
	}

	public class ContextCache {
		private Map<String, ContextTokenSpnTriple> contextMap;
		private final int maxCache = 1000;
		private int currentlyCached = 0;

		public ContextCache() {
			currentlyCached = 0;
			contextMap = new ConcurrentHashMap<String, BurpExtender.ContextTokenSpnTriple>();
		}

		public boolean isEmpty() {
			return currentlyCached == 0;
		}

		public void AddToCache(ContextTokenSpnTriple ctst) {
			if (currentlyCached < maxCache) {
				// log( 2, String.format(
				// "ContextCache putting %s %s, contains %d", ctst.getToken(),
				// ctst.getSpn(), currentlyCached+1));
				contextMap.put(ctst.getToken(), ctst);
				currentlyCached += 1;
			}
		}

		public void RemoveFromCache(String token) {
			// save a lookup in the synchronised hashmap
			if (currentlyCached == 0) {
				return;
			}

			if (contextMap.containsKey(token)) {
				// log( 2, String.format(
				// "ContextCache removing %s, contains %d", token,
				// currentlyCached-1));
				contextMap.remove(token);
				currentlyCached -= 1;
			}
		}

		public ContextTokenSpnTriple GetFromCache(String token) {
			// save a lookup in the synchronised hashmap
			if (currentlyCached == 0) {
				return null;
			}

			if (contextMap.containsKey(token)) {
				return contextMap.get(token);
			} else {
				return null;
			}
		}
	}

	private boolean checkConfigFileForForwardable(String configFilename) {
		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(
					new FileInputStream(configFilename)));

			boolean inLibDefaults = false;

			do {
				String s = br.readLine();
				if (s == null) {
					break;
				}

				s = s.trim();

				if (s.equals("[libdefaults]")) {
					inLibDefaults = true;
				} else if (s.startsWith("[")) {
					inLibDefaults = false;
				}

				if (inLibDefaults) {
					if (s.replace(" ", "").replace("\t", "")
							.equals("forwardable=true")) {
						br.close();
						return true;
					}
				}
			} while (true);

			br.close();
		} catch (FileNotFoundException e) {
			log(1, String.format("Couldn't open config file %s to check",
					configFilename));
		} catch (IOException e) {
			log(1, String.format("Error parsing config file %sk",
					configFilename));
		}

		return false;
	}
	
    private boolean isUnlimitedJCE() {
        
        try {
        	if( Cipher.getMaxAllowedKeyLength("AES") < 256)
        	{
        		return false;
        	}
        } 
        catch (NoSuchAlgorithmException ex) 
        {
        	try
        	{
	        	if( Cipher.getMaxAllowedKeyLength("RC4") < 256)
	        	{
	        		return false;
	        	} 
        	}
        	catch(NoSuchAlgorithmException e)
        	{
        		return false;	// really shouldn't get here
        	}
        }
        	
        return true;
    }

	// ================== GUI code starts here ========================================

	// header
	JScrollPane scroll;
	JPanel mainPanel;
	JCheckBox masterSwitchCheckBox;
	JLabel versionLabel;
	JButton restoreDefaultsButton;
	JButton clearStateButton;
	JButton logTicketsButton;
	
	// panels
	JPanel domainPanel;
	JPanel credsPanel;
	JPanel authenticationStrategyPanel;
	JPanel scopePanel;
	JPanel loggingPanel;
	JPanel delegationPanel;
	JPanel dummyPanel;
	
	// domain settings
	JLabel domainDnsLabel;
	JLabel kdcLabel;
	JTextField domainDnsNameTextField;
	JTextField kdcTextField;
	JButton changeDomainSettingsButton;
	JButton pingKDCButton;
	JButton domainDnsNameHelpButton;
	JButton kdcHelpButton;
	JButton domainControlsHelpButton;
	// JButton domainDnsNameAutoButton;
	JButton kdcAutoButton;
	JTextField domainStatusTextField;
	
	// credentials
	JLabel usernameLabel;
	JLabel passwordLabel;
	JTextField usernameTextField;
	JPasswordField passwordField;
	JButton usernameHelpButton;
	JButton changeCredentialsButton;
	JButton testCredentialsButton;
	JCheckBox savePasswordCheckBox;
	JButton passwordHelpButton;
	JButton credentialControlsHelpButton;
	JButton savePasswordHelpButton;
	JTextField credentialsStatusTextField;
	
	// delegation
	JButton checkDelegationConfigButton;
	JButton createKrb5ConfButton;
	JTextField krb5FileTextField;
	JLabel krb5FileLabel;
	JButton changeKrb5FileButton;
	JButton checkCurrentKrb5ConfigHelpButton;
	JButton delegationControlsHelpButton;
	JButton krb5FileHelpButton;
	
	// strategy
	JRadioButton proactiveButton;
	JRadioButton proactiveAfter401Button;
	JRadioButton reactiveButton;
	ButtonGroup authStrategyGroup;
	JButton authStrategyHelpButton;
	
	// scope
	JCheckBox ignoreNTLMServersCheckBox;
	JCheckBox includePlainhostnamesCheckBox;
	JCheckBox everythingInScopeCheckBox;
	JCheckBox wholeDomainInScopeCheckBox;
	JList<String> scopeListBox;
	JLabel scopeBoxLabel;
	JScrollPane scopePane;
	JButton scopeAddButton;
	JButton scopeEditButton;
	JButton scopeRemoveButton;
	
	JButton scopeHelpButton;
	
	// logging
	JLabel alertLevelLabel;
	JLabel loggingLevelLabel;
	JComboBox<String> alertLevelComboBox;
	JComboBox<String> loggingLevelComboBox;
	JButton alertLevelHelpButton;
	JButton loggingLevelHelpButton;

	// domain settings
	private final String domainDnsNameHelpString = "DNS name of the domain to authenticate against - not the NETBIOS name.";
	private final String kdcHelpString = "Hostname of a KDC (domain controller) for this domain.";
	private final String kdcTestSuccessString = "Successfully contacted Kerberos service.";
	private final String domainControlsHelpString = "\"Change...\" lets you change the Domain DNS Name and KDC Host.\n\n\"Autolocate KDC\" will do a DNS SRV lookup to try to find a KDC for the given domain.\n\n\"Test domain settings\" will check that the Kerberos service can be contacted successfully.";
	
	// credentials
	private final String usernameHelpString = "Username for a domain account. Just the plain username, not DOMAIN\\username or username@DOMAIN.COM or anything like that.";
	private final String credentialsTestSuccessString = "TGT successfully acquired.";
	private final String savePasswordHelpString = "Controls whether the password will be saved in Burp's settings file.";
	private final String passwordHelpString = "The domain password for the specified user.";
	
	private final String credentialControlsHelpString = "\"Change...\" lets you change the Username and Password.\n\n\"Test credentials\" will check that a ticket-granting ticket (TGT) can be acquired using these credentials.";
	
	// delegation
	private final String forwardableTgtString = "TGT is forwardable so delegation should work.";
	private final String notForwardableTgtString = "TGT is not forwardable so delegation will not work - you should use the \"Create krb5.conf file\" button to fix this.";
	private final String krb5FileHelpString = "The krb5.conf file which will be used (and controls whether delegation is enabled).";
	private final String checkCurrentKrb5ConfigHelpString = "Check if the specified krb5.conf file sets forwarding enabled.";
	private final String delegationControlsHelpString = "\"Change...\" lets you specify the location of the krb5.conf file.\n\n\"Create krb5.conf file\" creates a new minimal krb5.conf file, which will enable delegation, at a location of your choice on the file system.\n\n\"Check current config\" will verify that the specified krb5.conf file exists, and has delegation enabled.";
	
	// strategy
	private final String authStrategyHelpString = "There are three possible approaches here:\n\nReactive: when a 401 response is received from the server, add an appropriate Kerberos authentication header and resend the request. This is what Fiddler does.\nProactive: for hosts which are in scope for Kerberos authentication, add the Kerberos authentication header to outgoing requests (i.e. don't wait to get a 401).\nProactive after 401: use the reactive strategy for the first Kerberos authentication against a particular host, then if it was successful, move to proactive.\n\nThe Reactive approach is perhaps the most \"correct\", but is slower (requires an extra HTTP round trip to the server).\nThe Proactive approach is faster.\nThe Proactive after 401 approach is usually a good compromise.";
	
	// scope
	private final String scopeHelpString = "In this section, you can define which hosts are considered to be in scope for Kerberos authentication.\n\n\"All hosts in this Kerberos domain in scope for Kerberos\" is the default.\nThis means that Berserko will attempt Kerberos authentication only to web servers whose hostname ends with the domain DNS name.\n\n\"All hosts in scope for Kerberos authentication\" means that you don't need to bother specifying the scope manually.\nThe potential disadvantage of this configuration is that it might lead to Berserko sending Kerberos requests to the KDC to acquire service\ntickets for hosts which are not in the domain. This might cause performance issues, and might cause privacy issues (if you don't want this\ninformation leaked to the KDC).\n\nThe list box on the right allows you to specify additional hosts which should be in scope.\nIt is ignored when \"All hosts in scope for Kerberos authentication\" is selected.\n\nIf \"Plain hostnames considered part of domain\" is selected, Kerberos authentication will be attempted against hosts which are\nspecified by \"plain hostnames\", i.e. hostnames that are not qualified with the domain.\nThe only reason you might not want this would be if your machine was joined to a different domain from the one being\nauthenticated against using this extension.\n\nIf \"Do not perform Kerberos authentication to servers which support NTLM\" is selected, Kerberos authentication will not be performed\nagainst hosts which also support NTLM (as evidenced by a WWW-Authenticate: NTLM response header).\nThe purpose of selecting this would be to, for example, use Burp's existing NTLM authentication capability for these hosts.";
	
	// logging
	private final String alertLevelHelpString = "Controls level of logging performed to Burp's Alerts tab.";
	private final String loggingLevelHelpString = "Controls level of logging performed to extension's standard output.";
	
	@Override
	public Component getUiComponent() {
		return scroll;
	}

	@Override
	public String getTabCaption() {
		return tabName;
	}
	
	private void updateHostsInScope()
	{
		hostsInScope = new ArrayList<String>();
		
		for( int ii=0; ii<scopeListBox.getModel().getSize(); ii++)
		{
			hostsInScope.add( scopeListBox.getModel().getElementAt(ii));
		}
	}

	private void setupGUI() {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				// Create our initial UI components
				mainPanel = new JPanel();
				mainPanel.setLayout(new GridBagLayout());
				scroll = new JScrollPane(mainPanel);
				scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
				scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

				GridBagConstraints gbc = new GridBagConstraints();
				gbc.fill = GridBagConstraints.HORIZONTAL;

				masterSwitchCheckBox = new JCheckBox(
						"Do Kerberos authentication");
				versionLabel = new JLabel(extensionName + " version "
						+ versionString);
				restoreDefaultsButton = new JButton("Restore default settings");
				clearStateButton = new JButton("Clear Kerberos state");
				logTicketsButton = new JButton("Write tickets to log");

				domainPanel = new JPanel(new GridBagLayout());
				domainPanel.setBorder(BorderFactory
						.createTitledBorder("Domain Settings"));

				domainDnsLabel = new JLabel("Domain DNS Name");
				kdcLabel = new JLabel("KDC Host");
				domainDnsNameTextField = new JTextField();
				kdcTextField = new JTextField();
				domainStatusTextField = new JTextField();
				domainDnsNameTextField.setEditable(false);
				kdcTextField.setEditable(false);
				domainStatusTextField.setEditable(false);
				changeDomainSettingsButton = new JButton("Change...");
				pingKDCButton = new JButton("Test domain settings");
				domainDnsNameHelpButton = new JButton("?");
				kdcHelpButton = new JButton("?");
				domainControlsHelpButton = new JButton("?");
				kdcAutoButton = new JButton("Autolocate KDC");

				usernameLabel = new JLabel("Username               ");
				passwordLabel = new JLabel("Password               ");
				usernameTextField = new JTextField();
				usernameTextField.setEditable(false);
				passwordField = new JPasswordField();
				passwordField.setEditable(false);
				usernameHelpButton = new JButton("?");
				changeCredentialsButton = new JButton("Change...");
				testCredentialsButton = new JButton("Test credentials");
				savePasswordCheckBox = new JCheckBox(
						"Save password in Burp config?");
				credentialsStatusTextField = new JTextField();
				credentialsStatusTextField.setEditable(false);
				credentialControlsHelpButton = new JButton("?");
				savePasswordHelpButton = new JButton("?");
				passwordHelpButton = new JButton("?");

				alertLevelLabel = new JLabel("Alert Level            ");
				loggingLevelLabel = new JLabel("Logging Level        ");
				String[] levelStrings = { "None", "Normal", "Verbose" };
				alertLevelComboBox = new JComboBox<String>(levelStrings);
				loggingLevelComboBox = new JComboBox<String>(levelStrings);
				alertLevelHelpButton = new JButton("?");
				loggingLevelHelpButton = new JButton("?");

				proactiveButton = new JRadioButton(
						"Proactive Kerberos authentication");
				proactiveAfter401Button = new JRadioButton(
						"Proactive Kerberos authentication, only after initial 401 received");
				reactiveButton = new JRadioButton(
						"Reactive Kerberos authentication");
				authStrategyGroup = new ButtonGroup();
				authStrategyGroup.add(proactiveButton);
				authStrategyGroup.add(proactiveAfter401Button);
				authStrategyGroup.add(reactiveButton);
				authStrategyHelpButton = new JButton("?");
				
				everythingInScopeCheckBox = new JCheckBox(
						"All hosts in scope for Kerberos authentication");
				wholeDomainInScopeCheckBox = new JCheckBox(
						"All hosts in this Kerberos domain in scope for Kerberos");
				ignoreNTLMServersCheckBox = new JCheckBox(
						"Do not perform Kerberos authentication to servers which support NTLM");
				includePlainhostnamesCheckBox = new JCheckBox(
						"Plain hostnames (i.e. unqualified names) considered part of domain");
				scopeListBox = new JList<>( new DefaultListModel<String>());
				scopeListBox.setSelectionMode( ListSelectionModel.SINGLE_SELECTION);
				scopeBoxLabel = new JLabel( "Hosts in scope:");
				scopePane = new JScrollPane( scopeListBox);
				scopePane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
				scopePane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
				scopeAddButton = new JButton( "Add");
				scopeEditButton = new JButton( "Edit");
				scopeRemoveButton = new JButton( "Remove");
				//ignoreNTLMServersHelpButton = new JButton("?");
				//includePlainhostnamesHelpButton = new JButton("?");
				scopeHelpButton = new JButton( "?");

				checkDelegationConfigButton = new JButton(
						"Check current config");
				createKrb5ConfButton = new JButton("Create krb5.conf file");
				krb5FileLabel = new JLabel("krb5.conf file           ");
				krb5FileTextField = new JTextField("");
				krb5FileTextField.setEditable(false);
				changeKrb5FileButton = new JButton("Change...");
				checkCurrentKrb5ConfigHelpButton = new JButton("?");
				delegationControlsHelpButton = new JButton("?");
				krb5FileHelpButton = new JButton("?");

				credsPanel = new JPanel(new GridBagLayout());
				credsPanel.setBorder(BorderFactory
						.createTitledBorder("Domain Credentials"));

				authenticationStrategyPanel = new JPanel(new GridBagLayout());
				authenticationStrategyPanel.setBorder(BorderFactory
						.createTitledBorder("Authentication Strategy"));

				scopePanel = new JPanel(new GridBagLayout());
				scopePanel.setBorder(BorderFactory
						.createTitledBorder("Scope"));

				delegationPanel = new JPanel(new GridBagLayout());
				delegationPanel.setBorder(BorderFactory
						.createTitledBorder("Delegation"));

				loggingPanel = new JPanel(new GridBagLayout());
				loggingPanel.setBorder(BorderFactory
						.createTitledBorder("Logging"));

				dummyPanel = new JPanel();

				callbacks.customizeUiComponent(mainPanel);
				callbacks.customizeUiComponent(masterSwitchCheckBox);
				callbacks.customizeUiComponent(versionLabel);
				callbacks.customizeUiComponent(restoreDefaultsButton);
				callbacks.customizeUiComponent(clearStateButton);
				callbacks.customizeUiComponent(logTicketsButton);
				callbacks.customizeUiComponent(domainPanel);
				callbacks.customizeUiComponent(credsPanel);
				callbacks.customizeUiComponent(authenticationStrategyPanel);
				callbacks.customizeUiComponent(scopePanel);
				callbacks.customizeUiComponent(loggingPanel);
				callbacks.customizeUiComponent(domainDnsLabel);
				callbacks.customizeUiComponent(kdcLabel);
				callbacks.customizeUiComponent(domainDnsNameTextField);
				callbacks.customizeUiComponent(kdcTextField);
				callbacks.customizeUiComponent(domainStatusTextField);
				callbacks.customizeUiComponent(changeDomainSettingsButton);
				callbacks.customizeUiComponent(pingKDCButton);
				callbacks.customizeUiComponent(domainDnsNameHelpButton);
				callbacks.customizeUiComponent(kdcHelpButton);
				// callbacks.customizeUiComponent(domainDnsNameAutoButton);
				callbacks.customizeUiComponent(kdcAutoButton);
				callbacks.customizeUiComponent(usernameLabel);
				callbacks.customizeUiComponent(passwordLabel);
				callbacks.customizeUiComponent(usernameTextField);
				callbacks.customizeUiComponent(passwordField);
				callbacks.customizeUiComponent(usernameHelpButton);
				callbacks.customizeUiComponent(changeCredentialsButton);
				callbacks.customizeUiComponent(testCredentialsButton);
				callbacks.customizeUiComponent(savePasswordCheckBox);
				callbacks.customizeUiComponent(alertLevelLabel);
				callbacks.customizeUiComponent(loggingLevelLabel);
				callbacks.customizeUiComponent(alertLevelComboBox);
				callbacks.customizeUiComponent(loggingLevelComboBox);
				callbacks.customizeUiComponent(alertLevelHelpButton);
				callbacks.customizeUiComponent(loggingLevelHelpButton);

				callbacks.customizeUiComponent(proactiveButton);
				callbacks.customizeUiComponent(proactiveAfter401Button);
				callbacks.customizeUiComponent(reactiveButton);
				callbacks.customizeUiComponent(authStrategyHelpButton);
				
				callbacks.customizeUiComponent(ignoreNTLMServersCheckBox);
				callbacks.customizeUiComponent(includePlainhostnamesCheckBox);
				callbacks.customizeUiComponent(everythingInScopeCheckBox);
				callbacks.customizeUiComponent(wholeDomainInScopeCheckBox);
				callbacks.customizeUiComponent(scopeHelpButton);
				callbacks.customizeUiComponent(scopeListBox);
				callbacks.customizeUiComponent(scopePane);
				callbacks.customizeUiComponent(scopeAddButton);
				callbacks.customizeUiComponent(scopeEditButton);
				callbacks.customizeUiComponent(scopeRemoveButton);
				callbacks.customizeUiComponent(scopeBoxLabel);
				//callbacks.customizeUiComponent(ignoreNTLMServersHelpButton);
				//callbacks.customizeUiComponent(includePlainhostnamesHelpButton);

				callbacks.customizeUiComponent(checkDelegationConfigButton);
				callbacks.customizeUiComponent(createKrb5ConfButton);
				callbacks.customizeUiComponent(krb5FileTextField);
				callbacks.customizeUiComponent(changeKrb5FileButton);
				callbacks
						.customizeUiComponent(checkCurrentKrb5ConfigHelpButton);
				callbacks.customizeUiComponent(delegationControlsHelpButton);
				callbacks.customizeUiComponent(krb5FileHelpButton);

				// DOMAIN SETTINGS PANEL LAYOUT
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				domainPanel.add(domainDnsLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 1;
				domainPanel.add(kdcLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				gbc.gridwidth = 5;
				domainPanel.add(domainDnsNameTextField, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 1;
				gbc.gridwidth = 5;
				domainPanel.add(kdcTextField, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 4;
				gbc.gridy = 2;
				gbc.gridwidth = 2;
				domainPanel.add(domainStatusTextField, gbc);
				gbc.gridwidth = 1;
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 2;
				domainPanel.add(changeDomainSettingsButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 3;
				gbc.gridy = 2;
				domainPanel.add(pingKDCButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 2;
				gbc.gridy = 2;
				domainPanel.add(kdcAutoButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 6;
				gbc.gridy = 0;
				domainPanel.add(domainDnsNameHelpButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 6;
				gbc.gridy = 2;
				domainPanel.add(domainControlsHelpButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 6;
				gbc.gridy = 1;
				domainPanel.add(kdcHelpButton, gbc);

				// CREDENTIALS PANEL LAYOUT
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				credsPanel.add(usernameLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 1;
				credsPanel.add(passwordLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				gbc.gridwidth = 4;
				credsPanel.add(usernameTextField, gbc);
				gbc.gridwidth = 1;
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 1;
				gbc.gridwidth = 4;
				credsPanel.add(passwordField, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 3;
				gbc.gridy = 2;
				gbc.gridwidth = 2;
				credsPanel.add(credentialsStatusTextField, gbc);
				gbc.gridwidth = 1;
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 2;
				credsPanel.add(changeCredentialsButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 2;
				gbc.gridy = 2;
				credsPanel.add(testCredentialsButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 5;
				gbc.gridy = 0;
				credsPanel.add(usernameHelpButton, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 3;
				gbc.gridwidth = 4;
				credsPanel.add(savePasswordCheckBox, gbc);
				gbc.gridwidth = 1;
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 5;
				gbc.gridy = 1;
				credsPanel.add(passwordHelpButton, gbc);
				gbc.gridwidth = 1;
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 5;
				gbc.gridy = 2;
				credsPanel.add(credentialControlsHelpButton, gbc);
				gbc.gridwidth = 1;
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 5;
				gbc.gridy = 3;
				credsPanel.add(savePasswordHelpButton, gbc);

				// DELEGATION PANEL LAYOUT
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				delegationPanel.add(krb5FileLabel, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				gbc.gridwidth = 4;
				delegationPanel.add(krb5FileTextField, gbc);
				gbc.gridwidth = 1;
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 5;
				gbc.gridy = 0;
				delegationPanel.add(krb5FileHelpButton, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 1;
				delegationPanel.add(changeKrb5FileButton, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 2;
				gbc.gridy = 1;
				delegationPanel.add(createKrb5ConfButton, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 3;
				gbc.gridy = 1;
				delegationPanel.add(checkDelegationConfigButton, gbc);

				/*
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 5;
				gbc.gridy = 0;
				delegationPanel.add(checkCurrentKrb5ConfigHelpButton, gbc);
				*/
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 5;
				gbc.gridy = 1;
				delegationPanel.add(delegationControlsHelpButton, gbc);

				// LOGGING PANEL LAYOUT
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				loggingPanel.add(alertLevelLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 1;
				loggingPanel.add(loggingLevelLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				gbc.gridwidth = 3;
				loggingPanel.add(alertLevelComboBox, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 1;
				gbc.gridwidth = 3;
				loggingPanel.add(loggingLevelComboBox, gbc);
				gbc.gridwidth = 1;
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 4;
				gbc.gridy = 0;
				loggingPanel.add(alertLevelHelpButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 4;
				gbc.gridy = 1;
				loggingPanel.add(loggingLevelHelpButton, gbc);

				// AUTH STRATEGY PANEL LAYOUT
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				authenticationStrategyPanel.add(reactiveButton, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				authenticationStrategyPanel.add(proactiveButton, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 2;
				gbc.gridy = 0;
				authenticationStrategyPanel.add(proactiveAfter401Button, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 3;
				gbc.gridy = 0;
				authenticationStrategyPanel.add(authStrategyHelpButton, gbc);

				// SCOPE PANEL LAYOUT
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 2.0;
				gbc.weighty = 1.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				scopePanel.add(everythingInScopeCheckBox, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 2.0;
				gbc.weighty = 1.0;
				gbc.gridx = 0;
				gbc.gridy = 1;
				scopePanel.add(wholeDomainInScopeCheckBox, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 2.0;
				gbc.weighty = 1.0;
				gbc.gridx = 0;
				gbc.gridy = 2;
				scopePanel.add(includePlainhostnamesCheckBox, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 1.0;
				gbc.gridx = 0;
				gbc.gridy = 3;
				scopePanel.add(ignoreNTLMServersCheckBox, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.BOTH;
				gbc.weightx = 4.0;
				gbc.weighty = 3.0;
				gbc.gridx = 1;
				gbc.gridy = 1;
				gbc.gridheight = 3;
				scopePanel.add(scopePane, gbc);
				gbc.gridheight = 1;
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 1.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				scopePanel.add(scopeBoxLabel, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 1.0;
				gbc.gridx = 2;
				gbc.gridy = 1;
				scopePanel.add(scopeAddButton, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 1.0;
				gbc.gridx = 2;
				gbc.gridy = 2;
				scopePanel.add(scopeEditButton, gbc);
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 1.0;
				gbc.gridx = 2;
				gbc.gridy = 3;
				scopePanel.add(scopeRemoveButton, gbc);				
				
				gbc.insets = new Insets(5, 5, 5, 5);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 3;
				gbc.gridy = 0;
				scopePanel.add(scopeHelpButton, gbc);
				
				// MAIN PANEL LAYOUT

				gbc.gridwidth = 5;
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				gbc.gridwidth = 1;
				mainPanel.add(masterSwitchCheckBox, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				mainPanel.add(logTicketsButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 2;
				gbc.gridy = 0;
				mainPanel.add(restoreDefaultsButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 3;
				gbc.gridy = 0;
				mainPanel.add(clearStateButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 4;
				gbc.gridy = 0;
				mainPanel.add(versionLabel, gbc);
				gbc.gridwidth = 5;
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.1;
				gbc.gridx = 0;
				gbc.gridy = 1;
				mainPanel.add(domainPanel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.1;
				gbc.gridx = 0;
				gbc.gridy = 2;
				mainPanel.add(credsPanel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.1;
				gbc.gridx = 0;
				gbc.gridy = 3;
				mainPanel.add(delegationPanel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.1;
				gbc.gridx = 0;
				gbc.gridy = 4;
				mainPanel.add(authenticationStrategyPanel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.1;
				gbc.gridx = 0;
				gbc.gridy = 5;
				mainPanel.add(scopePanel, gbc);
				gbc.weightx = 1.0;
				gbc.weighty = 0.1;
				gbc.gridx = 0;
				gbc.gridy = 6;
				mainPanel.add(loggingPanel, gbc);
				gbc.fill = GridBagConstraints.BOTH;
				gbc.weightx = 1.0;
				gbc.weighty = 3.0;
				gbc.gridx = 0;
				gbc.gridy = 7;
				mainPanel.add(dummyPanel, gbc);

				// ACTION LISTENERS
				masterSwitchCheckBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent actionEvent) {
						JCheckBox cb = (JCheckBox) actionEvent.getSource();
						masterSwitchEnabled(cb.isSelected());
						if( cb.isSelected())
						{
							updateScopeControls( !everythingInScope);
							updateScopeListLabel(everythingInScope, wholeDomainInScope);
						}
					}
				});

				savePasswordCheckBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent actionEvent) {
						JCheckBox cb = (JCheckBox) actionEvent.getSource();
						savePassword = cb.isSelected();
					}
				});

				changeDomainSettingsButton
						.addActionListener(new ActionListener() {
							public void actionPerformed(ActionEvent e) {
								changeDomainSettings();
							}
						});

				pingKDCButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						pingKDC();
					}
				});

				// domainDnsNameAutoButton.addActionListener(new
				// ActionListener() {
				// public void actionPerformed(ActionEvent e) {
				// domainDnsNameAuto();
				// }
				// } );

				kdcAutoButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						kdcAuto();
					}
				});

				changeCredentialsButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						changeCredentials();
					}
				});

				testCredentialsButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						testCredentials();
					}
				});

				alertLevelComboBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						@SuppressWarnings("unchecked")
						JComboBox<String> cb = (JComboBox<String>) e
								.getSource();
						alertLevel = cb.getSelectedIndex();
					}
				});

				loggingLevelComboBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						@SuppressWarnings("unchecked")
						JComboBox<String> cb = (JComboBox<String>) e
								.getSource();
						logLevel = cb.getSelectedIndex();
					}
				});
				
				everythingInScopeCheckBox
				.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent actionEvent) {
						JCheckBox cb = (JCheckBox) actionEvent
								.getSource();
						everythingInScope = cb.isSelected();
						updateScopeControls( !everythingInScope);
						updateScopeListLabel(everythingInScope, wholeDomainInScope);
						warnIfProactiveAndEverythingInScope();
					}
				});		
				
				wholeDomainInScopeCheckBox
				.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent actionEvent) {
						JCheckBox cb = (JCheckBox) actionEvent
								.getSource();
						wholeDomainInScope = cb.isSelected();
						updateScopeListLabel(everythingInScope, wholeDomainInScope);
					}
				});	

				includePlainhostnamesCheckBox
						.addActionListener(new ActionListener() {
							public void actionPerformed(ActionEvent actionEvent) {
								JCheckBox cb = (JCheckBox) actionEvent
										.getSource();
								plainhostExpand = cb.isSelected();
							}
						});

				ignoreNTLMServersCheckBox
						.addActionListener(new ActionListener() {
							public void actionPerformed(ActionEvent actionEvent) {
								JCheckBox cb = (JCheckBox) actionEvent
										.getSource();
								ignoreNTLMServers = cb.isSelected();
							}
						});
				
				scopeAddButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						String s = hostDialogBox("");
						
						while( s.length() > 0 && !checkSpecialHostnameRegexp(s))
						{
							if( !checkSpecialHostnameRegexp(s))
							{
								JOptionPane
								.showMessageDialog(
										null,
										"Not a valid hostname expression",
										"Error", JOptionPane.ERROR_MESSAGE);
							}
							
							s = hostDialogBox(s);
						}
						
						if( s.length() > 0)
						{
							for( int ii=0; ii<scopeListBox.getModel().getSize(); ii++)
							{
								if( s.equals(((DefaultListModel<String>) scopeListBox.getModel()).getElementAt(ii)))
								{
									JOptionPane
									.showMessageDialog(
											null,
											"Already present in list",
											"Error", JOptionPane.ERROR_MESSAGE);
									return;
								}
							}
							
							((DefaultListModel<String>) scopeListBox.getModel()).addElement( s);
							updateHostsInScope();
						}
					}
				});	
				
				scopeEditButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						int index = scopeListBox.getSelectedIndex(); 
					    if (index != -1) 
					    { 
					    	String s = ((DefaultListModel<String>) scopeListBox.getModel()).getElementAt(index);
					    	
					    	s = hostDialogBox(s);
					    	
							while( s.length() > 0 && !checkSpecialHostnameRegexp(s))
							{
								if( !checkSpecialHostnameRegexp(s))
								{
									JOptionPane
									.showMessageDialog(
											null,
											"Not a valid hostname expression",
											"Error", JOptionPane.ERROR_MESSAGE);
								}
								
								s = hostDialogBox(s);
							}
					    	
					    	if( s.length() > 0)
							{
								for( int ii=0; ii<scopeListBox.getModel().getSize(); ii++)
								{
									if( ii != index && s.equals(((DefaultListModel<String>) scopeListBox.getModel()).getElementAt(ii)))
									{
										JOptionPane
										.showMessageDialog(
												null,
												"Already present in list",
												"Error", JOptionPane.ERROR_MESSAGE);
										return;
									}
								}
					    		
								((DefaultListModel<String>) scopeListBox.getModel()).setElementAt( s, index);
								updateHostsInScope();
							}
					    }
					}
				});	
				
				scopeRemoveButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						int index = scopeListBox.getSelectedIndex(); 
					    if (index != -1) 
					    { 
					    	((DefaultListModel<String>) scopeListBox.getModel()).removeElementAt(index);
					    	updateHostsInScope();
					    } 
					}
				});						

				proactiveAfter401Button.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						authStrategy = AuthStrategy.PROACTIVE_AFTER_401;
					}
				});

				proactiveButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						authStrategy = AuthStrategy.PROACTIVE;
						warnIfProactiveAndEverythingInScope();
					}
				});

				reactiveButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						authStrategy = AuthStrategy.REACTIVE_401;
					}
				});

				checkDelegationConfigButton
						.addActionListener(new ActionListener() {
							public void actionPerformed(ActionEvent e) {
								testDelegationConfig();
							}
						});

				createKrb5ConfButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						JFileChooser chooser = new JFileChooser();
						chooser.setSelectedFile(new File("krb5.conf"));
						chooser.setDialogTitle("Create new krb5.conf file");
						int returnVal = chooser.showSaveDialog(mainPanel);

						if (returnVal == JFileChooser.APPROVE_OPTION) {
							File f = chooser.getSelectedFile();

							if (f.exists()) {
								int n = JOptionPane
										.showConfirmDialog(
												chooser,
												"File already exists - do you want to continue and overwrite it?",
												"File already exists",
												JOptionPane.YES_NO_OPTION);

								if (n == JOptionPane.NO_OPTION) {
									return;
								}
							}

							try {
								PrintWriter writer = new PrintWriter(f);
								writer.println("[libdefaults]");
								writer.println("\tforwardable = true");
								writer.close();
							} catch (FileNotFoundException ee) {
								JOptionPane.showMessageDialog(null, String
										.format("Could not write to file %s\n",
												f), "Error",
										JOptionPane.ERROR_MESSAGE);
								return;
							}

							int n = JOptionPane
									.showConfirmDialog(
											chooser,
											"File created successfully - do you want to set this as the krb5.conf file to be used?",
											"Success",
											JOptionPane.YES_NO_OPTION);

							if (n == JOptionPane.YES_OPTION) {
								krb5FileTextField.setText(f.getPath());
								krb5File = f.getPath();
							}
						}
					}
				});

				changeKrb5FileButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						JFileChooser chooser = new JFileChooser();
						chooser.setSelectedFile(new File("krb5.conf"));
						chooser.setDialogTitle("Select krb5.conf file");
						int returnVal = chooser.showOpenDialog(mainPanel);

						if (returnVal == JFileChooser.APPROVE_OPTION) {
							File f = chooser.getSelectedFile();

							boolean result = checkConfigFileForForwardable(f
									.getPath());

							if (!result) {
								int n = JOptionPane.showConfirmDialog(
										null,
										String.format(
												"This Kerberos config file does not have \"forwardable=true\" set in it - delegation won't currently work.\n\nContinue?",
												krb5File), "Error",
										JOptionPane.YES_NO_OPTION);

								if (n == JOptionPane.NO_OPTION) {
									return;
								}
							}

							krb5FileTextField.setText(f.getPath());
							krb5File = f.getPath();
						}
					}
				});

				restoreDefaultsButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						setDefaultConfig();
						initialiseGUIFromConfig();
					}
				});
				
				logTicketsButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						int ticketCount = 1;

						if( loginContext == null || loginContext.getSubject() == null || loginContext.getSubject().getPrivateCredentials() == null)
						{
							log( 1, "No stored tickets");
						}
						else
						{
							for (Object ob : loginContext.getSubject().getPrivateCredentials()) {
								if (ob instanceof KerberosTicket) {
									KerberosTicket kt = (KerberosTicket) ob;
									log( 1, String.format("=== TICKET %d - %s @ %s ==================", ticketCount, kt.getClient().toString(), kt.getServer().toString()));
									ticketCount += 1;
									log( 1, kt.toString());
								}
							}
						}
					}
				});
				
				clearStateButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						int n = JOptionPane.showConfirmDialog(
								null,
								"Are you sure you want to clear the current Kerberos state (tickets, cached SPN mappings, etc.)?\n\nThere is usually no need to do this unless changes have been made on the server side and you want to start from a clean state.", "Clear Kerberos state",
								JOptionPane.YES_NO_OPTION);

						if (n == JOptionPane.NO_OPTION) {
							return;
						}	
						
						clearKerberosState();
					}
				});

				domainDnsNameHelpButton
						.addActionListener(new HelpButtonActionListener(
								domainDnsNameHelpString));
				kdcHelpButton.addActionListener(new HelpButtonActionListener(
						kdcHelpString));
				usernameHelpButton
						.addActionListener(new HelpButtonActionListener(
								usernameHelpString));
				alertLevelHelpButton
						.addActionListener(new HelpButtonActionListener(
								alertLevelHelpString));
				loggingLevelHelpButton
						.addActionListener(new HelpButtonActionListener(
								loggingLevelHelpString));
				authStrategyHelpButton
						.addActionListener(new HelpButtonActionListener(
								authStrategyHelpString));
				scopeHelpButton
						.addActionListener(new HelpButtonActionListener(
								scopeHelpString));				
				checkCurrentKrb5ConfigHelpButton
						.addActionListener(new HelpButtonActionListener(checkCurrentKrb5ConfigHelpString));
				delegationControlsHelpButton
						.addActionListener(new HelpButtonActionListener(delegationControlsHelpString));
				krb5FileHelpButton
						.addActionListener(new HelpButtonActionListener(krb5FileHelpString));
				domainControlsHelpButton.addActionListener( new HelpButtonActionListener(domainControlsHelpString));
				credentialControlsHelpButton.addActionListener( new HelpButtonActionListener(credentialControlsHelpString));
				savePasswordHelpButton.addActionListener( new HelpButtonActionListener(savePasswordHelpString));
				passwordHelpButton.addActionListener( new HelpButtonActionListener(passwordHelpString));
				

				initialiseGUIFromConfig();

				// Add our tab to the suite
				callbacks.addSuiteTab(BurpExtender.this);
			}
		});
	}

	private void testDelegationConfig() {
		if (krb5File.isEmpty()) {
			JOptionPane
					.showMessageDialog(
							null,
							"No krb5.conf file has been specified yet - delegation won't currently work.\n\nUse the \"Change\" button to specify a file, or \"Create krb5.conf file\" to create a new one.",
							"Error", JOptionPane.ERROR_MESSAGE);
		} else {
			if (new File(krb5File).exists()) {
				boolean result = checkConfigFileForForwardable(krb5File);

				if (result) {
					JOptionPane
							.showMessageDialog(
									null,
									String.format(
											"krb5.conf file found at %s, and \"forwardable=true\" set - delegation should work",
											krb5File), "Success",
									JOptionPane.INFORMATION_MESSAGE);
				} else {
					JOptionPane
							.showMessageDialog(
									null,
									String.format(
											"krb5.conf file found at %s, but \"forwardable=true\" not set in it - delegation won't currently work.\n\nTry editing the file, or creating a new one.",
											krb5File), "Error",
									JOptionPane.ERROR_MESSAGE);
				}
			} else {
				JOptionPane
						.showMessageDialog(
								null,
								String.format(
										"Can't find krb5.conf file %s - delegation won't currently work.",
										krb5File), "Error",
								JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	private void initialiseGUIFromConfig() {
		masterSwitchCheckBox.setSelected(masterSwitch);
		masterSwitchEnabled(masterSwitch);
		
		domainDnsNameTextField.setText(domainDnsName);
		kdcTextField.setText(kdcHost);
		domainStatusTextField.setText("");
		
		credentialsStatusTextField.setText("");
		usernameTextField.setText(username);
		passwordField.setText(password);
		savePasswordCheckBox.setSelected(savePassword);
		
		krb5FileTextField.setText(krb5File);
		
		switch (authStrategy) {
		case PROACTIVE:
			proactiveButton.setSelected(true);
			break;
		case PROACTIVE_AFTER_401:
			proactiveAfter401Button.setSelected(true);
			break;
		case REACTIVE_401:
			reactiveButton.setSelected(true);
			break;
		}
		
		everythingInScopeCheckBox.setSelected(everythingInScope);
		wholeDomainInScopeCheckBox.setSelected(wholeDomainInScope);
		for( String s : hostsInScope)
		{
			((DefaultListModel<String>) scopeListBox.getModel()).addElement( s);
		}
		includePlainhostnamesCheckBox.setSelected(plainhostExpand);
		ignoreNTLMServersCheckBox.setSelected(ignoreNTLMServers);
		//updateScopeControls( !everythingInScope);
		//updateScopeListLabel(everythingInScope, wholeDomainInScope);
		
		alertLevelComboBox.setSelectedIndex(alertLevel);
		loggingLevelComboBox.setSelectedIndex(logLevel);
	}
	
	
	private void updateScopeControls( boolean enable)
	{
		wholeDomainInScopeCheckBox.setEnabled(enable);
		includePlainhostnamesCheckBox.setEnabled(enable);
		scopeListBox.setEnabled(enable);
		scopeBoxLabel.setEnabled(enable);
		scopeAddButton.setEnabled(enable);
		scopeEditButton.setEnabled(enable);
		scopeRemoveButton.setEnabled(enable);
	}
	
	private void updateScopeListLabel( boolean everythingInScope, boolean wholeDomainInScope)
	{
		if( everythingInScope)
		{
			scopeBoxLabel.setText( "Additional hosts in scope:");
		}
		else
		{
			if( wholeDomainInScope)
			{
				scopeBoxLabel.setText( "Additional hosts in scope:");
			}
			else
			{
				scopeBoxLabel.setText( "Hosts in scope:");
			}
		}
	}

	// http://stackoverflow.com/questions/10985734/java-swing-enabling-disabling-all-components-in-jpanel
	private void enableComponents(Container container, boolean enable) {
		Component[] components = container.getComponents();
		for (Component component : components) {
			component.setEnabled(enable);
			if (component instanceof Container) {
				enableComponents((Container) component, enable);
			}
		}
	}

	private void masterSwitchEnabled(boolean enabled) {
		alertAndLog(1, enabled ? "Kerberos authentication enabled"
				: "Kerberos authentication disabled");

		masterSwitch = enabled;
		domainPanel.setEnabled(enabled);
		enableComponents(domainPanel, enabled);
		credsPanel.setEnabled(enabled);
		enableComponents(credsPanel, enabled);
		authenticationStrategyPanel.setEnabled(enabled);
		enableComponents(authenticationStrategyPanel, enabled);
		scopePanel.setEnabled(enabled);
		enableComponents(scopePanel, enabled);
		loggingPanel.setEnabled(enabled);
		enableComponents(loggingPanel, enabled);
		delegationPanel.setEnabled(enabled);
		enableComponents(delegationPanel, enabled);

		if (enabled) {
			if (domainDnsName.isEmpty() || kdcHost.isEmpty()
					|| username.isEmpty()) {
				JOptionPane
						.showMessageDialog(
								null,
								"Domain DNS Name, KDC Host, Username and (probably) Password must all be set, and ideally tested, before Kerberos authentication will work",
								"Warning", JOptionPane.WARNING_MESSAGE);
			} else if (password.isEmpty()) {
				JOptionPane
						.showMessageDialog(
								null,
								"Password is not set - probably because it wasn't saved in the extension settings.\n\nYou need to set it (unless the account has a blank password of course).",
								"Warning", JOptionPane.WARNING_MESSAGE);
			}
			
			warnIfProactiveAndEverythingInScope();
		}
	}
	
	private void warnIfProactiveAndEverythingInScope()
	{
		if( authStrategy == AuthStrategy.PROACTIVE && everythingInScope)
		{
			JOptionPane
			.showMessageDialog(
					null,
					"It is not recommended to set all hosts in scope in combination with the 'Proactive' strategy, as this may lead to lots of spurious Kerberos traffic (and possible privacy issues).\n\nIt is suggested to use 'Proactive after 401' instead.",
					"Warning", JOptionPane.WARNING_MESSAGE);
		}
	}

	private void changeDomainSettings() {
		JTextField newDomainDnsNameTextField = new JTextField();
		newDomainDnsNameTextField.setText(domainDnsName);
		JTextField newKdcTextField = new JTextField();
		newKdcTextField.setText(kdcHost);
		final JComponent[] inputs = new JComponent[] {
				new JLabel("Domain DNS Name"), newDomainDnsNameTextField,
				new JLabel("KDC Host"), newKdcTextField, };
		JOptionPane.showMessageDialog(null, inputs, "Change domain settings",
				JOptionPane.PLAIN_MESSAGE);

		if (newDomainDnsNameTextField.getText().endsWith(".")) {
			JOptionPane.showMessageDialog(null,
					"Removing dot from end of DNS domain name", "Info",
					JOptionPane.INFORMATION_MESSAGE);
			newDomainDnsNameTextField.setText(newDomainDnsNameTextField
					.getText().substring(0,
							newDomainDnsNameTextField.getText().length() - 1));
		}
		if (newKdcTextField.getText().endsWith(".")) {
			JOptionPane.showMessageDialog(null,
					"Removing dot from end of KDC hostname", "Info",
					JOptionPane.INFORMATION_MESSAGE);
			newKdcTextField.setText(newKdcTextField.getText().substring(0,
					newKdcTextField.getText().length() - 1));
		}

		if (!checkHostnameRegexp(newDomainDnsNameTextField.getText())) {
			JOptionPane
					.showMessageDialog(
							null,
							"DNS domain name does not match hostname regexp - please check",
							"Warning", JOptionPane.WARNING_MESSAGE);
		} else if (!isMultiComponentHostname(newDomainDnsNameTextField
				.getText())) {
			JOptionPane
					.showMessageDialog(
							null,
							"This seems to be a single-component DNS name - this isn't valid for Windows domains but might be valid for other Kerberos realms",
							"Warning", JOptionPane.WARNING_MESSAGE);
		}

		if (!checkHostnameRegexp(newKdcTextField.getText())) {
			if (!newKdcTextField.getText().isEmpty()) {
				JOptionPane
						.showMessageDialog(
								null,
								"KDC hostname does not match hostname regexp - please check",
								"Warning", JOptionPane.WARNING_MESSAGE);
			} else {
				JOptionPane
						.showMessageDialog(
								null,
								"You will need to also set the KDC Host before authentication will work.\n\nMaybe try the Auto button.",
								"Warning", JOptionPane.WARNING_MESSAGE);
			}
		}

		if ((newDomainDnsNameTextField.getText() != domainDnsName)
				|| (newKdcTextField.getText() != kdcHost)) // don't do anything if values are unchanged
		{
			domainDnsName = newDomainDnsNameTextField.getText();
			domainDnsNameTextField.setText(newDomainDnsNameTextField.getText());
			kdcHost = newKdcTextField.getText();
			kdcTextField.setText(newKdcTextField.getText());
			domainStatusTextField.setText("");
			credentialsStatusTextField.setText("");

			if (domainDnsName.isEmpty()) {
				domainStatusTextField
						.setText("Domain DNS name cannot be empty");
			} else if (kdcHost.isEmpty()) {
				domainStatusTextField.setText("KDC host cannot be empty");
			}

			setDomainAndKdc(domainDnsName, kdcHost);
		}

		domainDnsNameTextField.setText(newDomainDnsNameTextField.getText());
		kdcTextField.setText(newKdcTextField.getText());

	}
	
	// 
	// ValidHostnameRegex = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$";
	
	private boolean checkSpecialHostnameRegexp(String input) {
		// https://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
		String pattern = "^(([a-zA-Z0-9\\*\\?]|[a-zA-Z0-9\\*\\?][a-zA-Z0-9\\-\\*\\?]*[a-zA-Z0-9\\*\\?])\\.)*([A-Za-z0-9\\*\\?]|[A-Za-z0-9\\*\\?][A-Za-z0-9\\*\\?\\-]*[A-Za-z0-9\\*\\?])$";
		Pattern r = Pattern.compile(pattern);

		Matcher m = r.matcher(input);

		return m.find();
	}
	
	private String hostDialogBox( String input)
	{
		JTextField hostnameTextField = new JTextField();
		hostnameTextField.setText(input);
		
		final JComponent[] inputs = new JComponent[] { new JLabel("Specify a hostname"), new JLabel( "You can use wildcards (* matches zero or more characters, ? matches any character except a dot)"),
				hostnameTextField};
		int result = JOptionPane.showConfirmDialog(null, inputs, input.length() == 0 ? "Add host" : "Edit host", JOptionPane.OK_CANCEL_OPTION,
						JOptionPane.PLAIN_MESSAGE);
		
		if( result == JOptionPane.OK_OPTION)
		{
			return hostnameTextField.getText();
		}
		else
		{
			return "";
		}
	}

	@SuppressWarnings("deprecation")
	private void changeCredentials() {
		JTextField newUsernameTextField = new JTextField();
		newUsernameTextField.setText(username);
		JPasswordField newPasswordField = new JPasswordField();
		newPasswordField.setText(password);
		final JComponent[] inputs = new JComponent[] { new JLabel("Username "),
				newUsernameTextField, new JLabel("Password "), newPasswordField, };
		JOptionPane.showMessageDialog(null, inputs, "Change credentials",
				JOptionPane.PLAIN_MESSAGE);

		if (newUsernameTextField.getText().contains("\\")
				|| newUsernameTextField.getText().contains("/")
				|| newUsernameTextField.getText().contains("@")) {
			JOptionPane
					.showMessageDialog(
							null,
							"Username shouldn't contain slash, backslash or '@' - just a plain username is required",
							"Warning", JOptionPane.WARNING_MESSAGE);
		}

		if ((newUsernameTextField.getText() != username)
				|| (newPasswordField.getText() != password)) // don't do anything if values are unchanged
		{
			username = newUsernameTextField.getText();
			usernameTextField.setText(newUsernameTextField.getText());
			password = newPasswordField.getText();
			passwordField.setText(newPasswordField.getText());
			credentialsStatusTextField.setText("");

			if (username.isEmpty()) {
				credentialsStatusTextField.setText("Username cannot be empty");
			}

			setCredentials(username, password);
		}
	}
	
	private void testCredentials() {
		
		if (usernameTextField.getText().isEmpty()) {
			JOptionPane.showMessageDialog(null, "Username not set yet",
					"Error", JOptionPane.ERROR_MESSAGE);
			return;
		}

		if (!(domainStatusTextField.getText().equals(kdcTestSuccessString))) {
			int n = JOptionPane
					.showConfirmDialog(
							null,
							"You haven't successfully tested the domain settings yet, do you want to continue without doing so?\nIf the KDC can't be found, this command will hang Burp for quite a while (around 90 seconds).",
							"Proceed?", JOptionPane.YES_NO_OPTION);

			if (n == JOptionPane.NO_OPTION) {
				return;
			}
		}

		setKrb5Config();

		setupKerberosConfig();
		
		try {
			LoginContext loginContext = new LoginContext("KrbLogin",
					new KerberosCallBackHandler(username, password));
			loginContext.login();

			boolean forwardable = checkTgtForwardableFlag(loginContext
					.getSubject());

			credentialsStatusTextField.setText(credentialsTestSuccessString
					+ " ("
					+ (forwardable ? forwardableTgtString
							: notForwardableTgtString) + ")");
			JOptionPane.showMessageDialog(null, credentialsTestSuccessString
					+ "\n\n("
					+ (forwardable ? forwardableTgtString
							: notForwardableTgtString) + ")", "Success",
					JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception e) {
			if (e.getMessage().startsWith(
					"Client not found in Kerberos database")) {
				credentialsStatusTextField
						.setText("Failed to acquire TGT - username appears to be invalid");
				JOptionPane
						.showMessageDialog(
								null,
								"Failed to acquire TGT - username appears to be invalid.",
								"Failure", JOptionPane.ERROR_MESSAGE);
				log(1, "Error when testing credentials: " + e.getMessage());				
			} else if (e.getMessage().startsWith(
					"Pre-authentication information was invalid")) {
				credentialsStatusTextField
						.setText("Failed to acquire TGT - password appears to be invalid");
				JOptionPane
						.showMessageDialog(
								null,
								"Failed to acquire TGT - password appears to be invalid.\n\nBe careful not to lock out the account with more tests.",
								"Failure", JOptionPane.ERROR_MESSAGE);
				log(1, "Error when testing credentials: " + e.getMessage());
			} else if( e.getMessage().startsWith( "KDC has no support for encryption type"))
			{
				credentialsStatusTextField
				.setText("Failed to acquire TGT - encryption type not supported");
				if( unlimitedJCE)
				{
					JOptionPane
					.showMessageDialog(
							null,
							"Failed to acquire TGT - encryption algorithm not supported by KDC.\n\nThis is unexpected, as you appear to have the JCE Unlimited Strength Jurisdiction Policy installed.",
							"Failure", JOptionPane.ERROR_MESSAGE);
				}
				else
				{
					JOptionPane
					.showMessageDialog(
							null,
							"Failed to acquire TGT - encryption algorithm not supported by KDC.\n\nThis is likely to be because you do not have the JCE Unlimited Strength Jurisdiction Policy installed.\n\nSee http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#importlimits\n\nAlso note that newer versions of Burp seem to have a workaround for this.",
							"Failure", JOptionPane.ERROR_MESSAGE);
				}
				alertAndLog(1, "Error when testing credentials: " + e.getMessage());
			} else {
				credentialsStatusTextField.setText("Failed to acquire TGT: "
						+ e.getMessage());
				JOptionPane.showMessageDialog(null, "Failed to acquire TGT: "
						+ e.getMessage(), "Failure", JOptionPane.ERROR_MESSAGE);
				log(1,
						"Unexpected error when testing credentials: "
								+ e.getMessage());
				logException(2, e);
			}
		}
	}

	private void pingKDC() {
		if (domainDnsNameTextField.getText().isEmpty()) {
			JOptionPane.showMessageDialog(null, "Domain DNS name not set yet",
					"Error", JOptionPane.ERROR_MESSAGE);
			return;
		}

		if (kdcTextField.getText().isEmpty()) {
			JOptionPane.showMessageDialog(null, "KDC hostname not set yet",
					"Error", JOptionPane.ERROR_MESSAGE);
			return;
		}

		try {
			Socket client = new Socket();
			client.connect(new InetSocketAddress(kdcHost, 88), 2000);
			client.close();
		} catch (UnknownHostException e) {
			domainStatusTextField.setText("KDC hostname couldn't be resolved");
			JOptionPane.showMessageDialog(null,
					"Couldn't resolve KDC hostname:" + kdcHost, "Failure",
					JOptionPane.ERROR_MESSAGE);
			return;
		} catch (SocketTimeoutException e) {
			domainStatusTextField
					.setText("Couldn't connect to port 88 (Kerberos) on KDC - socket timed out");
			JOptionPane.showMessageDialog(null,
					"Couldn't connect to port 88 (Kerberos) on KDC:" + kdcHost
							+ ". Socket timed out - check hostname?",
					"Failure", JOptionPane.ERROR_MESSAGE);
			return;
		} catch (Exception e) {
			domainStatusTextField
					.setText("Failed to connect to port 88 on KDC");
			JOptionPane.showMessageDialog(
					null,
					"Failed to connect to port 88 on " + kdcHost + ": "
							+ e.getMessage(), "Failure",
					JOptionPane.ERROR_MESSAGE);
			log(1,
					"Unexpected error when testing connectivity to KDC: "
							+ e.getMessage());
			logException(2, e);
			return;
		}

		setKrb5Config();
		
		setupKerberosConfig();

		try {
			LoginContext loginContext = new LoginContext("KrbLogin",
					new KerberosCallBackHandler(null, null));
			loginContext.login();
		} catch (Exception e) {
			if (e.getMessage().startsWith(
					"Client not found in Kerberos database")) {
				domainStatusTextField.setText(kdcTestSuccessString);
				JOptionPane.showMessageDialog(null, kdcTestSuccessString,
						"Success", JOptionPane.INFORMATION_MESSAGE);
			} else if (e.getMessage().contains("(68)")) {
				domainStatusTextField
						.setText("Failed to contact Kerberos service - error code 68 suggests that KDC is valid but domain DNS name is wrong");
				JOptionPane
						.showMessageDialog(
								null,
								"Failed to contact Kerberos service - error code 68 suggests that KDC is valid but domain DNS name is wrong",
								"Failure", JOptionPane.ERROR_MESSAGE);
			} 
			else {
				domainStatusTextField
						.setText("Connected to port 88, but failed to contact Kerberos service: "
								+ e.getMessage());
				JOptionPane.showMessageDialog(null,
						"Connected to port 88, but failed to contact Kerberos service: "
								+ e.getMessage(), "Failure",
						JOptionPane.ERROR_MESSAGE);
				log(1,
						"Unexpected error when making test Kerberos request to KDC: "
								+ e.getMessage());
				logException(2, e);
			}
		}
	}

	/*
	 * private void domainDnsNameAuto() { 
	 * // XXX: write me : might need to be platform-specific hacks / could read %USERDNSDOMAIN% on Windows 
	 * }
	 */

	private void kdcAuto() {
		if (domainDnsName.isEmpty()) {
			JOptionPane.showMessageDialog(null,
					"Have to set the domain DNS name first", "Failure",
					JOptionPane.ERROR_MESSAGE);
			return;
		}

		List<String> results = new ArrayList<String>();
		try {
			Hashtable<String, String> envProps = new Hashtable<String, String>();
			envProps.put(Context.INITIAL_CONTEXT_FACTORY,
					"com.sun.jndi.dns.DnsContextFactory");
			DirContext dnsContext = new InitialDirContext(envProps);
			Attributes dnsEntries = dnsContext.getAttributes("_kerberos._tcp."
					+ domainDnsName.toLowerCase(), new String[] { "SRV" });
			if (dnsEntries != null) {
				Attribute attr = dnsEntries.get("SRV");

				if (attr != null) {
					for (int i = 0; i < attr.size(); i++) {
						String s = (String) attr.get(i);
						String[] parts = s.split(" ");
						String namePart = parts[parts.length - 1];
						if (namePart.endsWith(".")) {
							namePart = namePart.substring(0,
									namePart.length() - 1);
						}
						results.add(namePart);
					}
				}
			}
		} catch (Exception e) {
			if (e.getMessage().startsWith("DNS name not found")) {
				JOptionPane
						.showMessageDialog(
								null,
								"Couldn't find any suitable DNS SRV records - is (one of) your DNS server(s) in the domain?",
								"Failure", JOptionPane.ERROR_MESSAGE);
			} else {
				JOptionPane.showMessageDialog(null,
						"Failure doing DNS SRV lookup", "Failure",
						JOptionPane.ERROR_MESSAGE);
				log(1,
						"Unexpected error when doing DNS SRV lookup: "
								+ e.getMessage());
				logException(2, e);
			}
			return;
		}

		if (results.size() == 0) {
			JOptionPane.showMessageDialog(null, "No DNS entries for KDC found",
					"Failure", JOptionPane.ERROR_MESSAGE);
			return;
		}

		String selectedValue = "";

		if (results.size() == 1) {
			selectedValue = results.get(0);
		} else {
			Object[] possibilities = new Object[results.size()];
			for (int ii = 0; ii < results.size(); ii++) {
				possibilities[ii] = results.get(ii);
			}
			selectedValue = (String) JOptionPane.showInputDialog(null,
					"Multiple KDCs were found", "Select KDC",
					JOptionPane.PLAIN_MESSAGE, null, possibilities,
					results.get(0));
		}

		if (!selectedValue.isEmpty()) {
			kdcHost = selectedValue;
			kdcTextField.setText(selectedValue);
			domainStatusTextField.setText("");

			setDomainAndKdc(domainDnsName, kdcHost);
		}
	}

	private class HelpButtonActionListener implements ActionListener {

		private String message;

		public HelpButtonActionListener(String m) {
			this.message = m;
		}

		public void actionPerformed(ActionEvent e) {
			JOptionPane.showMessageDialog(null, message, "Help",
					JOptionPane.INFORMATION_MESSAGE);
		}
	}
	

}
