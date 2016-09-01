package burp;

import java.awt.Component;
import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
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
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import com.sun.security.jgss.ExtendedGSSContext;

// XXX: what about streaming responses?

public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener
{
	private enum AuthStrategy { PROACTIVE, PROACTIVE_AFTER_401, REACTIVE_401};

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	private PrintWriter stdout = null;

	private GSSManager manager;
	private LoginContext loginContext = null;
	private boolean kerberosConfigSetUp = false;
	private boolean loginFailed = false;
	//private boolean incorrectCreds = false;
	private boolean gotTGT = false;

	private final String extensionName = "Berserko";
	private final String versionString = "0.81 (alpha)";
	private final String tabName = "Berserko";

	private List<String> workingSet = null;
	private Map<String,String> hostnameToSpnMap = null;
	private List<String> failedSpns = null;
	private Map<String,List<String>> failedSpnsForHost = null;
	private List<String> hostnamesWithUnknownSpn = null;
	private ContextCache contextCache  = null;

	//config
	private String domainDnsName;
	private String kdcHost;
	private String username;
	private String password;

	private boolean masterSwitch;
	private boolean plainhostExpand;
	private boolean ignoreNTLMServers;

	private boolean savePassword;

	private int logLevel;
	private int alertLevel;

	private AuthStrategy authStrategy;
	// end config

	private Object contextLock = new Object();

	public void registerExtenderCallbacks(
			IBurpExtenderCallbacks callbacks)
	{
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		helpers = callbacks.getHelpers();

		// set our extension name
		callbacks.setExtensionName(extensionName);

		stdout = new PrintWriter( callbacks.getStdout(), true);

		callbacks.registerHttpListener(this);

		callbacks.registerExtensionStateListener(this);

		log( 1, "Berserko version " + versionString);
		
		if( savedConfigAvailable())
		{
			loadConfig();
			setDomainAndKdc(domainDnsName, kdcHost);
		}
		else
		{
			setDefaultConfig();
		}
		
		setupGUI();

		manager = GSSManager.getInstance();

		/*
		clearLoginContext();
		workingSet = Collections.synchronizedList(new ArrayList<String>());	// this should be sufficient for synchronizing access to workingSet given that we are never iterating over it
		hostnameToSpnMap = new ConcurrentHashMap<String, String>();
		failedSpns = Collections.synchronizedList(new ArrayList<String>());
		failedSpnsForHost = new ConcurrentHashMap<String, List<String>>();
		hostnamesWithUnknownSpn = Collections.synchronizedList(new ArrayList<String>());
		contextCache = new ContextCache();
		*/
	}

	public void extensionUnloaded()
	{
		saveConfig();
	}

	private void alert( int level, String message)
	{
		if( alertLevel >= level)
		{
			callbacks.issueAlert( message);
		}
	}

	private void log( int level, String message)
	{
		if( logLevel >= level)
		{
			stdout.println( message);
		}
	}

	private void logWithTimestamp( int level, String message)
	{
		if( logLevel >= level)
		{
			java.util.Date date= new java.util.Date();
			stdout.println( String.format( "%s: %s", new Timestamp(date.getTime()), message));
		}
	}

	private void alertAndLog( int level, String message)
	{
		alert( level, message);
		log( level, message);
	}

	private void logException( int level, Exception e)
	{
		if( logLevel >= level)
		{
			e.printStackTrace(stdout);
		}
	}

	private void setDefaultConfig()
	{
		masterSwitch = false;
		setDomainAndKdc( "", "");
		setCredentials( "", "");
		savePassword = false;
		alertLevel = logLevel = 1;
		plainhostExpand = true;
		ignoreNTLMServers = false;
		authStrategy = AuthStrategy.REACTIVE_401;
	}

	private void saveSetting( String a, String b)
	{
		callbacks.saveExtensionSetting( extensionName + "_" + a, b);
	}

	private String loadSetting( String a)
	{
		return callbacks.loadExtensionSetting( extensionName + "_" + a);
	}

	private void logConfig()
	{
		log( 1, "Domain DNS Name     : " + domainDnsName);
		log( 1, "KDC Host            : " + kdcHost);
		log( 1, "Username            : " + username);
		log( 1, "Password            : " + (password.isEmpty() ? "" : "****"));
		log( 1, "Save password       : " + String.valueOf(savePassword));
		log( 1, "Include plainhosts  : " + String.valueOf(plainhostExpand));
		log( 1, "Ignore NTLM servers : " + String.valueOf(ignoreNTLMServers));
		log( 1, "Alert level         : " + String.valueOf(alertLevel));
		log( 1, "Logging level       : " + String.valueOf(logLevel));
		log( 1, "Auth strategy       : " + authStrategy.toString());
	}

	private void saveConfig()
	{
		saveSetting( "saved_config_marker", "x");
		saveSetting( "domain_dns_name", domainDnsName);
		saveSetting( "kdc_host", kdcHost);
		saveSetting( "username", username);
		if( savePassword)
		{
			saveSetting( "password", password);
		}
		else
		{
			saveSetting( "password", null);
		}
		saveSetting( "plainhost_expand", String.valueOf(plainhostExpand));
		saveSetting( "ignore_ntlm_servers", String.valueOf(ignoreNTLMServers));
		saveSetting( "alert_level", String.valueOf(alertLevel));
		saveSetting( "log_level", String.valueOf(logLevel));
		saveSetting( "auth_strategy", authStrategy.toString());

		logWithTimestamp( 1, "Saving config...");
		logConfig();
	}

	private boolean savedConfigAvailable()
	{
		if( loadSetting( "saved_config_marker") == null)
		{
			return false;
		}
		else
		{
			return true;
		}    		
	}

	private void loadConfig()
	{
		// we don't restore the masterSwitch setting from the saved config - it always starts as Off
		domainDnsName = loadSetting( "domain_dns_name");
		kdcHost = loadSetting( "kdc_host");
		username = loadSetting( "username");
		if( loadSetting("password") != null)
		{
			password = loadSetting( "password");
		}
		else
		{
			password = "";
		}
		plainhostExpand = loadSetting( "plainhost_expand").equals( "true") ? true : false;
		ignoreNTLMServers = loadSetting( "ignore_ntlm_servers").equals( "true") ? true : false;
		alertLevel = Integer.parseInt(loadSetting( "alert_level"));
		logLevel = Integer.parseInt(loadSetting( "log_level"));
		authStrategy = AuthStrategy.valueOf(loadSetting( "auth_strategy"));

		logWithTimestamp( 1, "Loaded config...");
		logConfig();
	}
	
	private void addSpnToListIfNotInvalid( List<String> l, String spn, String hostname)
	{
		if( !failedSpns.contains(spn))
		{
			if( failedSpnsForHost.containsKey( hostname.toLowerCase()))
			{
				if( failedSpnsForHost.get( hostname.toLowerCase()).contains(spn))
				{
					return;
				}
			}
			l.add( spn);
		}
	}

	private List<String> hostnameToSpn( String hostname)
	{
		List<String> ret = new ArrayList<String>();
		
		if( hostnameToSpnMap.containsKey(hostname.toLowerCase()))
		{
			ret.add( hostnameToSpnMap.get(hostname.toLowerCase()));
		}
		else
		{
			if( !hostnamesWithUnknownSpn.contains( hostname.toLowerCase()))
			{
				hostnamesWithUnknownSpn.add( hostname.toLowerCase());
			}
			
			if( isPlainhostname(hostname))
			{
				addSpnToListIfNotInvalid( ret, "HTTP/" + expandHostname(hostname).toLowerCase() + "@" + getRealmName(), hostname);
				addSpnToListIfNotInvalid( ret, "http/" + expandHostname(hostname).toLowerCase() + "@" + getRealmName(), hostname);
				addSpnToListIfNotInvalid( ret, "HTTP/" + hostname.toLowerCase() + "@" + getRealmName(), hostname);
				addSpnToListIfNotInvalid( ret, "http/" + hostname.toLowerCase() + "@" + getRealmName(), hostname);
				// TODO: include port names
				// TODO: include string from host headers
			}
			else
			{
				addSpnToListIfNotInvalid( ret, "HTTP/" + hostname.toLowerCase() + "@" + getRealmName(), hostname);
				addSpnToListIfNotInvalid( ret, "http/" + hostname.toLowerCase() + "@" + getRealmName(), hostname);
				addSpnToListIfNotInvalid( ret, "HTTP/" + getPlainHostname(hostname).toLowerCase() + "@" + getRealmName(), hostname);
				addSpnToListIfNotInvalid( ret, "http/" + getPlainHostname(hostname).toLowerCase() + "@" + getRealmName(), hostname);
			}
		}
		
		return ret;
	}

	private String usernameToPrincipal( String username)
	{
		// XXX: is it correct to always make the username lowercase?
		return username.toLowerCase() + "@" + getRealmName();
	}

	private boolean hostnameIsInWorkingSet( String hostname)
	{
		return workingSet.contains(expandHostname(hostname).toLowerCase());
	}

	private void addHostnameToWorkingSet( String hostname)
	{
		if( !workingSet.contains(expandHostname(hostname).toLowerCase()))
		{
			log( 2, String.format( "Adding %s to working set",  hostname));
			workingSet.add( expandHostname(hostname).toLowerCase());
		}
	}

	private boolean hostnameIsInScope( String hostname)
	{
		if( plainhostExpand && isPlainhostname(hostname))
		{
			return true;
		}
		else
		{
			return hostname.toLowerCase().endsWith(domainDnsName.toLowerCase());
		}
	}

	private String expandHostname( String hostname)
	{
		if( isPlainhostname( hostname))
		{
			return hostname + "." + domainDnsName.toLowerCase();
		}
		else
		{
			return hostname;
		}
	}
	
	private String getPlainHostname( String hostname)
	{
		int i = hostname.indexOf(".");
		
		if( i == -1)
		{
			return hostname;
		}
		else
		{
			return hostname.substring(0, i);
		}
	}

	private boolean isPlainhostname( String hostname)
	{
		return hostname.indexOf('.') == -1;
	}

	private String buildAuthenticateHeaderFromToken( String token)
	{
		return String.format("Authorization: Negotiate %s", token);
	}

	private String getTokenFromAuthenticateNegotiateResponseHeader( String headerLine)
	{
		String pattern = "WWW-Authenticate:\\s*Negotiate\\s*(.*)";
		Pattern r = Pattern.compile(pattern);

		Matcher m = r.matcher(headerLine);
		if (m.find())
		{
			return m.group(1);
		}
		else
		{
			return "";
		}
	}
	
	private String getTokenFromAuthorizationNegotiateRequestHeader( String headerLine)
	{
		String pattern = "Authorization:\\s*Negotiate\\s*(.*)";
		Pattern r = Pattern.compile(pattern);

		Matcher m = r.matcher(headerLine);
		if (m.find())
		{
			return m.group(1);
		}
		else
		{
			return "";
		}
	}

	private boolean checkHostnameRegexp( String input)
	{
		// http://stackoverflow.com/questions/1418423/the-hostname-regex
		String pattern = "^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?$";
		Pattern r = Pattern.compile(pattern);

		Matcher m = r.matcher(input);
		
		return m.find();
	}
	
	private boolean isMultiComponentHostname( String input)
	{
		return input.contains( ".");
	}

	/*
	private String getSchemeFromAuthenticateResponseHeader( String headerLine)
	{
		String pattern = "WWW-Authenticate:\\s*(.*)\\s*.";
		Pattern r = Pattern.compile(pattern);

		// Now create matcher object.
		Matcher m = r.matcher(headerLine);
		if (m.find())
		{
			return m.group(1);
		}
		else
		{
			return "";
		}
	}  
	 */

	private String getSchemeFromAuthenticateRequestHeader( String headerLine)
	{
		String pattern = "Authorization:\\s*(\\S*)\\s*.*";
		Pattern r = Pattern.compile(pattern);

		// Now create matcher object.
		Matcher m = r.matcher(headerLine);
		if (m.find())
		{
			return m.group(1);
		}
		else
		{
			return "";
		}
	}   

	private String getRealmName()
	{
		return domainDnsName.toUpperCase();
	}

	private void clearLoginContext()
	{
		log( 2, "Clearing login context");

		synchronized( contextLock)
		{
			loginContext = null;
		}

		gotTGT = false;
		loginFailed = false;
	}

	private void setDomainAndKdc( String domain, String kdc)
	{
		domainDnsName = domain;
		kdcHost = kdc;
		
		if( domain.isEmpty())
		{
			alertAndLog( 1, "No domain DNS name set");
			
			if( kdc.isEmpty())
			{
				alertAndLog( 1, "No KDC host set");
			}
			
			return;
		}
		
		clearLoginContext();

		System.setProperty("java.security.krb5.realm", domain.toUpperCase());
		System.setProperty("java.security.krb5.kdc", kdcHost);
		workingSet = Collections.synchronizedList(new ArrayList<String>());	// this should be sufficient for synchronizing access to workingSet given that we are never iterating over it
		hostnameToSpnMap = new ConcurrentHashMap<String, String>();
		failedSpns = Collections.synchronizedList(new ArrayList<String>());
		failedSpnsForHost = new ConcurrentHashMap<String, List<String>>();
		hostnamesWithUnknownSpn = Collections.synchronizedList(new ArrayList<String>());
		contextCache = new ContextCache();

		log( 2, String.format( "New domain DNS name (%s) and KDC hostname (%s) set", domainDnsName, kdcHost));
	}

	private void setCredentials( String user, String pass)
	{
		username = user;
		password = pass;
		
		if( user.isEmpty())
		{
			alertAndLog( 1, "No username set");
			return;
		}
		
		clearLoginContext();
		//incorrectCreds = false;

		log( 2, String.format( "New username (%s) and password set", username));
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest,
			IHttpRequestResponse messageInfo) {

		if( !masterSwitch)
		{
			return;
		}

		try
		{
			if( messageIsRequest)
			{
				if( authStrategy == AuthStrategy.PROACTIVE)
				{
					IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
					List<String> headers = reqInfo.getHeaders();
					String hostname = messageInfo.getHttpService().getHost();

					if( hostnameIsInScope(hostname))
					{
						try
						{
							if( headersContainStartswith(headers, "Authorization"))
							{
								String scheme = getSchemeFromAuthenticateRequestHeader(getHeaderStartingWith(headers, "Authorization:"));
								alertAndLog( 1, String.format( "Authorization header (%s) already applied for in-scope host %s; ignoring this host. Perhaps Burp \"Platform Authentication\" is configured against this host?", scheme, hostname));
							}
							else
							{
								byte[] body = Arrays.copyOfRange( messageInfo.getRequest(), reqInfo.getBodyOffset(), messageInfo.getRequest().length);
								log( 2, "Getting token for " + hostname);
								ContextTokenSpnTriple ctst = getToken( hostnameToSpn(hostname));

								if( ctst != null)
								{
									log( 2, "Setting token in request to " + hostname);
									headers.add( buildAuthenticateHeaderFromToken(ctst.getToken()));
									messageInfo.setRequest( helpers.buildHttpMessage(headers, body));
									addHostnameToWorkingSet(hostname);
									if( hostnamesWithUnknownSpn.contains( hostname.toLowerCase()))
									{
										contextCache.AddToCache(ctst);
									}
								}
							}
						}
						catch( Exception e)
						{
							log( 1, String.format( "Exception authenticating request using proactive strategy: %s",  e.getMessage()));
							logException( 2, e);
						}
					}
				}
				else if( authStrategy == AuthStrategy.PROACTIVE_AFTER_401)
				{
					IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
					List<String> headers = reqInfo.getHeaders();
					String hostname = messageInfo.getHttpService().getHost();

					if( hostnameIsInWorkingSet(hostname))
					{
						try
						{
							if( headersContainStartswith(headers, "Authorization"))
							{
								String scheme = getSchemeFromAuthenticateRequestHeader(getHeaderStartingWith(headers, "Authorization:"));
								alertAndLog( 1, String.format( "Authorization header (%s) already applied for in-scope host %s; ignoring this host. Perhaps Burp \"Platform Authentication\" is configured against this host?", scheme, hostname));
							}
							else
							{
								log( 2, "Getting token for " + hostname);
								ContextTokenSpnTriple ctst = getToken( hostnameToSpn(hostname));

								if( ctst != null)
								{
									byte[] body = Arrays.copyOfRange( messageInfo.getRequest(), reqInfo.getBodyOffset(), messageInfo.getRequest().length);
									log( 2, "Setting token in request to " + hostname);
									headers.add( buildAuthenticateHeaderFromToken(ctst.getToken()));
									messageInfo.setRequest( helpers.buildHttpMessage(headers, body));
									if( hostnamesWithUnknownSpn.contains( hostname.toLowerCase()))
									{
										contextCache.AddToCache(ctst);
									}
								}
							}
						}
						catch( Exception e)
						{
							log( 1, String.format( "Exception authenticating request using proactive-after-401 strategy: %s",  e.getMessage()));
							logException( 2, e);
						}
					}
				}
			}
			else
			{
				byte[] responseBytes = messageInfo.getResponse();
				IResponseInfo respInfo = helpers.analyzeResponse(responseBytes);
				List<String> headers = respInfo.getHeaders();

				// ok, this is pretty dirty but we don't want to do anything with the responses to our own requests that we make below using makeHttpRequest
				// we'll heuristically identify these based on them being issued by the Extender tool, and containing a Negotiate header
				// alternatively I guess we could add our own marker request header or something
				if(toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER)
				{
					IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);

					if( headersContainStartswith( reqInfo.getHeaders(), "Authorization: Negotiate"))
					{
						return;
					}
				}

				if( is401Negotiate( respInfo, messageInfo.getHttpService().getHost()))
				{
					byte[] req = messageInfo.getRequest();
					IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
					String hostname = messageInfo.getHttpService().getHost();
					byte[] body = Arrays.copyOfRange( req, reqInfo.getBodyOffset(), req.length);
					List<String> requestHeaders = helpers.analyzeRequest( req).getHeaders();

					if( headersContainStartswith(requestHeaders, "Authorization"))	// this was a failed authentication...
					{
						if( hostnameIsInWorkingSet(hostname)) // ... a failed authentication by us
						{
							String requestToken = getTokenFromAuthorizationNegotiateRequestHeader(getHeaderStartingWith(requestHeaders, "Authorization:"));

							ContextTokenSpnTriple ctst = contextCache.GetFromCache(requestToken);

							if( ctst != null)
							{
								contextCache.RemoveFromCache(requestToken);

								String serverToken = getTokenFromAuthenticateNegotiateResponseHeader(getHeaderStartingWith(headers, "WWW-Authenticate:"));
								String err = ProcessErrorTokenResponse(ctst.getContext(), serverToken);

								if( err.isEmpty())
								{
									alertAndLog( 1, String.format( "Failed Kerberos authentication to host %s: unknown error", hostname));
								}
								else if( err.contains("AP_REP token id does not match"))
								{
									alertAndLog( 1, String.format( "Failed Kerberos authentication to host %s - possibly service ticket for wrong service being used, error message was %s", hostname, err));
									log( 2, String.format( "SPN %s incorrect for hostname %s", ctst.getSpn(), hostname));
									
									if( !failedSpnsForHost.containsKey(hostname.toLowerCase()))
									{
										failedSpnsForHost.put( hostname.toLowerCase(), new ArrayList<String>());
									}
									if( !failedSpnsForHost.get( hostname.toLowerCase()).contains( ctst.getSpn()))
									{
										failedSpnsForHost.get( hostname.toLowerCase()).add( ctst.getSpn());
									}
								}
								else
								{
									alertAndLog( 1, String.format( "Failed Kerberos authentication to host %s: error %s", hostname, err));
								}
							}
							else
							{
								alertAndLog( 1, String.format( "Failed Kerberos authentication to host %s: unknown error", hostname));
								log( 2, "Response from server: " + getHeaderStartingWith( headers, "WWW-Authenticate"));
							}

						}
						else if( hostnameIsInScope( hostname))
						{
							String scheme = getSchemeFromAuthenticateRequestHeader(getHeaderStartingWith(requestHeaders, "Authorization:"));
							alertAndLog( 1, String.format( "Authorization header (%s) already applied for in-scope host %s (and was not successful); ignoring this host. Perhaps Burp \"Platform Authentication\" is configured against this host?", scheme, hostname));
						}
					}
					else if( authStrategy == AuthStrategy.REACTIVE_401)
					{
						try
						{
							if( hostnameIsInScope(hostname) && !hostnameIsInWorkingSet(hostname))
							{
								log( 2, "Getting token for " + hostname);
								ContextTokenSpnTriple ctst = getToken( hostnameToSpn(hostname));

								if( ctst != null)
								{
									requestHeaders.add( buildAuthenticateHeaderFromToken(ctst.getToken()));
									log( 2, "Creating new authenticated request to " + hostname);
									IHttpRequestResponse resp = callbacks.makeHttpRequest( messageInfo.getHttpService(), helpers.buildHttpMessage(requestHeaders, body));

									byte[] myResponseBytes = resp.getResponse();
									IResponseInfo myRespInfo = helpers.analyzeResponse(myResponseBytes);
									List<String> myResponseHeaders = myRespInfo.getHeaders();

									if( myRespInfo.getStatusCode() == 401)
									{
										if( headersContainStartswith(myResponseHeaders, "WWW-Authenticate: Negotiate"))
										{
											String serverToken = getTokenFromAuthenticateNegotiateResponseHeader(getHeaderStartingWith(myResponseHeaders, "WWW-Authenticate:"));
											String err = ProcessErrorTokenResponse(ctst.getContext(), serverToken);

											if( err.isEmpty())
											{
												alertAndLog( 1, String.format( "Failed Kerberos authentication to host %s: unknown error", hostname));
											}
											else if( err.contains("AP_REP token id does not match"))
											{
												alertAndLog( 1, String.format( "Failed Kerberos authentication to host %s - possibly service ticket for wrong service being used, error message was %s", hostname, err));
												log( 2, String.format( "SPN %s incorrect for hostname %s", ctst.getSpn(), hostname));
												
												if( !failedSpnsForHost.containsKey(hostname.toLowerCase()))
												{
													failedSpnsForHost.put( hostname.toLowerCase(), new ArrayList<String>());
												}
												if( !failedSpnsForHost.get( hostname.toLowerCase()).contains( ctst.getSpn()))
												{
													failedSpnsForHost.get( hostname.toLowerCase()).add( ctst.getSpn());
												}
												
												// TODO: maybe try again with the next SPN?
											}
											else
											{
												alertAndLog( 1, String.format( "Failed Kerberos authentication to host %s: error %s", hostname, err));
											}
										}
										else
										{
											alertAndLog( 1, String.format( "Failed Kerberos authentication to host %s: unknown error, server did not supply WWW-Authenticate response header"));
										}
									}
									else
									{
										messageInfo.setResponse(resp.getResponse());
										if( !hostnameToSpnMap.containsKey(hostname.toLowerCase()))
										{
											log( 2, String.format( "Storing hostname->SPN mapping: %s->%s", hostname.toLowerCase(), ctst.getSpn()));
											hostnameToSpnMap.put( hostname.toLowerCase(), ctst.getSpn());
										}
									}
								}
							}
						}
						catch( Exception e)
						{
							log( 1, String.format( "Exception processing request using reactive strategy: %s",  e.getMessage()));
							logException( 2, e);
						}
					}
					else if( authStrategy == AuthStrategy.PROACTIVE_AFTER_401
							&& !hostnameIsInWorkingSet( hostname)
							&& hostnameIsInScope(hostname))
					{
						try
						{
							log( 2, "Getting token for " + hostname);
							ContextTokenSpnTriple ctst = getToken( hostnameToSpn(hostname));
	
							if( ctst != null)
							{
								requestHeaders.add( buildAuthenticateHeaderFromToken(ctst.getToken()));
	
								log( 2, "Creating new authenticated request to " + hostname);
								IHttpRequestResponse resp = callbacks.makeHttpRequest( messageInfo.getHttpService(), helpers.buildHttpMessage(requestHeaders, body));
	
								byte[] myResponseBytes = resp.getResponse();
								IResponseInfo myRespInfo = helpers.analyzeResponse(myResponseBytes);
								List<String> myResponseHeaders = myRespInfo.getHeaders();
	
								if( myRespInfo.getStatusCode() == 401)
								{
									if( headersContainStartswith(myResponseHeaders, "WWW-Authenticate: Negotiate"))
									{
										String serverToken = getTokenFromAuthenticateNegotiateResponseHeader(getHeaderStartingWith(myResponseHeaders, "WWW-Authenticate:"));
										String err = ProcessErrorTokenResponse(ctst.getContext(), serverToken);
	
										alertAndLog( 1, String.format( "Failed Kerberos authentication to host %s - possibly service ticket for wrong service being used, error message was %s", hostname, err));
										log( 2, String.format( "SPN %s incorrect for hostname %s", ctst.getSpn(), hostname));
										
										if( !failedSpnsForHost.containsKey(hostname.toLowerCase()))
										{
											failedSpnsForHost.put( hostname.toLowerCase(), new ArrayList<String>());
										}
										if( !failedSpnsForHost.get( hostname.toLowerCase()).contains( ctst.getSpn()))
										{
											failedSpnsForHost.get( hostname.toLowerCase()).add( ctst.getSpn());
										}
										
										// TODO: maybe try again with the next SPN?
									}
									else
									{
										alert( 1, String.format( "Failed Kerberos authentication to host %s: unknown error, server did not supply WWW-Authenticate response header"));
									}
								}
								else
								{
									addHostnameToWorkingSet(hostname);
									log( 2, String.format( "Storing hostname->SPN mapping: %s->%s", hostname.toLowerCase(), ctst.getSpn()));
									hostnameToSpnMap.put( hostname.toLowerCase(), ctst.getSpn());
									messageInfo.setResponse(resp.getResponse());
								}
							}
						}
						catch( Exception e)
						{
							log( 1, String.format( "Exception processing initial 401 response using proactive-after-401 strategy: %s",  e.getMessage()));
							logException( 2, e);
						}
					}
				}
				else
				{
					if( !contextCache.isEmpty())
					{
						byte[] req = messageInfo.getRequest();
						String hostname = messageInfo.getHttpService().getHost();
						List<String> requestHeaders = helpers.analyzeRequest( req).getHeaders();
				
						String requestToken = getTokenFromAuthorizationNegotiateRequestHeader(getHeaderStartingWith(requestHeaders, "Authorization:"));

						ContextTokenSpnTriple ctst = contextCache.GetFromCache(requestToken);

						if( ctst != null)
						{
							contextCache.RemoveFromCache(requestToken);
							if( hostnamesWithUnknownSpn.contains( hostname.toLowerCase()))
							{
								log( 2, String.format( "Storing hostname->SPN mapping: %s->%s", hostname.toLowerCase(), ctst.getSpn()));
								hostnamesWithUnknownSpn.remove(hostname.toLowerCase());
								hostnameToSpnMap.put( hostname.toLowerCase(), ctst.getSpn());
							}
						}
					}
				}
			}
		}
		catch( Exception e)
		{
			log( 1, String.format( "Exception in processHttpMessage: %s",  e.getMessage()));
			logException( 2, e);
		}
	}


	private boolean headersContainStartswith( List<String> headers, String target)
	{
		for( String s : headers)
		{
			if( s.startsWith(target))
			{
				return true;
			}
		}

		return false;
	}

	private String getHeaderStartingWith( List<String> headers, String target)
	{
		for( String s : headers)
		{
			if( s.startsWith(target))
			{
				return s;
			}
		}

		return "";
	}

	private boolean is401Negotiate( IResponseInfo respInfo, String hostname)
	{
		if( !(respInfo.getStatusCode() == 401))
		{
			return false;
		}

		List<String> headers = respInfo.getHeaders();

		boolean supportsNegotiate = false;
		boolean supportsNTLM = false;

		supportsNegotiate = headersContainStartswith(headers,  "WWW-Authenticate: Negotiate");
		supportsNTLM = headersContainStartswith(headers,  "WWW-Authenticate: NTLM");

		if( ignoreNTLMServers)
		{
			alertAndLog( 1, String.format( "Not authenticating to server %s as it supports NTLM", hostname));
			return supportsNegotiate && !supportsNTLM;
		}
		else
		{
			return supportsNegotiate;
		}
	}

	// // http://stackoverflow.com/questions/24074507/how-to-generate-the-kerberos-security-token
	@SuppressWarnings("rawtypes")
	private class GetTokenAction implements PrivilegedExceptionAction
	{
		private List<String> spns;

		public GetTokenAction( List<String> s)
		{
			spns = s;
		}

		@Override
		public Object run() throws TGTExpiredException {

			String encodedToken = "";
			GSSContext context = null;

			for( String spn : spns)
			{
				log( 2, "Trying SPN: " + spn);
				
				try {
					Oid spnegoMechOid  = new Oid("1.3.6.1.5.5.2"); 

					GSSName gssServerName = manager.createName( spn, null);

					GSSCredential userCreds = manager.createCredential(null,
							GSSCredential.INDEFINITE_LIFETIME,
							spnegoMechOid,
							GSSCredential.INITIATE_ONLY);

					context = manager.createContext(gssServerName, spnegoMechOid, userCreds, GSSCredential.INDEFINITE_LIFETIME);
					ExtendedGSSContext extendedContext = null;
					if( context instanceof ExtendedGSSContext)
                	{
                		extendedContext = (ExtendedGSSContext) context;
                		extendedContext.requestDelegPolicy(true);
                	}
					byte spnegoToken[] = new byte[0];
					spnegoToken = context.initSecContext(spnegoToken, 0, spnegoToken.length);
					encodedToken =  Base64.getEncoder().encodeToString( spnegoToken);
					
					//if( extendedContext != null)
					//{
					//	log( 2, String.format( "getDelegPolicyState = %s for %s", extendedContext.getDelegPolicyState(), spn));
					//	log( 2, String.format( "getCredDelegState = %s for %s", extendedContext.getCredDelegState(), spn));
					//}

					return new ContextTokenSpnTriple(context, spn, encodedToken);
				} 
				catch (Exception e) {
					if( e.getMessage().contains("Server not found in Kerberos database"))
					{
						alertAndLog( 1, String.format( "Failed to acquire service ticket for %s - service name not recognised by KDC", spn));
						if( !failedSpns.contains(spn))
						{
							failedSpns.add( spn);
						}
						continue;
					}
					else if( e.getMessage().contains("Failed to find any Kerberos tgt") || e.getMessage().contains("Ticket expired"))
					{
						alertAndLog( 1, String.format( "Failed to acquire token for service %s, TGT has expired? Trying to get a new one...", spn));
						throw new TGTExpiredException("TGT Expired");
					}
					else
					{
						alertAndLog( 1, String.format( "Failed to acquire token for service %s, error message was %s", spn, e.getMessage()));
						logException(2, e);
					}
					
					return null;
				}
			}
			
			return null;
		}
	}

	private String ProcessErrorTokenResponse( GSSContext context, String returnedToken)
	{
		byte[] tokenBytes = null;

		try
		{
			tokenBytes = Base64.getDecoder().decode(returnedToken);
		}
		catch( Exception e)
		{
			return "Failed to base64-decode Negotiate token from server";
		}

		try
		{
			tokenBytes = context.initSecContext(tokenBytes, 0, tokenBytes.length);
		}
		catch( Exception e)
		{
			// this is an "expected" exception - we're deliberately feeding in an error token from the server to collect the corresponding exception
			return e.getMessage();
		}

		return "";
	}

	@SuppressWarnings("unchecked")
	private ContextTokenSpnTriple getToken( List<String> spns)
	{
		ContextTokenSpnTriple ctst = null;

		if( !gotTGT)
		{
			setupLoginContext();
		}

		if( gotTGT)
		{
			synchronized( contextLock)
			{
				try
				{
					GetTokenAction tokenAction = new GetTokenAction( spns);
					ctst = (ContextTokenSpnTriple) Subject.doAs(loginContext.getSubject(), tokenAction);
				}
				catch( PrivilegedActionException e)
				{
					if( e.getException().getClass().getName().contains( "TGTExpiredException"))
					{
						clearLoginContext();
						setupLoginContext();
						
						if( !gotTGT)
						{
							return null;
						}
						
						try
						{
							GetTokenAction tokenAction = new GetTokenAction( spns);
							ctst = (ContextTokenSpnTriple) Subject.doAs(loginContext.getSubject(), tokenAction);
						}
						catch( PrivilegedActionException ee)
						{
							alertAndLog( 1, "Exception thrown when trying to get token with new TGT: " + ee.getMessage());
							logException(2, ee);
							return null;
						}
					}
					else
					{
						alertAndLog( 1, "Exception thrown in getToken: " + e.getMessage());
						logException(2, e);
						return null;
					}
				}
			}
		}
		else
		{
			return null;
		}

		return ctst;
	}

	private void setupKerberosConfig()
	{
		if( kerberosConfigSetUp)
		{
			return;
		}

		Configuration.setConfiguration(null);

		System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");	// necessary to stop it requesting a new service ticket for each request

		try
		{
			Configuration config = new Configuration() {
				@Override
				public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
	
					Map<String,Object> map = new HashMap<String, Object>();
					map.put( "doNotPrompt", "false");
					map.put( "useTicketCache", "false");
					map.put( "refreshKrb5Config", "true");
	
					return new AppConfigurationEntry[]{
							new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
									AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
									map)
					};
				}
	
				@Override
				public void refresh() {
					// ignored
				}
			};
			
			Configuration.setConfiguration(config);
			
			kerberosConfigSetUp = true;
		}
		catch( Exception e)
		{
			alertAndLog( 1, "Error setting up Kerberos configuration: " + e.getMessage());
			logException(2, e);
		}
	}
	
	private boolean checkTgtForwardableFlag( Subject sub)
	{
		for( Object ob : sub.getPrivateCredentials())
        {
        	if( ob instanceof KerberosTicket)
        	{
        		KerberosTicket kt = (KerberosTicket) ob;
        		boolean[] flags = kt.getFlags();
        		return flags[1];
        	}
        }
		
		return false;
	}

	private void setupLoginContext()
	{
		if( loginFailed)
		{
			return;	// don't keep trying to get a TGT after a failure, until we are provided with new domain details or creds or whatever
		}
		
		if( domainDnsName.isEmpty())
		{
			alertAndLog(1, "Domain DNS name is blank - not trying to acquire TGT");
			loginFailed = true;
			return;
		}
		
		if( kdcHost.isEmpty())
		{
			alertAndLog(1, "KDC hostname is blank - not trying to acquire TGT");
			loginFailed = true;
			return;
		}
		
		if( username.isEmpty())
		{
			alertAndLog(1, "User is blank - not trying to acquire TGT");
			loginFailed = true;
			return;
		}
		
		setupKerberosConfig();

		synchronized( contextLock)
		{
			try
			{
				log( 2, String.format( "Attempting to acquire TGT for realm %s at KDC %s with user %s", getRealmName(), kdcHost, username));
				loginContext = new LoginContext("KrbLogin", new KerberosCallBackHandler(username, password));
				loginContext.login();
				log( 2, "TGT successfully acquired");
				gotTGT = true;
				
				boolean forwardable = checkTgtForwardableFlag(loginContext.getSubject());
				
				if( forwardable)
				{
        			log( 1, "TGT is forwardable - delegation should work OK");
        		}
        		else
        		{
        			log( 1, "TGT is not forwardable so delegation will not work.");
        		}
			}
			catch( Exception e)
			{
				if( (e.getCause() != null)
						&& (e.getCause().getClass().getName()  == "java.net.UnknownHostException"))
				{
					alertAndLog( 1, String.format( "Failed to acquire TGT on domain %s with user %s - couldn't find DC %s. Not making further attempts until domain settings are changed.", domainDnsName, username, kdcHost));
				}
				else if( e.getMessage().startsWith( "Client not found in Kerberos database"))
				{
					alertAndLog( 1, String.format( "Failed to acquire TGT on domain %s with user %s - username appears to be invalid. Not making further attempts, to avoid account lockout. Try setting new credentials (and checking the domain details)", domainDnsName, username));
					//incorrectCreds = true;
				}
				else if( e.getMessage().startsWith( "Pre-authentication information was invalid"))
				{
					if( password.isEmpty())
					{
						alertAndLog( 1, String.format( "Failed to acquire TGT on domain %s with user %s - password appears to be invalid (it is blank). Not making further attempts, to avoid account lockout. Try setting new credentials (and checking the domain details)", domainDnsName, username));
						//incorrectCreds = true;
					}
					else
					{
						alertAndLog( 1, String.format( "Failed to acquire TGT on domain %s with user %s - password appears to be invalid. Not making further attempts, to avoid account lockout. Try setting new credentials (and checking the domain details)", domainDnsName, username));
						//incorrectCreds = true;
					}
				}
				else
				{
					alertAndLog( 1, String.format( "Failed to acquire TGT on domain %s with user %s. Not making further attempts until domain settings are changed. Error was: %s", domainDnsName, username, e.getMessage()));
					logException( 2, e);
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

		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

			for (Callback callback : callbacks) {

				if (callback instanceof NameCallback) {
					NameCallback nc = (NameCallback) callback;
					if( user == null)
					{
						nc.setName(usernameToPrincipal("berserkotest"));
					}
					else
					{
						nc.setName(usernameToPrincipal(user));
					}
				} else if (callback instanceof PasswordCallback) {
					PasswordCallback pc = (PasswordCallback) callback;
					if( user == null)
					{
						pc.setPassword( "berserkotest".toCharArray());
					}
					else
					{
						pc.setPassword(password.toCharArray());
					}
				} else {
					throw new UnsupportedCallbackException(callback, "Unknown Callback");
				}

			}
		}
	}

	private class ContextTokenSpnTriple
	{
		private GSSContext context;
		private String token;
		private String spn;

		public ContextTokenSpnTriple( GSSContext c, String s, String t)
		{
			context = c;
			token = t;
			spn = s;
		}

		public GSSContext getContext()
		{
			return context;
		}

		public String getToken()
		{
			return token;
		}
		
		public String getSpn()
		{
			return spn;
		}
	}
	
	@SuppressWarnings("serial")
	public class TGTExpiredException extends Exception {
	    public TGTExpiredException(String message) {
	        super(message);
	    }
	}
	
	public class ContextCache
	{
		private Map<String,ContextTokenSpnTriple> contextMap;
		private final int maxCache = 1000;
		private int currentlyCached = 0;
		
		public ContextCache()
		{
			currentlyCached = 0;
			contextMap = new ConcurrentHashMap<String, BurpExtender.ContextTokenSpnTriple>();
		}
		
		public boolean isEmpty()
		{
			return currentlyCached == 0;
		}
		
		public void AddToCache( ContextTokenSpnTriple ctst)
		{
			if( currentlyCached < maxCache)
			{
				//log( 2, String.format( "ContextCache putting %s %s, contains %d", ctst.getToken(), ctst.getSpn(), currentlyCached+1));
				contextMap.put( ctst.getToken(), ctst);
				currentlyCached += 1;
			}
		}
		
		public void RemoveFromCache( String token)
		{
			// save a lookup in the synchronised hashmap
			if( currentlyCached == 0)
			{
				return;
			}
			
			if( contextMap.containsKey(token))
			{
				//log( 2, String.format( "ContextCache removing %s, contains %d", token, currentlyCached-1));
				contextMap.remove( token);
				currentlyCached -= 1;
			}
		}
		
		public ContextTokenSpnTriple GetFromCache( String token)
		{
			// save a lookup in the synchronised hashmap
			if( currentlyCached == 0)
			{
				return null;
			}
			
			if( contextMap.containsKey(token))
			{
				return contextMap.get( token);
			}
			else
			{
				return null;
			}
		}
	}

	// ================== GUI code starts here ========================================

	JPanel mainPanel;
	JCheckBox masterSwitchCheckBox;
	JLabel versionLabel;
	JButton restoreDefaultsButton;
	JPanel domainPanel;
	JPanel credsPanel;
	JPanel authenticationStrategyPanel;
	JPanel optionsPanel;
	JPanel loggingPanel;
	JPanel dummyPanel;
	JLabel domainDnsLabel;
	JLabel kdcLabel;
	JTextField domainDnsNameTextField;
	JTextField kdcTextField;
	JButton changeDomainSettingsButton;
	JButton pingKDCButton;
	JButton domainDnsNameHelpButton;
	JButton kdcHelpButton;
	//JButton domainDnsNameAutoButton;
	JButton kdcAutoButton;
	JTextField domainStatusTextField;
	JLabel usernameLabel;
	JLabel passwordLabel;
	JTextField usernameTextField;
	JPasswordField passwordField;
	JButton usernameHelpButton;
	JButton changeCredentialsButton;
	JButton testCredentialsButton;
	JCheckBox savePasswordCheckBox;
	JTextField credentialsStatusTextField;
	JLabel alertLevelLabel;
	JLabel loggingLevelLabel;
	JComboBox<String> alertLevelComboBox;
	JComboBox<String> loggingLevelComboBox;
	JButton alertLevelHelpButton;
	JButton loggingLevelHelpButton;

	JRadioButton proactiveButton;
	JRadioButton proactiveAfter401Button;
	JRadioButton reactiveButton;
	ButtonGroup authStrategyGroup;
	JCheckBox ignoreNTLMServersCheckBox;
	JCheckBox includePlainhostnamesCheckBox;
	JButton authStrategyHelpButton;
	JButton ignoreNTLMServersHelpButton;
	JButton includePlainhostnamesHelpButton;

	private final String domainDnsNameHelpString = "DNS name of the domain to authenticate against - not the NETBIOS name.";
	private final String kdcHelpString = "Hostname of a KDC (domain controller) for this domain.\n\n\"Auto\" button will do a DNS SRV lookup to try to find a KDC for the given domain.";
	private final String usernameHelpString = "Username for a domain account. Just the plain username, not DOMAIN\\username or username@DOMAIN.COM or anything like that.";
	private final String kdcTestSuccessString = "Successfully contacted Kerberos service";
	private final String credentialsTestSuccessString = "TGT successfully acquired";
	private final String forwardableTgtString = "TGT is forwardable so delegation should work";
	private final String notForwardableTgtString = "TGT is not forwardable so delegation will not work";
	private final String alertLevelHelpString = "Controls level of logging performed to Burp's Alerts tab";
	private final String loggingLevelHelpString = "Controls level of logging performed to extension's standard output";
	private final String authStrategyHelpString = "There are three possible approaches here:\n\nReactive: when a 401 response is received from the server, add an appropriate Kerberos authentication header and resend the request. This is what Fiddler does.\nProactive: for hosts which are in scope for Kerberos authentication, add the Kerberos authentication header to outgoing requests (i.e. don't wait to get a 401).\nProactive after 401: use the reactive strategy for the first Kerberos authentication against a particular host, then if it was successful, move to proactive.\n\nThe Reactive approach is perhaps the most \"correct\", but is slower (requires an extra HTTP round trip to the server).\nThe Proactive approach is faster.\nThe Proactive after 401 approach is maybe a good compromise.";
	private final String ignoreNTLMServersHelpString = "If this is selected, Kerberos authentication will not be performed against hosts which also support NTLM (as evidenced by a WWW-Authenticate: NTLM response header).\n\nThe purpose of selecting this would be to, for example, use Burp's existing NTLM authentication capability for these hosts.";
	private final String includePlainhostnamesHelpString = "If this is selected, Kerberos authentication will be attempted against hosts which are specified by \"plain hostnames\", i.e. hostnames that are not qualified with the domain.\n\nThe only reason you might want this would be if your machine was joined to a different domain from the one being authenticated against using this extension.";

	@Override
	public Component getUiComponent() {
		return mainPanel;
	}

	@Override
	public String getTabCaption() {
		return tabName;
	}

	private void setupGUI()
	{
		SwingUtilities.invokeLater(new Runnable(){
			@Override
			public void run(){
				//Create our initial UI components
				mainPanel = new JPanel();
				mainPanel.setLayout( new GridBagLayout());

				GridBagConstraints gbc = new GridBagConstraints();
				gbc.fill = GridBagConstraints.HORIZONTAL;

				masterSwitchCheckBox = new JCheckBox( "Do Kerberos authentication");
				versionLabel = new JLabel( extensionName + " version " + versionString);
				restoreDefaultsButton = new JButton( "Restore defaults");

				domainPanel = new JPanel(new GridBagLayout());
				domainPanel.setBorder(BorderFactory.createTitledBorder( "Domain Settings"));

				domainDnsLabel = new JLabel( "Domain DNS Name");
				kdcLabel = new JLabel( "KDC Host");
				domainDnsNameTextField = new JTextField();
				kdcTextField = new JTextField();
				domainStatusTextField = new JTextField();
				domainDnsNameTextField.setEditable(false);
				kdcTextField.setEditable(false);
				domainStatusTextField.setEditable(false);
				changeDomainSettingsButton = new JButton( "Change...");
				pingKDCButton = new JButton( "Test domain settings");
				domainDnsNameHelpButton = new JButton("?");
				kdcHelpButton = new JButton("?");
				//domainDnsNameAutoButton = new JButton( "Auto");
				kdcAutoButton = new JButton("Auto");

				usernameLabel = new JLabel( "Username               ");
				passwordLabel = new JLabel( "Password               ");
				usernameTextField = new JTextField();
				usernameTextField.setEditable(false);
				passwordField = new JPasswordField();
				passwordField.setEditable(false);
				usernameHelpButton = new JButton("?");
				changeCredentialsButton = new JButton( "Change...");
				testCredentialsButton = new JButton( "Test credentials");
				savePasswordCheckBox = new JCheckBox( "Save password in Burp config?");
				credentialsStatusTextField = new JTextField();
				credentialsStatusTextField.setEditable(false);

				alertLevelLabel = new JLabel( "Alert Level            ");
				loggingLevelLabel = new JLabel( "Logging Level        ");
				String[] levelStrings = { "None", "Normal", "Verbose"};
				alertLevelComboBox = new JComboBox<String>( levelStrings);
				loggingLevelComboBox = new JComboBox<String>( levelStrings);
				alertLevelHelpButton = new JButton( "?");
				loggingLevelHelpButton = new JButton( "?");


				proactiveButton = new JRadioButton( "Proactive Kerberos authentication");
				proactiveAfter401Button = new JRadioButton( "Proactive Kerberos authentication, only after initial 401 received");
				reactiveButton = new JRadioButton( "Reactive Kerberos authentication");
				authStrategyGroup = new ButtonGroup();
				authStrategyGroup.add( proactiveButton);
				authStrategyGroup.add( proactiveAfter401Button);
				authStrategyGroup.add( reactiveButton);
				ignoreNTLMServersCheckBox = new JCheckBox( "Do not perform Kerberos authentication to servers which support NTLM");
				includePlainhostnamesCheckBox = new JCheckBox( "Plain hostnames (i.e. unqualified names) considered part of domain");
				authStrategyHelpButton = new JButton("?");
				ignoreNTLMServersHelpButton = new JButton("?");
				includePlainhostnamesHelpButton = new JButton("?");

				credsPanel = new JPanel(new GridBagLayout());
				credsPanel.setBorder(BorderFactory.createTitledBorder( "Domain Credentials"));

				authenticationStrategyPanel = new JPanel(new GridBagLayout());
				authenticationStrategyPanel.setBorder(BorderFactory.createTitledBorder( "Authentication Strategy"));

				optionsPanel = new JPanel(new GridBagLayout());
				optionsPanel.setBorder(BorderFactory.createTitledBorder( "Options"));

				loggingPanel = new JPanel(new GridBagLayout());
				loggingPanel.setBorder(BorderFactory.createTitledBorder( "Logging"));

				dummyPanel = new JPanel();

				callbacks.customizeUiComponent(mainPanel);
				callbacks.customizeUiComponent(masterSwitchCheckBox);
				callbacks.customizeUiComponent(versionLabel);
				callbacks.customizeUiComponent(restoreDefaultsButton);
				callbacks.customizeUiComponent(domainPanel);
				callbacks.customizeUiComponent(credsPanel);
				callbacks.customizeUiComponent(authenticationStrategyPanel);
				callbacks.customizeUiComponent(optionsPanel);
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
				//callbacks.customizeUiComponent(domainDnsNameAutoButton);
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
				callbacks.customizeUiComponent(ignoreNTLMServersCheckBox);
				callbacks.customizeUiComponent(includePlainhostnamesCheckBox);
				callbacks.customizeUiComponent(authStrategyHelpButton);
				callbacks.customizeUiComponent(ignoreNTLMServersHelpButton);
				callbacks.customizeUiComponent(includePlainhostnamesHelpButton);

				// DOMAIN SETTINGS PANEL LAYOUT
				gbc.insets = new Insets( 5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				domainPanel.add( domainDnsLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 1;
				domainPanel.add( kdcLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				gbc.gridwidth = 3;
				domainPanel.add( domainDnsNameTextField, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 1;
				gbc.gridwidth = 3;
				domainPanel.add( kdcTextField, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 3;
				gbc.gridwidth = 3;
				domainPanel.add( domainStatusTextField, gbc);
				gbc.gridwidth = 1;
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 2;
				domainPanel.add( changeDomainSettingsButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 2;
				gbc.gridy = 2;
				domainPanel.add( pingKDCButton, gbc);
				/*
                gbc.fill = GridBagConstraints.NONE;
                gbc.weightx = 0.0;
                gbc.weighty = 0.0;
                gbc.gridx = 4;
                gbc.gridy = 0;
                domainPanel.add( domainDnsNameAutoButton, gbc);
				 */
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 4;
				gbc.gridy = 1;
				domainPanel.add( kdcAutoButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 5;
				gbc.gridy = 0;
				domainPanel.add( domainDnsNameHelpButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 5;
				gbc.gridy = 1;
				domainPanel.add( kdcHelpButton, gbc);

				// CREDENTIALS PANEL LAYOUT
				gbc.insets = new Insets( 5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				credsPanel.add( usernameLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 1;
				credsPanel.add( passwordLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				gbc.gridwidth = 3;
				credsPanel.add( usernameTextField, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 1;
				gbc.gridwidth = 3;
				credsPanel.add( passwordField, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 3;
				gbc.gridwidth = 3;
				credsPanel.add( credentialsStatusTextField, gbc);
				gbc.gridwidth = 1;
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 2;
				credsPanel.add( changeCredentialsButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 2;
				gbc.gridy = 2;
				credsPanel.add( testCredentialsButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 4;
				gbc.gridy = 0;
				credsPanel.add( usernameHelpButton, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 4;
				gbc.gridwidth = 3;
				credsPanel.add( savePasswordCheckBox, gbc);
				gbc.gridwidth = 1;

				// LOGGING PANEL LAYOUT
				gbc.insets = new Insets( 5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				loggingPanel.add( alertLevelLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 1;
				loggingPanel.add( loggingLevelLabel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				gbc.gridwidth = 3;
				loggingPanel.add( alertLevelComboBox, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 1;
				gbc.gridwidth = 3;
				loggingPanel.add( loggingLevelComboBox, gbc);
				gbc.gridwidth = 1;
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 4;
				gbc.gridy = 0;
				loggingPanel.add( alertLevelHelpButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 4;
				gbc.gridy = 1;
				loggingPanel.add( loggingLevelHelpButton, gbc);

				// AUTH STRATEGY PANEL LAYOUT
				gbc.insets = new Insets( 5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				authenticationStrategyPanel.add( reactiveButton, gbc);
				gbc.insets = new Insets( 5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 1;
				authenticationStrategyPanel.add( proactiveButton, gbc);
				gbc.insets = new Insets( 5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 2;
				authenticationStrategyPanel.add( proactiveAfter401Button, gbc);
				gbc.insets = new Insets( 5, 5, 5, 5);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				authenticationStrategyPanel.add( authStrategyHelpButton, gbc);

				// OPTIONS PANEL LAYOUT
				gbc.insets = new Insets( 5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				optionsPanel.add( ignoreNTLMServersCheckBox, gbc);
				gbc.insets = new Insets( 5, 5, 5, 5);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 1;
				optionsPanel.add( includePlainhostnamesCheckBox, gbc);
				gbc.insets = new Insets( 5, 5, 5, 5);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 0;
				optionsPanel.add( ignoreNTLMServersHelpButton, gbc);
				gbc.insets = new Insets( 5, 5, 5, 5);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 1;
				gbc.gridy = 1;
				optionsPanel.add( includePlainhostnamesHelpButton, gbc);

				// MAIN PANEL LAYOUT

				gbc.gridwidth = 4;
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.0;
				gbc.gridx = 0;
				gbc.gridy = 0;
				gbc.gridwidth = 1;
				mainPanel.add( masterSwitchCheckBox, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 3;
				gbc.gridy = 0;
				mainPanel.add( restoreDefaultsButton, gbc);
				gbc.fill = GridBagConstraints.NONE;
				gbc.weightx = 0.0;
				gbc.weighty = 0.0;
				gbc.gridx = 4;
				gbc.gridy = 0;
				mainPanel.add( versionLabel, gbc);
				gbc.gridwidth = 5;
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.1;
				gbc.gridx = 0;
				gbc.gridy = 1;
				mainPanel.add( domainPanel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.1;
				gbc.gridx = 0;
				gbc.gridy = 2;
				mainPanel.add( credsPanel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.1;
				gbc.gridx = 0;
				gbc.gridy = 3;
				mainPanel.add( authenticationStrategyPanel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.1;
				gbc.gridx = 0;
				gbc.gridy = 4;
				mainPanel.add( optionsPanel, gbc);
				gbc.fill = GridBagConstraints.HORIZONTAL;
				gbc.weightx = 1.0;
				gbc.weighty = 0.1;
				gbc.gridx = 0;
				gbc.gridy = 5;
				mainPanel.add( loggingPanel, gbc);
				gbc.fill = GridBagConstraints.BOTH;
				gbc.weightx = 1.0;
				gbc.weighty = 3.0;
				gbc.gridx = 0;
				gbc.gridy = 6;
				mainPanel.add( dummyPanel, gbc);

				// ACTION LISTENERS
				masterSwitchCheckBox.addActionListener( new ActionListener() {
					public void actionPerformed(ActionEvent actionEvent) {
						JCheckBox cb = (JCheckBox) actionEvent.getSource();
						masterSwitchEnabled( cb.isSelected());
					}
				});

				savePasswordCheckBox.addActionListener( new ActionListener() {
					public void actionPerformed(ActionEvent actionEvent) {
						JCheckBox cb = (JCheckBox) actionEvent.getSource();
						savePassword = cb.isSelected();
					}
				});

				changeDomainSettingsButton.addActionListener(new ActionListener() { 
					public void actionPerformed(ActionEvent e) { 
						changeDomainSettings();
					} 
				} );

				pingKDCButton.addActionListener(new ActionListener() { 
					public void actionPerformed(ActionEvent e) { 
						pingKDC();
					} 
				} );

				//domainDnsNameAutoButton.addActionListener(new ActionListener() { 
				//  public void actionPerformed(ActionEvent e) { 
				//	    domainDnsNameAuto();
				//	  } 
				//	} );

				kdcAutoButton.addActionListener(new ActionListener() { 
					public void actionPerformed(ActionEvent e) { 
						kdcAuto();
					} 
				} );

				changeCredentialsButton.addActionListener(new ActionListener() { 
					public void actionPerformed(ActionEvent e) { 
						changeCredentials();
					} 
				} );

				testCredentialsButton.addActionListener(new ActionListener() { 
					public void actionPerformed(ActionEvent e) { 
						testCredentials();
					} 
				} );

				alertLevelComboBox.addActionListener(new ActionListener() { 
					public void actionPerformed(ActionEvent e) { 
						@SuppressWarnings("unchecked")
						JComboBox<String> cb = (JComboBox<String>)e.getSource();
						alertLevel = cb.getSelectedIndex();
					} 
				} );

				loggingLevelComboBox.addActionListener(new ActionListener() { 
					public void actionPerformed(ActionEvent e) { 
						@SuppressWarnings("unchecked")
						JComboBox<String> cb = (JComboBox<String>)e.getSource();
						logLevel = cb.getSelectedIndex();
					} 
				} );

				includePlainhostnamesCheckBox.addActionListener( new ActionListener() {
					public void actionPerformed(ActionEvent actionEvent) {
						JCheckBox cb = (JCheckBox) actionEvent.getSource();
						plainhostExpand = cb.isSelected();
					}
				});

				ignoreNTLMServersCheckBox.addActionListener( new ActionListener() {
					public void actionPerformed(ActionEvent actionEvent) {
						JCheckBox cb = (JCheckBox) actionEvent.getSource();
						ignoreNTLMServers = cb.isSelected();
					}
				});

				proactiveAfter401Button.addActionListener(new ActionListener() { 
					public void actionPerformed(ActionEvent e) { 
						authStrategy = AuthStrategy.PROACTIVE_AFTER_401;
					} 
				} );

				proactiveButton.addActionListener(new ActionListener() { 
					public void actionPerformed(ActionEvent e) { 
						authStrategy = AuthStrategy.PROACTIVE;
					} 
				} );

				reactiveButton.addActionListener(new ActionListener() { 
					public void actionPerformed(ActionEvent e) { 
						authStrategy = AuthStrategy.REACTIVE_401;
					} 
				} );

				restoreDefaultsButton.addActionListener(new ActionListener() { 
					public void actionPerformed(ActionEvent e) { 
						setDefaultConfig();
						initialiseGUIFromConfig();
					} 
				} );

				domainDnsNameHelpButton.addActionListener( new HelpButtonActionListener( domainDnsNameHelpString));
				kdcHelpButton.addActionListener( new HelpButtonActionListener( kdcHelpString));
				usernameHelpButton.addActionListener( new HelpButtonActionListener( usernameHelpString));
				alertLevelHelpButton.addActionListener( new HelpButtonActionListener( alertLevelHelpString));
				loggingLevelHelpButton.addActionListener( new HelpButtonActionListener( loggingLevelHelpString));
				authStrategyHelpButton.addActionListener( new HelpButtonActionListener( authStrategyHelpString));
				includePlainhostnamesHelpButton.addActionListener( new HelpButtonActionListener( includePlainhostnamesHelpString));
				ignoreNTLMServersHelpButton.addActionListener( new HelpButtonActionListener( ignoreNTLMServersHelpString));

				initialiseGUIFromConfig();

				//Add our tab to the suite
				callbacks.addSuiteTab(BurpExtender.this);
			}
		});
	}

	private void initialiseGUIFromConfig()
	{
		masterSwitchCheckBox.setSelected( masterSwitch);
		masterSwitchEnabled( masterSwitch);
		domainDnsNameTextField.setText( domainDnsName);
		kdcTextField.setText( kdcHost);
		domainStatusTextField.setText("");
		credentialsStatusTextField.setText("");
		usernameTextField.setText( username);
		passwordField.setText( password);
		savePasswordCheckBox.setSelected(savePassword);
		alertLevelComboBox.setSelectedIndex(alertLevel);
		loggingLevelComboBox.setSelectedIndex(logLevel);
		includePlainhostnamesCheckBox.setSelected( plainhostExpand);
		ignoreNTLMServersCheckBox.setSelected( ignoreNTLMServers);
		switch( authStrategy)
		{
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
	}

	// http://stackoverflow.com/questions/10985734/java-swing-enabling-disabling-all-components-in-jpanel
	private void enableComponents(Container container, boolean enable) {
		Component[] components = container.getComponents();
		for (Component component : components) {
			component.setEnabled(enable);
			if (component instanceof Container) {
				enableComponents((Container)component, enable);
			}
		}
	}

	private void masterSwitchEnabled( boolean enabled)
	{
		alertAndLog( 1, enabled ? "Kerberos authentication enabled" : "Kerberos authentication disabled");

		masterSwitch = enabled;
		domainPanel.setEnabled(enabled);
		enableComponents( domainPanel, enabled);
		credsPanel.setEnabled(enabled);
		enableComponents( credsPanel, enabled);
		authenticationStrategyPanel.setEnabled(enabled);
		enableComponents( authenticationStrategyPanel, enabled);
		optionsPanel.setEnabled(enabled);
		enableComponents( optionsPanel, enabled);
		loggingPanel.setEnabled(enabled);
		enableComponents( loggingPanel, enabled);
		
		if( enabled)
		{
			if( domainDnsName.isEmpty() || kdcHost.isEmpty() || username.isEmpty())
			{
				JOptionPane.showMessageDialog( null, "Domain DNS Name, KDC Host, Username and (probably) Password must all be set, and ideally tested, before Kerberos authentication will work", "Warning", JOptionPane.WARNING_MESSAGE);
			}
			else if( password.isEmpty())
			{
				JOptionPane.showMessageDialog( null, "Password is not set - probably because it wasn't saved in the extension settings.\n\nYou need to set it (unless the account has a blank password of course).", "Warning", JOptionPane.WARNING_MESSAGE);
			}
		}
	}

	private void changeDomainSettings()
	{
		JTextField newDomainDnsNameTextField = new JTextField();
		newDomainDnsNameTextField.setText(domainDnsName);
		JTextField newKdcTextField = new JTextField();
		newKdcTextField.setText( kdcHost);
		final JComponent[] inputs = new JComponent[] {
				new JLabel("Domain DNS Name"),
				newDomainDnsNameTextField,
				new JLabel("KDC Host"),
				newKdcTextField,
		};
		JOptionPane.showMessageDialog(null, inputs, "Change domain settings", JOptionPane.PLAIN_MESSAGE);

		if( newDomainDnsNameTextField.getText().endsWith("."))
		{
			JOptionPane.showMessageDialog( null, "Removing dot from end of DNS domain name", "Info", JOptionPane.INFORMATION_MESSAGE);
			newDomainDnsNameTextField.setText(newDomainDnsNameTextField.getText().substring(0, newDomainDnsNameTextField.getText().length() - 1));
		}
		if( newKdcTextField.getText().endsWith("."))
		{
			JOptionPane.showMessageDialog( null, "Removing dot from end of KDC hostname", "Info", JOptionPane.INFORMATION_MESSAGE);
			newKdcTextField.setText(newKdcTextField.getText().substring(0, newKdcTextField.getText().length() - 1));
		}

		if( !checkHostnameRegexp(newDomainDnsNameTextField.getText()))
		{
			JOptionPane.showMessageDialog( null, "DNS domain name does not match hostname regexp - please check", "Warning", JOptionPane.WARNING_MESSAGE);
		}
		else if( !isMultiComponentHostname(newDomainDnsNameTextField.getText()))
		{
			JOptionPane.showMessageDialog( null, "This seems to be a single-component DNS name - this isn't valid for Windows domains but might be valid for other Kerberos realms", "Warning", JOptionPane.WARNING_MESSAGE);
		}

		if( !checkHostnameRegexp(newKdcTextField.getText()))
		{
			JOptionPane.showMessageDialog( null, "KDC hostname does not match hostname regexp - please check", "Warning", JOptionPane.WARNING_MESSAGE);
		}

		if( (newDomainDnsNameTextField.getText() != domainDnsName)
				|| (newKdcTextField.getText() != kdcHost))		// don't do anything if values are unchanged
		{
			domainDnsName = newDomainDnsNameTextField.getText();
			domainDnsNameTextField.setText( newDomainDnsNameTextField.getText());
			kdcHost = newKdcTextField.getText();
			kdcTextField.setText( newKdcTextField.getText());
			domainStatusTextField.setText("");
			credentialsStatusTextField.setText("");

			if( domainDnsName.isEmpty())
			{
				domainStatusTextField.setText( "Domain DNS name cannot be empty");
			}
			else if( kdcHost.isEmpty())
			{
				domainStatusTextField.setText( "KDC host cannot be empty");
			}

			setDomainAndKdc(domainDnsName, kdcHost);
		}

		domainDnsNameTextField.setText( newDomainDnsNameTextField.getText());
		kdcTextField.setText( newKdcTextField.getText());

	}

	@SuppressWarnings("deprecation")
	private void changeCredentials()
	{
		JTextField newUsernameTextField = new JTextField();
		newUsernameTextField.setText(username);
		JPasswordField newPasswordField = new JPasswordField();
		newPasswordField.setText( password);
		final JComponent[] inputs = new JComponent[] {
				new JLabel("Username"),
				newUsernameTextField,
				new JLabel("Password"),
				newPasswordField,
		};
		JOptionPane.showMessageDialog(null, inputs, "Change credentials", JOptionPane.PLAIN_MESSAGE);

		if( newUsernameTextField.getText().contains("\\")
				|| newUsernameTextField.getText().contains("/")
				|| newUsernameTextField.getText().contains("@")
				)
		{
			JOptionPane.showMessageDialog( null, "Username shouldn't contain slash, backslash or '@' - just a plain username is required", "Warning", JOptionPane.WARNING_MESSAGE);
		}

		if( (newUsernameTextField.getText() != username)
				|| (newPasswordField.getText() != password))		// don't do anything if values are unchanged
		{
			username = newUsernameTextField.getText();
			usernameTextField.setText( newUsernameTextField.getText());
			password = newPasswordField.getText();
			passwordField.setText( newPasswordField.getText());
			credentialsStatusTextField.setText("");

			if( username.isEmpty())
			{
				credentialsStatusTextField.setText( "Username cannot be empty");
			}
			/*
			else if( password.isEmpty())
			{
				credentialsStatusTextField.setText( "Password cannot be empty");
			}
			*/

			setCredentials(username, password);
		}
	}

	private void testCredentials()
	{
		if( usernameTextField.getText().isEmpty())
		{
			JOptionPane.showMessageDialog( null, "Username not set yet", "Error", JOptionPane.ERROR_MESSAGE);
			return;
		}

		/*
		if( passwordField.getText().isEmpty())
		{
			JOptionPane.showMessageDialog( null, "Password not set yet", "Error", JOptionPane.ERROR_MESSAGE);
			return;
		}
		*/

		if( !(domainStatusTextField.getText().equals(kdcTestSuccessString)))
		{
			int n = JOptionPane.showConfirmDialog(
					null,
					"You haven't successfully tested the domain settings yet, do you want to continue without doing so?",
					"Proceed?",
					JOptionPane.YES_NO_OPTION);

			if( n == JOptionPane.NO_OPTION)
			{
				return;
			}
		}

		setupKerberosConfig();

		try
		{
			LoginContext loginContext = new LoginContext("KrbLogin", new KerberosCallBackHandler( username, password));
			loginContext.login();
			
			boolean forwardable = checkTgtForwardableFlag(loginContext.getSubject());
			
			credentialsStatusTextField.setText( credentialsTestSuccessString + " (" + (forwardable ? forwardableTgtString : notForwardableTgtString) + ")");
			JOptionPane.showMessageDialog( null, credentialsTestSuccessString + "\n\n(" + (forwardable ? forwardableTgtString : notForwardableTgtString) + ")", "Success", JOptionPane.INFORMATION_MESSAGE);
		}
		catch( Exception e)
		{
			if( e.getMessage().startsWith( "Client not found in Kerberos database"))
			{
				credentialsStatusTextField.setText( "Failed to acquire TGT - username appears to be invalid");
				JOptionPane.showMessageDialog( null, "Failed to acquire TGT - username appears to be invalid.", "Failure", JOptionPane.ERROR_MESSAGE);
			}
			else if( e.getMessage().startsWith( "Pre-authentication information was invalid"))
			{
				credentialsStatusTextField.setText( "Failed to acquire TGT - password appears to be invalid");
				JOptionPane.showMessageDialog( null, "Failed to acquire TGT - password appears to be invalid.\n\nBe careful not to lock out the account with more tests.", "Failure", JOptionPane.ERROR_MESSAGE);
			}
			else
			{
				credentialsStatusTextField.setText( "Failed to acquire TGT: " + e.getMessage());
				JOptionPane.showMessageDialog( null, "Failed to acquire TGT: " + e.getMessage(), "Failure", JOptionPane.ERROR_MESSAGE);
				log( 1, "Unexpected error when testing credentials: " + e.getMessage());
				logException( 2, e);
			}
		}
	}

	private void pingKDC()
	{
		if( domainDnsNameTextField.getText().isEmpty())
		{
			JOptionPane.showMessageDialog( null, "Domain DNS name not set yet", "Error", JOptionPane.ERROR_MESSAGE);
			return;
		}

		if( kdcTextField.getText().isEmpty())
		{
			JOptionPane.showMessageDialog( null, "KDC hostname not set yet", "Error", JOptionPane.ERROR_MESSAGE);
			return;
		}

		try
		{
			Socket client=new Socket();   
			client.connect(new InetSocketAddress(kdcHost, 88), 2000);
			client.close();
		}
		catch( UnknownHostException e)
		{
			domainStatusTextField.setText( "KDC hostname couldn't be resolved");
			JOptionPane.showMessageDialog( null, "Couldn't resolve KDC hostname:" + kdcHost, "Failure", JOptionPane.ERROR_MESSAGE);
			return;
		}
		catch( SocketTimeoutException e)
		{
			domainStatusTextField.setText( "Couldn't connect to port 88 (Kerberos) on KDC - socket timed out");
			JOptionPane.showMessageDialog( null, "Couldn't connect to port 88 (Kerberos) on KDC:" + kdcHost + ". Socket timed out - check hostname?", "Failure", JOptionPane.ERROR_MESSAGE);
			return;
		}
		catch( Exception e)
		{
			domainStatusTextField.setText( "Failed to connect to port 88 on KDC");
			JOptionPane.showMessageDialog( null, "Failed to connect to port 88 on " + kdcHost + ": " + e.getMessage(), "Failure", JOptionPane.ERROR_MESSAGE);
			log( 1, "Unexpected error when testing connectivity to KDC: " + e.getMessage());
			logException( 2, e);
			return;
		}

		setupKerberosConfig();

		try
		{
			LoginContext loginContext = new LoginContext("KrbLogin", new KerberosCallBackHandler( null, null));
			loginContext.login();
		}
		catch( Exception e)
		{
			if( e.getMessage().startsWith( "Client not found in Kerberos database"))
			{
				domainStatusTextField.setText( kdcTestSuccessString);
				JOptionPane.showMessageDialog( null, kdcTestSuccessString, "Success", JOptionPane.INFORMATION_MESSAGE);
			}
			else if( e.getMessage().contains("(68)"))
			{
				domainStatusTextField.setText( "Failed to contact Kerberos service - error code 68 suggests that KDC is valid but domain DNS name is wrong");
				JOptionPane.showMessageDialog( null, "Failed to contact Kerberos service - error code 68 suggests that KDC is valid but domain DNS name is wrong", "Failure", JOptionPane.ERROR_MESSAGE);
			}
			else
			{
				domainStatusTextField.setText( "Connected to port 88, but failed to contact Kerberos service: " + e.getMessage());
				JOptionPane.showMessageDialog( null, "Connected to port 88, but failed to contact Kerberos service: " + e.getMessage(), "Failure", JOptionPane.ERROR_MESSAGE);
				log( 1, "Unexpected error when making test Kerberos request to KDC: " + e.getMessage());
				logException( 2, e);
			}
		}
	}

	/*
	private void domainDnsNameAuto()
	{
		// XXX: write me
		// might need to be platform-specific hacks
		// could read %USERDNSDOMAIN% on Windows
	}
	 */

	private void kdcAuto()
	{
		if( domainDnsName.isEmpty())
		{
			JOptionPane.showMessageDialog( null, "Have to set the domain DNS name first", "Failure", JOptionPane.ERROR_MESSAGE);
			return;
		}

		List<String> results = new ArrayList<String>();
		try {
			Hashtable<String, String> envProps = new Hashtable<String, String>();
			envProps.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
			DirContext dnsContext = new InitialDirContext(envProps);
			Attributes dnsEntries = dnsContext.getAttributes( "_kerberos._tcp." + domainDnsName.toLowerCase(), new String[]{"SRV"});
			if(dnsEntries != null) {
				Attribute attr = dnsEntries.get("SRV");

				if (attr != null) {
					for (int i = 0; i < attr.size(); i++) {
						String s = (String) attr.get(i);
						String[] parts = s.split(" ");
						String namePart = parts[parts.length - 1];
						if( namePart.endsWith("."))
						{
							namePart = namePart.substring(0, namePart.length() - 1);
						}
						results.add(namePart);
					}
				}
			}
		} catch(Exception e) {
			if( e.getMessage().startsWith("DNS name not found"))
			{
				JOptionPane.showMessageDialog( null, "Couldn't find any suitable DNS SRV records - is (one of) your DNS server(s) in the domain?", "Failure", JOptionPane.ERROR_MESSAGE);
			}
			else
			{
				JOptionPane.showMessageDialog( null, "Failure doing DNS SRV lookup", "Failure", JOptionPane.ERROR_MESSAGE);
				log( 1, "Unexpected error when doing DNS SRV lookup: " + e.getMessage());
				logException( 2, e);
			}
			return;
		}

		if( results.size() == 0)
		{
			JOptionPane.showMessageDialog( null, "No DNS entries for KDC found", "Failure", JOptionPane.ERROR_MESSAGE);
			return;
		}

		String selectedValue = "";

		if( results.size() == 1)
		{
			selectedValue = results.get(0);
		}
		else
		{
			Object[] possibilities = new Object[results.size()];
			for( int ii=0; ii<results.size(); ii++)
			{
				possibilities[ii] = results.get(ii);
			}
			selectedValue = (String)JOptionPane.showInputDialog(
					null,
					"Multiple KDCs were found",
					"Select KDC", 
					JOptionPane.PLAIN_MESSAGE,
					null,
					possibilities,
					results.get(0));
		}

		if( !selectedValue.isEmpty())
		{
			kdcHost = selectedValue;
			kdcTextField.setText( selectedValue);
			domainStatusTextField.setText("");

			setDomainAndKdc(domainDnsName, kdcHost);
		}
	}

	private class HelpButtonActionListener implements ActionListener{

		private String message;

		public HelpButtonActionListener(String m)
		{
			this.message=m;
		}

		public void actionPerformed(ActionEvent e) {
			JOptionPane.showMessageDialog(null, message, "Help", JOptionPane.INFORMATION_MESSAGE);
		}
	}
}
