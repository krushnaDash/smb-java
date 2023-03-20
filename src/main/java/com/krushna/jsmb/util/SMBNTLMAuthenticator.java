package com.krushna.jsmb.util;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.GSSAuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.Share;

import jcifs.CIFSContext;
import jcifs.context.SingletonContext;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SmbFile;

public class SMBNTLMAuthenticator {

	public static void connectWithsmbj(String hostName, String filePath, String domain, String userName,
			String password) throws Exception {

		SMBClient client = new SMBClient();

		try (Connection connection = client.connect(hostName)) {
			AuthenticationContext ac = new AuthenticationContext(userName, password.toCharArray(), domain);
			Session session = connection.authenticate(ac);

			// Connect to Share
			try (DiskShare share = (DiskShare) session.connectShare(filePath)) {
				for (FileIdBothDirectoryInformation f : share.list("FOLDER", "*.TXT")) {
					System.out.println("File : " + f.getFileName());
				}
			}
		}
		client.close();
	}

	public static void connectWithjcifs(String hostName, String filePath, String domain, String userName,
			String password) {
		System.setProperty("jcifs.smb.client.maxVersions", "SMB300");
		System.setProperty("jcifs.smb.client.enforceSpnegoIntegrity", "false");

		CIFSContext base = SingletonContext.getInstance();
		CIFSContext authed1 = base.withCredentials(new NtlmPasswordAuthenticator(domain, userName, password));
		String url = "smb://" + hostName + "/" + filePath;

		try {
			SmbFile f = new SmbFile(url, authed1);

			for (SmbFile fi : f.listFiles()) {
				System.out.println(fi.getName());
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	public static void connectWithJcifsKrbAuth(String hostName, String filePath, String domain, String userName,
			String password) {
		
	}
}
