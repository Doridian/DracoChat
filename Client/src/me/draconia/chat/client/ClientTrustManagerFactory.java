package me.draconia.chat.client;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class ClientTrustManagerFactory extends TrustManagerFactorySpi {
	private static final TrustManager DUMMY_TRUST_MANAGER = new X509TrustManager() {
		@Override
		public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

		}

		@Override
		public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}
	};

	@Override
	protected void engineInit(KeyStore keyStore) throws KeyStoreException {
		//Unused
	}

	@Override
	protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException {
		//Unused
	}

	@Override
	protected TrustManager[] engineGetTrustManagers() {
		return getTrustManagers();
	}

	public static TrustManager[] getTrustManagers() {
		return new TrustManager[]{DUMMY_TRUST_MANAGER};  //To change body of implemented methods use File | Settings | File Templates.
	}
}
