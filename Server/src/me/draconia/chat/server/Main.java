package me.draconia.chat.server;

import me.draconia.chat.ChatLib;
import me.draconia.chat.net.packets.Packet;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.jboss.netty.bootstrap.ServerBootstrap;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.FileReader;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.concurrent.Executors;

public class Main {
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());

		SSLContext sslContext;

		try {
			final char[] ksPW = "secret".toCharArray();

			final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter().setProvider("BC");

			FileReader fileReader = new FileReader("server.crt");
			PEMParser pemReader = new PEMParser(fileReader);
			X509Certificate mainCert = null;
			ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
			while(pemReader.ready()) {
				X509CertificateHolder holder = (X509CertificateHolder)pemReader.readObject();
				if(holder == null) break;
				X509Certificate cert = certificateConverter.getCertificate(holder);
				certs.add(cert);
				if(mainCert == null) mainCert = cert;
			}
			pemReader.close();

			fileReader = new FileReader("server.key");
			pemReader = new PEMParser(fileReader);
			KeyPair keyPair = new JcaPEMKeyConverter().setProvider("BC").getKeyPair((PEMKeyPair)pemReader.readObject());
			pemReader.close();

			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(null);
			ks.setCertificateEntry("cert", mainCert);
			ks.setKeyEntry("key", keyPair.getPrivate(), ksPW, certs.toArray(new Certificate[certs.size()]));

			// Set up key manager factory to use our key store
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, ksPW);

			// Initialize the SSLContext to work with our key managers.
			sslContext = SSLContext.getInstance("TLS");
			sslContext.init(kmf.getKeyManagers(), null, null);
		} catch (Exception e) {
			throw new Error("Failed to initialize the server-side SSLContext", e);
		}

		ChannelPipelineFactory channelPipelineFactory = ChatLib.initialize(sslContext, false, new ServerPacketHandler(), Packet.Side.CLIENT_TO_SERVER, new ServerUserFactory(), new ServerChannelFactory());

		ServerBootstrap serverBootstrap = new ServerBootstrap(new NioServerSocketChannelFactory(Executors.newCachedThreadPool(), Executors.newCachedThreadPool()));
		serverBootstrap.setPipelineFactory(channelPipelineFactory);
		serverBootstrap.setOption("child.tcpNoDelay", true);
		serverBootstrap.setOption("child.keepAlive", true);

		final int port = 13137;

		serverBootstrap.bind(new InetSocketAddress(port));

		System.out.println("[NET] Server listening on port " + port);
	}
}
