package me.draconia.chat.server;

import me.draconia.chat.ChatLib;
import me.draconia.chat.net.packets.Packet;
import org.jboss.netty.bootstrap.ServerBootstrap;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.Security;
import java.util.concurrent.Executors;

public class Main {
    public static void main(String[] args) {
        SSLContext sslContext;

        try {
            String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
            if(algorithm == null) {
                algorithm = "SunX509";
            }

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream("server.jks"), "secret".toCharArray());

            // Set up key manager factory to use our key store
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(ks, "secret".toCharArray());

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

        serverBootstrap.bind(new InetSocketAddress(13137));
    }
}
