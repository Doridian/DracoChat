package me.draconia.chat.client.gui;

import me.draconia.chat.ChatLib;
import me.draconia.chat.client.*;
import me.draconia.chat.net.packets.Packet;
import me.draconia.chat.types.GenericContext;
import me.draconia.chat.types.MessageContext;
import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory;

import javax.net.ssl.SSLContext;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.HashMap;
import java.util.concurrent.Executors;

public class FormMain {
    private JTabbedPane chatTabs;
    private JPanel rootPanel;

    public static ClientBootstrap clientBootstrap;

    public static FormMain instance;
    public static ChatTab genericChatTab;

    private JFrame rootFrame;

    public FormMain() {
        instance = this;
        genericChatTab = getChatTab(GenericContext.instance);
    }

    public static void main(String[] args) {
        new FormMain();

        final SSLContext sslContext;

        try {
            // Initialize the SSLContext to work with our key managers.
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, ClientTrustManagerFactory.getTrustManagers(), null);
        } catch(Exception e) {
            throw new Error("Failed to initialize the client-side SSLContext", e);
        }

        ChannelPipelineFactory channelPipelineFactory = ChatLib.initialize(sslContext, true, new ClientPacketHandler(), Packet.Side.SERVER_TO_CLIENT, new ClientUserFactory(), new ClientChannelFactory());
        clientBootstrap = new ClientBootstrap(new NioClientSocketChannelFactory(Executors.newCachedThreadPool(), Executors.newCachedThreadPool()));
        clientBootstrap.setPipelineFactory(channelPipelineFactory);
        clientBootstrap.setOption("tcpNoDelay", true);
        clientBootstrap.setOption("keepAlive", true);

        FormMain.instance.rootFrame = new JFrame("DracoChat");
        FormMain.instance.rootFrame.setMinimumSize(new Dimension(640, 480));
        FormMain.instance.rootFrame.setLocationRelativeTo(null);
        FormMain.instance.rootFrame.setContentPane(instance.rootPanel);
        FormMain.instance.rootFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        FormMain.instance.rootFrame.pack();
        FormMain.instance.rootFrame.setVisible(true);

        FormMain.instance.rootFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosed(WindowEvent e) {
                exit();
            }
        });

        if(ClientLib.myLogin == null || ClientLib.myLogin.isEmpty()) {
            FormMain.instance.showLoginDialog();
        }
    }

    public void onSuccessfulLogin() {
        for(MessageContext messageContext : tabMap.keySet()) {
            if(messageContext instanceof ClientChannel) {
                ((ClientChannel)messageContext).join();
            }
        }
    }

    public void showLoginDialog() {
        DialogLogin dialogLogin = new DialogLogin(FormMain.instance.rootFrame);
        dialogLogin.setMinimumSize(new Dimension(300, 150));
        dialogLogin.setLocationRelativeTo(this.rootPanel);

        dialogLogin.setVisible(true);
    }

    private final HashMap<MessageContext, ChatTab> tabMap = new HashMap<MessageContext, ChatTab>();

    public void refreshTabTitle(MessageContext messageContext) {
        ChatTab chatTab = getChatTabNoCreate(messageContext);
        if(chatTab == null) return;
        chatTabs.setTitleAt(chatTabs.indexOfTabComponent(chatTab.chatTabPanel), messageContext.getContextName());
    }

    private ChatTab getChatTabNoCreate(MessageContext messageContext) {
        return tabMap.get(messageContext);
    }

    public ChatTab getChatTab(MessageContext messageContext) {
        ChatTab chatTab = getChatTabNoCreate(messageContext);
        if(chatTab == null) {
            chatTab = new ChatTab(messageContext);
            chatTabs.addTab(messageContext.getContextName(), chatTab.chatTabPanel);
            tabMap.put(messageContext, chatTab);
        }
        return chatTab;
    }

    public void removeChatTab(MessageContext messageContext) {
        ChatTab chatTab = tabMap.remove(messageContext);
        if(chatTab != null) {
            chatTabs.remove(chatTab.chatTabPanel);
        }
    }

    public static void exit() {
        new Thread() {
            @Override
            public void run() {
                try {
                    clientBootstrap.releaseExternalResources();
                } catch(Exception e) { }
                System.exit(0);
            }
        }.start();
    }
}
