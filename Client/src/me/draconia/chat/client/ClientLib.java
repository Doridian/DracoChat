package me.draconia.chat.client;

import me.draconia.chat.ChatLib;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.client.otr.OTRChatManager;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.net.packets.Packet;
import me.draconia.chat.net.packets.PacketLoginRequest;
import me.draconia.chat.net.packets.PacketMessageToServer;
import me.draconia.chat.types.Message;
import org.jboss.netty.channel.Channel;

import java.net.InetSocketAddress;

public class ClientLib {
    protected static Channel clientDataChannel;
    public static void sendPacket(Packet packet) {
        clientDataChannel.write(packet.getData());
    }

    public static String myLogin = null;
    private static String myPassord = null;

    public static boolean ALWAYS_OTR = true;
    public static boolean ENABLE_AUTORECONNECT = false;

    public static void setPassword(String password) {
        myPassord = password;
    }

    public static String getPassword() {
        return myPassord;
    }

    public static ClientUser myUser;

    public static void sendEncryptableMessage(Message message) {
        message.from = ClientLib.myUser;
        if(message.context instanceof ClientUser && (ALWAYS_OTR || OTRChatManager.isOTR((ClientUser)message.context))) {
            message.encrypted = true;
            OTRChatManager.sendMessage(message);
        } else {
            ClientLib.sendMessage(message);
        }
    }

    public static void sendMessage(Message message) {
        sendMessage(message, true);
    }

    public static void sendMessage(Message message, boolean showReceived) {
        message.from = myUser;
        PacketMessageToServer packetMessage = new PacketMessageToServer();
        packetMessage.message = message;

        sendPacket(packetMessage);

        if(showReceived) {
            FormMain.instance.getChatTab(message).messageReceived(message);
        }
    }

    public static void login() {
        FormMain.clientBootstrap.connect(new InetSocketAddress("127.0.0.1", 13137));
    }

    protected static void sendLogin() {
        PacketLoginRequest packetLoginRequest = new PacketLoginRequest();
        packetLoginRequest.username = myLogin;
        packetLoginRequest.password = myPassord;
        packetLoginRequest.version = ChatLib.PROTOCOL_VERSION;
        sendPacket(packetLoginRequest);
    }
}
