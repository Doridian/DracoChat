package me.draconia.chat.client;

import me.draconia.chat.ChatLib;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.client.otr.OTRChatManager;
import me.draconia.chat.net.packets.Packet;
import me.draconia.chat.net.packets.PacketLoginRequest;
import me.draconia.chat.net.packets.PacketMessageToServer;
import me.draconia.chat.types.Message;
import me.draconia.chat.types.MessageContext;
import me.draconia.chat.types.TextMessage;
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

    public static void setPassword(String password) {
        myPassord = password;
    }

    public static String getPassword() {
        return myPassord;
    }

    public static ClientUser myUser;

    public static void sendMessage(MessageContext messageContext, byte type, String message) {
        TextMessage msg = new TextMessage();
        msg.context = messageContext;
        msg.content = message;
        msg.type = type;
        msg.from = myUser;
        sendEncryptableMessage(msg);
    }

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
        message.from = myUser;

        PacketMessageToServer packetMessage = new PacketMessageToServer();
        packetMessage.message = message;
        sendPacket(packetMessage);
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
