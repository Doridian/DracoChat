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
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;

import java.net.InetSocketAddress;

public class ClientLib {
	public static Channel clientDataChannel;

	public static ChannelFuture sendPacket(Packet packet) {
		if (clientDataChannel == null) return null;
		return clientDataChannel.write(packet.getData());
	}

	public static String myLogin = null;
	public static InetSocketAddress myHost = null;
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

	public static void sendEncryptableMessage(Message message, boolean showReceived) {
		sendEncryptableMessage(message, null, showReceived);
	}

	public static void sendEncryptableMessage(Message message) {
		sendEncryptableMessage(message, null);
	}

	public static void sendEncryptableMessage(Message message, ChannelFutureListener channelFutureListener) {
		sendEncryptableMessage(message, channelFutureListener, true);
	}

	public static void sendEncryptableMessage(Message message, ChannelFutureListener channelFutureListener, boolean showReceived) {
		message.from = ClientLib.myUser;
		if (message.context instanceof ClientUser && (ALWAYS_OTR || OTRChatManager.isOTR((ClientUser) message.context))) {
			message.encrypted = true;
			OTRChatManager.sendMessage(message, channelFutureListener, showReceived);
		} else {
			ClientLib.sendMessage(message, channelFutureListener, showReceived);
		}
	}

	public static void sendMessage(Message message, boolean showReceived) {
		sendMessage(message, null, showReceived);
	}

	public static void sendMessage(Message message) {
		sendMessage(message, null);
	}

	public static void sendMessage(Message message, ChannelFutureListener channelFutureListener) {
		sendMessage(message, channelFutureListener, true);
	}

	public static void sendMessage(Message message, ChannelFutureListener channelFutureListener, boolean showReceived) {
		message.from = myUser;
		PacketMessageToServer packetMessage = new PacketMessageToServer();
		packetMessage.message = message;

		ChannelFuture channelFuture = sendPacket(packetMessage);
		if(channelFutureListener != null) {
			channelFuture.addListener(channelFutureListener);
		}

		if (showReceived) {
			FormMain.instance.getChatTab(message).messageReceived(message);
		}
	}

	public static void login() {
		FormMain.clientBootstrap.connect(myHost).addListener(new ChannelFutureListener() {
			@Override
			public void operationComplete(ChannelFuture channelFuture) throws Exception {
				if ((!channelFuture.getChannel().isConnected()) && channelFuture.getCause() != null) {
					FormMain.genericChatTab.addText("[NET] Connection error: " + channelFuture.getCause().getMessage());
					FormMain.instance.showLoginDialog();
				}
			}
		});
	}

	protected static void sendLogin() {
		PacketLoginRequest packetLoginRequest = new PacketLoginRequest();
		packetLoginRequest.username = myLogin;
		packetLoginRequest.password = myPassord;
		packetLoginRequest.version = ChatLib.PROTOCOL_VERSION;
		sendPacket(packetLoginRequest);
	}
}
