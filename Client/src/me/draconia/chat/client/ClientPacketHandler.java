package me.draconia.chat.client;

import me.draconia.chat.client.gui.ChatTab;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.client.otr.OTRChatManager;
import me.draconia.chat.client.types.ClientChannel;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.net.PacketHandler;
import me.draconia.chat.net.Packets;
import me.draconia.chat.net.packets.*;
import me.draconia.chat.types.BinaryMessage;
import me.draconia.chat.types.Message;
import me.draconia.chat.types.TextMessage;
import me.draconia.chat.types.UserFactory;
import org.jboss.netty.channel.*;
import org.jboss.netty.handler.ssl.SslHandler;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;

public class ClientPacketHandler extends PacketHandler {
	@Override
	public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
		final SslHandler sslHandler = ctx.getPipeline().get(SslHandler.class);
		ChannelFuture handshakeFuture = sslHandler.handshake();
		handshakeFuture.addListener(new ChannelFutureListener() {
			@Override
			public void operationComplete(ChannelFuture channelFuture) throws Exception {
				FormMain.genericChatTab.addText("[NET] Connected");
				ClientLib.clientDataChannel = channelFuture.getChannel();
				ClientLib.sendLogin();
			}
		});
	}

	@Override
	public void packetReceived(ChannelHandlerContext ctx, Packet packet) throws Exception {
		final int packetID = packet.getID();

		switch (packetID) {
			case Packets.PING:
				PacketPingPong packetPingPong = (PacketPingPong) packet;
				if (packetPingPong.id > 0) {
					packetPingPong.id = -packetPingPong.id;
					ctx.getChannel().write(packetPingPong.getData());
				} else {
					//We got a response...DEAL WITH IT HERE
				}
				break;
			case Packets.CHANNEL_ACTION:
				PacketChannelAction packetChannelAction = (PacketChannelAction) packet;
				if (packetChannelAction.user.equals(ClientLib.myUser)) {
					switch (packetChannelAction.action) {
						case PacketChannelAction.ACTION_JOIN:
							FormMain.instance.getChatTab(packetChannelAction.channel);
							break;
						case PacketChannelAction.ACTION_LEAVE:
							FormMain.instance.removeChatTab(packetChannelAction.channel);
							break;
						case PacketChannelAction.ACTION_JOIN_DECLINED:
							FormMain.instance.removeChatTab(packetChannelAction.channel);
							break;
					}
				} else {
					switch (packetChannelAction.action) {
						case PacketChannelAction.ACTION_JOIN:
							((ClientChannel) packetChannelAction.channel).userJoined((ClientUser) packetChannelAction.user);
							break;
						case PacketChannelAction.ACTION_LEAVE:
							((ClientChannel) packetChannelAction.channel).userLeft((ClientUser) packetChannelAction.user);
							break;
					}
				}
				break;
			case Packets.CHANNEL_USER_SNAPSHOT:
				PacketChannelUserSnapshotResponse packetChannelUserSnapshotResponse = (PacketChannelUserSnapshotResponse) packet;
				((ClientChannel) packetChannelUserSnapshotResponse.channel).gotUserSnapshot(packetChannelUserSnapshotResponse.users);
				break;
			case Packets.LOGIN:
				PacketLoginResponse packetLoginResponse = (PacketLoginResponse) packet;
				if (packetLoginResponse.success) {
					ClientLib.ENABLE_AUTORECONNECT = true;
					ClientLib.myUser = (ClientUser) UserFactory.instance.getFromLogin(ClientLib.myLogin);
					ClientLib.myUser.setNickname(packetLoginResponse.nickname);
					FormMain.genericChatTab.addText("[MOTD] " + packetLoginResponse.message);
					ClientLib.clientDataChannel.getCloseFuture().addListener(new ChannelFutureListener() {
						@Override
						public void operationComplete(ChannelFuture channelFuture) throws Exception {
							new Thread() {
								public void run() {
									try {
										FormMain.genericChatTab.addText("[NET] Disconnected");
										Thread.sleep(1000);
										if (ClientLib.ENABLE_AUTORECONNECT) {
											ClientLib.login();
										}
									} catch (Exception e) {

									}
								}
							}.start();
						}
					});

					FormMain.instance.onSuccessfulLogin();
				} else {
					FormMain.genericChatTab.addText("[LOGIN] " + packetLoginResponse.message);
					FormMain.instance.showLoginDialog();
				}
				break;
			case Packets.NICK_SET:
				PacketNickset packetNickset = (PacketNickset) packet;
				ClientLib.myUser.setNickname(packetNickset.nickname);
				break;
			case Packets.USERINFO:
				PacketUserinfoResponse packetUserinfoResponse = (PacketUserinfoResponse) packet;
				for (int i = 0; i < packetUserinfoResponse.users.length; i++) {
					ClientUser cltUser = (ClientUser) packetUserinfoResponse.users[i];
					cltUser.setNickname(packetUserinfoResponse.nicknames[i]);
					cltUser.setState(packetUserinfoResponse.states[i]);
				}
				break;
			case Packets.DISCONNECT:
				ClientLib.ENABLE_AUTORECONNECT = false;
				PacketDisconnect packetDisconnect = (PacketDisconnect) packet;
				FormMain.genericChatTab.addText("[QUIT] " + packetDisconnect.message);
				ctx.getChannel().close();
				break;
			case Packets.MESSAGE:
				Message message = ((PacketMessageToClient) packet).message;
				if (message instanceof TextMessage) {
					ChatTab chatTab = FormMain.instance.getChatTab(message);
					chatTab.messageReceived(message);
				} else if (message instanceof BinaryMessage) {
					BinaryMessage binaryMessage = (BinaryMessage) message;
					if (binaryMessage.type == BinaryMessage.TYPE_OTR_MESSGAE || binaryMessage.type == BinaryMessage.TYPE_OTR_PUBKEY_1 || binaryMessage.type == BinaryMessage.TYPE_OTR_PUBKEY_2 || binaryMessage.type == BinaryMessage.TYPE_OTR_ERROR) {
						OTRChatManager.messageReceived(binaryMessage);
					}
				}
				break;
		}
	}

	@Override
	public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
		if (e.getCause() instanceof ClosedChannelException || e.getCause() instanceof IOException)
			return;
		e.getCause().printStackTrace();
	}
}
