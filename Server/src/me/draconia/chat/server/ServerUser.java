package me.draconia.chat.server;

import iaik.sha3.IAIKSHA3Provider;
import me.draconia.chat.net.packets.Packet;
import me.draconia.chat.net.packets.PacketMessageToClient;
import me.draconia.chat.net.packets.PacketUserinfoResponse;
import me.draconia.chat.types.GenericContext;
import me.draconia.chat.types.TextMessage;
import me.draconia.chat.types.User;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;

public class ServerUser extends User implements Serializable {
	public static final long serialVersionUID = -1L;

	private transient byte state = User.STATE_OFFLINE;

	private byte[] password;
	private transient Channel channel;

	protected transient HashSet<ServerChannel> channels = new HashSet<ServerChannel>();
	protected transient HashSet<ServerUser> subscribed_users = new HashSet<ServerUser>();
	protected transient HashSet<ServerUser> subscriptions = new HashSet<ServerUser>();

	private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
		in.defaultReadObject();
		channels = new HashSet<ServerChannel>();
		subscribed_users = new HashSet<ServerUser>();
		subscriptions = new HashSet<ServerUser>();
		state = User.STATE_OFFLINE;
	}

	protected ServerUser(String login) {
		super(login);
	}

	public byte getState() {
		return state;
	}

	public void setState(byte state) {
		if (state == this.state) return;
		this.state = state;
		notifySubscribers();
	}

	@Override
	public void setNickname(String nickname) {
		if (nickname.equals(this.nickname)) return;
		super.setNickname(nickname);
		notifySubscribers();
	}

	public void notifySubscribers() {
		PacketUserinfoResponse packetUserinfoResponse = new PacketUserinfoResponse();
		packetUserinfoResponse.users = new User[]{this};
		packetUserinfoResponse.states = new byte[]{this.state};
		packetUserinfoResponse.nicknames = new String[]{this.nickname};

		HashSet<ServerUser> reportToUsers = new HashSet<ServerUser>(subscribed_users);

		synchronized (channels) {
			for (ServerChannel serverChannel : channels) {
				reportToUsers.addAll(serverChannel.getUsers());
			}
		}

		for (ServerUser subscribedUser : reportToUsers) {
			subscribedUser.sendPacket(packetUserinfoResponse);
		}
	}

	protected void setChannel(final Channel setChannel) {
		setState(User.STATE_ONLINE);
		this.channel = setChannel;
		setChannel.getCloseFuture().addListener(new ChannelFutureListener() {
			@Override
			public void operationComplete(ChannelFuture channelFuture) throws Exception {
				disconnected(setChannel);
			}
		});
	}

	public boolean subscribe(ServerUser serverUser) {
		final boolean ret;
		synchronized (serverUser.subscribed_users) {
			synchronized (subscriptions) {
				ret = serverUser.subscribed_users.add(this);
				subscriptions.add(serverUser);
			}
		}
		return ret;
	}

	public boolean unsubscribe(ServerUser serverUser) {
		final boolean ret;
		synchronized (serverUser.subscribed_users) {
			synchronized (subscriptions) {
				ret = serverUser.subscribed_users.remove(this);
				subscriptions.remove(serverUser);
			}
		}
		return ret;
	}

	protected void disconnected(Channel channel) {
		if (channel != null && channel != this.channel) return;
		synchronized (channels) {
			final ServerChannel[] sChannels = channels.toArray(new ServerChannel[channels.size()]);
			for (ServerChannel serverChannel : sChannels) {
				serverChannel.leaveUser(this);
			}
			channels.clear();
		}
		synchronized (subscriptions) {
			final ServerUser[] sUsers = subscriptions.toArray(new ServerUser[subscriptions.size()]);
			for (ServerUser serverUser : sUsers) {
				this.unsubscribe(serverUser);
			}
			subscriptions.clear();
		}
		this.channel = null;
		setState(User.STATE_OFFLINE);
		System.out.println("[LOGIN] " + this.login + " left the server!");
	}

	protected Channel getChannel() {
		return channel;
	}

	private byte[] hashPassword(String password) {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("KECCAK256", IAIKSHA3Provider.getInstance());
			messageDigest.update(login.getBytes("UTF-8"));
			messageDigest.update(password.getBytes("UTF-8"));
			return messageDigest.digest();
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("UPS");
		}
	}

	public void setPassword(String password) {
		this.password = hashPassword(password);
	}

	public boolean checkPassword(String password) {
		if (this.password == null || password == null)
			return false;
		return Arrays.equals(this.password, hashPassword(password));
	}

	public boolean hasPassword() {
		return (this.password != null);
	}

	public boolean sendPacket(Packet packet) {
		if (channel == null) return false;
		channel.write(packet.getData());
		return true;
	}

	public boolean sendSystemMessage(String text) {
		return sendSystemMessage(text, TextMessage.TYPE_SYSTEM);
	}

	public boolean sendSystemError(String text) {
		return sendSystemMessage(text, TextMessage.TYPE_SYSTEM_ERROR);
	}

	public boolean sendSystemMessage(String text, byte type) {
		TextMessage message = new TextMessage();
		message.content = text;
		message.type = type;
		message.context = GenericContext.instance;
		message.from = User.getSYSTEM();
		PacketMessageToClient packetMessageToClient = new PacketMessageToClient();
		packetMessageToClient.message = message;
		return sendPacket(packetMessageToClient);
	}
}
