package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import me.draconia.chat.types.Channel;
import me.draconia.chat.types.ChannelFactory;
import me.draconia.chat.types.User;
import me.draconia.chat.types.UserFactory;
import org.jboss.netty.buffer.ChannelBuffer;

//When a client sends this packet, we discard the user!
@Packet.PacketID(Packets.CHANNEL_ACTION)
public class PacketChannelAction extends Packet {
	public static final byte ACTION_LEAVE = 0;
	public static final byte ACTION_JOIN = 1;
	public static final byte ACTION_JOIN_DECLINED = 2;

	public User user;
	public Channel channel;
	public byte action;

	@Override
	protected void decode(ChannelBuffer channelBuffer) {
		user = UserFactory.instance.getFromLogin(readString(channelBuffer));
		channel = ChannelFactory.instance.createFromName(readString(channelBuffer));
		action = channelBuffer.readByte();
	}

	@Override
	protected void encode(ChannelBuffer channelBuffer) {
		writeString(channelBuffer, user.login);
		writeString(channelBuffer, channel.name);
		channelBuffer.writeByte(action);
	}
}
