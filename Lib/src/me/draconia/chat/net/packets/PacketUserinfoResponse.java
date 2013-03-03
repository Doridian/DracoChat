package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import me.draconia.chat.types.User;
import me.draconia.chat.types.UserFactory;
import org.jboss.netty.buffer.ChannelBuffer;

@Packet.PacketID(Packets.USERINFO)
@Packet.PacketSide(Packet.Side.SERVER_TO_CLIENT)
public class PacketUserinfoResponse extends Packet {
	public User[] users;
	public String[] nicknames;
	public byte[] states;

	@Override
	protected void decode(ChannelBuffer channelBuffer) {
		short count = channelBuffer.readShort();
		users = new User[count];
		nicknames = new String[count];
		states = new byte[count];
		for (short i = 0; i < count; i++) {
			users[i] = UserFactory.instance.getFromLogin(readString(channelBuffer));
			nicknames[i] = readString(channelBuffer);
			states[i] = channelBuffer.readByte();
		}
	}

	@Override
	protected void encode(ChannelBuffer channelBuffer) {
		short count = (short) users.length;
		channelBuffer.writeShort(count);
		for (short i = 0; i < count; i++) {
			writeString(channelBuffer, users[i].login);
			writeString(channelBuffer, nicknames[i]);
			channelBuffer.writeByte(states[i]);
		}
	}
}
