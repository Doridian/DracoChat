package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import me.draconia.chat.types.User;
import me.draconia.chat.types.UserFactory;
import org.jboss.netty.buffer.ChannelBuffer;

@Packet.PacketID(Packets.USERINFO)
@Packet.PacketSide(Packet.Side.CLIENT_TO_SERVER)
public class PacketUserinfoRequest extends Packet {
	public User[] users_subscribe;
	public User[] users_unsubscribe;

	@Override
	protected void decode(ChannelBuffer channelBuffer) {
		short count = channelBuffer.readShort();
		users_subscribe = new User[count];
		for (short i = 0; i < count; i++) {
			users_subscribe[i] = UserFactory.instance.getFromLogin(readString(channelBuffer));
		}
		count = channelBuffer.readShort();
		users_unsubscribe = new User[count];
		for (short i = 0; i < count; i++) {
			users_unsubscribe[i] = UserFactory.instance.getFromLogin(readString(channelBuffer));
		}
	}

	@Override
	protected void encode(ChannelBuffer channelBuffer) {
		short count = (short) users_subscribe.length;
		channelBuffer.writeShort(count);
		for (short i = 0; i < count; i++) {
			writeString(channelBuffer, users_subscribe[i].login);
		}
		count = (short) users_unsubscribe.length;
		channelBuffer.writeShort(count);
		for (short i = 0; i < count; i++) {
			writeString(channelBuffer, users_unsubscribe[i].login);
		}
	}
}
