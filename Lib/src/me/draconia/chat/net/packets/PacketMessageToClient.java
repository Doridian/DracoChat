package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import me.draconia.chat.types.UserFactory;
import org.jboss.netty.buffer.ChannelBuffer;

@Packet.PacketID(Packets.MESSAGE)
@Packet.PacketSide(Packet.Side.SERVER_TO_CLIENT)
public class PacketMessageToClient extends PacketMessageToServer {
	@Override
	protected void encode(ChannelBuffer channelBuffer) {
		super.encode(channelBuffer);
		writeString(channelBuffer, message.from.login);
		channelBuffer.writeLong(message.timestamp);
	}

	@Override
	protected void decode(ChannelBuffer channelBuffer) {
		super.decode(channelBuffer);
		message.from = UserFactory.instance.getFromLogin(readString(channelBuffer));
		message.timestamp = channelBuffer.readLong();
	}
}
