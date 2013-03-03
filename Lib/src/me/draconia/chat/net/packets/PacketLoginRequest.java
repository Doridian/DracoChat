package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import org.jboss.netty.buffer.ChannelBuffer;

@Packet.PacketID(Packets.LOGIN)
@Packet.PacketSide(Packet.Side.CLIENT_TO_SERVER)
public class PacketLoginRequest extends Packet {
	public int version;
	public String username;
	public String password;

	@Override
	protected void decode(ChannelBuffer channelBuffer) {
		version = channelBuffer.readInt();
		username = readString(channelBuffer);
		password = readString(channelBuffer);
	}

	@Override
	protected void encode(ChannelBuffer channelBuffer) {
		channelBuffer.writeInt(version);
		writeString(channelBuffer, username);
		writeString(channelBuffer, password);
	}
}
