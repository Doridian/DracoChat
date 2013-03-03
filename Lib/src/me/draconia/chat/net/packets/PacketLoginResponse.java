package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import org.jboss.netty.buffer.ChannelBuffer;

@Packet.PacketID(Packets.LOGIN)
@Packet.PacketSide(Packet.Side.SERVER_TO_CLIENT)
public class PacketLoginResponse extends Packet {
	public int version;
	public boolean success;
	public String message; //Error on fail, MOTD on success
	public String nickname;

	@Override
	protected void decode(ChannelBuffer channelBuffer) {
		version = channelBuffer.readInt();
		success = readBoolean(channelBuffer);
		message = readString(channelBuffer);
		nickname = readString(channelBuffer);
	}

	@Override
	protected void encode(ChannelBuffer channelBuffer) {
		channelBuffer.writeInt(version);
		writeBoolean(channelBuffer, success);
		writeString(channelBuffer, message);
		writeString(channelBuffer, nickname);
	}
}
