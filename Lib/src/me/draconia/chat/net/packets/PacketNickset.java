package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import org.jboss.netty.buffer.ChannelBuffer;

@Packet.PacketID(Packets.NICK_SET)
public class PacketNickset extends Packet {
	public String nickname;

	@Override
	protected void decode(ChannelBuffer channelBuffer) {
		nickname = readString(channelBuffer);
	}

	@Override
	protected void encode(ChannelBuffer channelBuffer) {
		writeString(channelBuffer, nickname);
	}
}
