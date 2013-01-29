package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import org.jboss.netty.buffer.ChannelBuffer;

@Packet.PacketID(Packets.DISCONNECT)
public class PacketDisconnect extends Packet {
    public String message;

    @Override
    protected void decode(ChannelBuffer channelBuffer) {
        message = readString(channelBuffer);
    }

    @Override
    protected void encode(ChannelBuffer channelBuffer) {
        writeString(channelBuffer, message);
    }
}
