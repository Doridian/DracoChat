package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import org.jboss.netty.buffer.ChannelBuffer;

@Packet.PacketID(Packets.PING)
public class PacketPingPong extends Packet {
    public int id; //Positive = request, negative = answer

    @Override
    protected void decode(ChannelBuffer channelBuffer) {
        id = channelBuffer.readInt();
    }

    @Override
    protected void encode(ChannelBuffer channelBuffer) {
        channelBuffer.writeInt(id);
    }
}
