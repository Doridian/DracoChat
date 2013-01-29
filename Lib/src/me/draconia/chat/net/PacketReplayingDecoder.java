package me.draconia.chat.net;

import me.draconia.chat.net.packets.Packet;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.replay.ReplayingDecoder;

enum PacketReadingState {
    READ_ID,
    READ_LENGTH,
    READ_CONTENT
}

public class PacketReplayingDecoder extends ReplayingDecoder<PacketReadingState> {
    public PacketReplayingDecoder() {
        super(PacketReadingState.READ_ID);
    }

    private byte id;
    private int length;

    @Override
    protected Object decode(ChannelHandlerContext channelHandlerContext, Channel channel, ChannelBuffer channelBuffer, PacketReadingState packetReadingState) throws Exception {
        switch(packetReadingState) {
            case READ_ID:
                id = channelBuffer.readByte();
                checkpoint(PacketReadingState.READ_LENGTH);
            case READ_LENGTH:
                length = channelBuffer.readInt();
                checkpoint(PacketReadingState.READ_CONTENT);
            case READ_CONTENT:
                ChannelBuffer frame = channelBuffer.readBytes(length);
                checkpoint(PacketReadingState.READ_ID);
                return Packet.createPacketFrom(id, frame);
            default:
                throw new Error("Wut?");
        }
    }
}
