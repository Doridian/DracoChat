package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import me.draconia.chat.types.Channel;
import me.draconia.chat.types.ChannelFactory;
import me.draconia.chat.types.User;
import me.draconia.chat.types.UserFactory;
import org.jboss.netty.buffer.ChannelBuffer;

@Packet.PacketID(Packets.CHANNEL_USER_SNAPSHOT)
@Packet.PacketSide(Packet.Side.SERVER_TO_CLIENT)
public class PacketChannelUserSnapshotResponse extends Packet {
    public Channel channel;
    public User[] users;

    @Override
    protected void decode(ChannelBuffer channelBuffer) {
        channel = ChannelFactory.instance.createFromName(readString(channelBuffer));
        byte count = channelBuffer.readByte();
        users = new User[count];
        for(byte i=0;i<count;i++) {
            users[i] = UserFactory.instance.getFromLogin(readString(channelBuffer));
        }
    }

    @Override
    protected void encode(ChannelBuffer channelBuffer) {
        writeString(channelBuffer, channel.name);
        byte count = (byte)users.length;
        channelBuffer.writeByte(count);
        for(byte i=0;i<count;i++) {
            writeString(channelBuffer, users[i].login);
        }
    }
}
