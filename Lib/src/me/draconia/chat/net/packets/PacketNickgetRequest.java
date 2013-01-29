package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import me.draconia.chat.types.User;
import me.draconia.chat.types.UserFactory;
import org.jboss.netty.buffer.ChannelBuffer;

@Packet.PacketID(Packets.NICK_GET)
@Packet.PacketSide(Packet.Side.CLIENT_TO_SERVER)
public class PacketNickgetRequest extends Packet {
    public User[] users;

    @Override
    protected void decode(ChannelBuffer channelBuffer) {
        byte count = channelBuffer.readByte();
        users = new User[count];
        for(byte i=0;i<count;i++) {
            users[i] = UserFactory.instance.getFromLogin(readString(channelBuffer));
        }
    }

    @Override
    protected void encode(ChannelBuffer channelBuffer) {
        byte count = (byte)users.length;
        channelBuffer.writeByte(count);
        for(byte i=0;i<count;i++) {
            writeString(channelBuffer, users[i].login);
        }
    }
}
