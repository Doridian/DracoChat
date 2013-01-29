package me.draconia.chat.net;

import me.draconia.chat.net.packets.Packet;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelHandler;

public abstract class PacketHandler extends SimpleChannelHandler {
    @Override
    public final void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        packetReceived(ctx, (Packet)e.getMessage());
    }

    public abstract void packetReceived(ChannelHandlerContext ctx, Packet packet) throws Exception;
}
