package me.draconia.chat.client.types;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.net.packets.PacketChannelAction;
import me.draconia.chat.types.Channel;

public class ClientChannel extends Channel {
    ClientChannel(String name) {
        super(name);
    }

    public void join() {
        PacketChannelAction packetChannelAction = new PacketChannelAction();
        packetChannelAction.channel = this;
        packetChannelAction.user = ClientLib.myUser;
        packetChannelAction.action = PacketChannelAction.ACTION_JOIN;
        ClientLib.sendPacket(packetChannelAction);
    }
}
