package me.draconia.chat.client.types;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.net.packets.PacketChannelAction;
import me.draconia.chat.types.Channel;
import me.draconia.chat.types.User;

import java.util.HashSet;

public class ClientChannel extends Channel {
    private final HashSet<ClientUser> users = new HashSet<ClientUser>();

    ClientChannel(String name) {
        super(name);
    }

    public void userJoined(ClientUser clientUser) {
        synchronized (users) {
            users.add(clientUser);
        }
        FormMain.instance.getChatTab(this).addUserToList(clientUser);
    }

    public void userLeft(ClientUser clientUser) {
        synchronized (users) {
            users.remove(clientUser);
        }
        FormMain.instance.getChatTab(this).removeUserFromList(clientUser);
    }

    public void gotUserSnapshot(User[] newUsers) {
        synchronized (users) {
            users.clear();
            for(User newUser : newUsers) {
                users.add((ClientUser)newUser);
            }
        }
        FormMain.instance.getChatTab(this).setUserList(newUsers);
    }

    public void join() {
        PacketChannelAction packetChannelAction = new PacketChannelAction();
        packetChannelAction.channel = this;
        packetChannelAction.user = ClientLib.myUser;
        packetChannelAction.action = PacketChannelAction.ACTION_JOIN;
        ClientLib.sendPacket(packetChannelAction);
    }

    public void leave() {
        PacketChannelAction packetChannelAction = new PacketChannelAction();
        packetChannelAction.channel = this;
        packetChannelAction.user = ClientLib.myUser;
        packetChannelAction.action = PacketChannelAction.ACTION_LEAVE;
        ClientLib.sendPacket(packetChannelAction);
    }
}
