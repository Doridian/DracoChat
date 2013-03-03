package me.draconia.chat.commands;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.net.packets.PacketNickset;
import me.draconia.chat.types.MessageContext;
import me.draconia.chat.types.User;

@BaseCommand.Names("nick")
public class NickCommand extends BaseClientCommand {
	@Override
	public void run(User user, MessageContext messageContext, String[] args, String argStr) throws Exception {
		PacketNickset packetNickset = new PacketNickset();
		packetNickset.nickname = argStr;
		ClientLib.sendPacket(packetNickset);
	}
}
