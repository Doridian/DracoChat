package me.draconia.chat.commands;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.types.MessageContext;
import me.draconia.chat.types.TextMessage;
import me.draconia.chat.types.User;

@BaseCommand.Names({"me", "emote"})
public class MeCommand extends BaseClientCommand {
	@Override
	public void run(User user, MessageContext messageContext, String[] args, String argStr) throws Exception {
		TextMessage message = new TextMessage();
		message.content = argStr;
		message.type = TextMessage.TYPE_ACTION;
		message.context = messageContext;
		ClientLib.sendEncryptableMessage(message);
	}
}
