package me.draconia.chat.commands;

import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.client.types.ClientChannel;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.types.MessageContext;
import me.draconia.chat.types.User;

@BaseCommand.Names({"close", "leave"})
public class LeaveCommand extends BaseClientCommand {
	@Override
	public void run(User user, MessageContext messageContext, String[] args, String argStr) throws Exception {
		if (messageContext instanceof ClientChannel) {
			((ClientChannel) messageContext).leave();
		} else if (messageContext instanceof ClientUser) {
			FormMain.instance.removeChatTab(messageContext);
		}
	}
}
