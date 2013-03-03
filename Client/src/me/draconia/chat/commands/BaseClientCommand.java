package me.draconia.chat.commands;

import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.types.MessageContext;
import me.draconia.chat.types.User;

public abstract class BaseClientCommand extends BaseCommand {
	@Override
	public final void commandError(User user, MessageContext messageContext, Exception error) {
		FormMain.instance.getChatTab(messageContext).addText("[ERROR] " + error.getMessage());
	}
}
