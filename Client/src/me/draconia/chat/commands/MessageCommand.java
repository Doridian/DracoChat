package me.draconia.chat.commands;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.types.*;
import me.draconia.chat.util.IntUtils;

@BaseCommand.Names({"msg", "message"})
public class MessageCommand extends BaseClientCommand {
	@Override
	public void run(User user, MessageContext messageContext, String[] args, String argStr) throws Exception {
		MessageContext sendMessageTo;
		String arg = args[0];
		if (arg.charAt(0) == '#') {
			sendMessageTo = ChannelFactory.instance.createFromName(arg.substring(1));
		} else {
			sendMessageTo = UserFactory.instance.getFromLogin(arg);
		}
		TextMessage textMessage = new TextMessage();
		textMessage.context = sendMessageTo;
		textMessage.type = TextMessage.TYPE_CHAT;
		textMessage.content = IntUtils.concatArray(args, 1, "");
		ClientLib.sendEncryptableMessage(textMessage);
	}
}
