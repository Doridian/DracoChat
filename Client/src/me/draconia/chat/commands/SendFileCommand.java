package me.draconia.chat.commands;

import me.draconia.chat.client.filetransfer.FileSender;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.types.MessageContext;
import me.draconia.chat.types.User;

import java.io.File;
import java.util.HashMap;

@BaseCommand.Names({"send"})
public class SendFileCommand extends BaseClientCommand {
	private final HashMap<ClientUser, FileSender> fileSenders = new HashMap<ClientUser, FileSender>();

	@Override
	public void run(User user, MessageContext messageContext, String[] args, String argStr) throws Exception {
		ClientUser context = (ClientUser)messageContext;
		FileSender fileSender;
		synchronized (fileSenders) {
			if((fileSender = fileSenders.get(context)) != null) {
				if(!fileSender.isFinished()) {
					throw new Error("Sorry, there is already a file transfer with that user in progress");
				}
			}
			fileSender = new FileSender(context, new File(argStr));
			fileSenders.put(context, fileSender);
		}
	}
}