package me.draconia.chat.commands;

import me.draconia.chat.client.filetransfer.FileSender;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.types.MessageContext;
import me.draconia.chat.types.User;

import javax.swing.*;
import java.io.File;

@BaseCommand.Names({"send"})
public class SendFileCommand extends BaseClientCommand {
	@Override
	public void run(User user, MessageContext messageContext, String[] args, String argStr) throws Exception {
		final ClientUser clientUser = (ClientUser)messageContext;

		if(argStr.isEmpty()) {
			new Thread() {
				@Override
				public void run() {
					JFileChooser fileChooser = new JFileChooser();
					int ret = fileChooser.showOpenDialog(FormMain.instance.rootFrame);
					if(ret == JFileChooser.APPROVE_OPTION) {
						File chosenFile = fileChooser.getSelectedFile();
						FileSender.sendFile(clientUser, chosenFile);
					}
				}
			}.start();
		} else {
			FileSender.sendFile(clientUser, new File(argStr));
		}
	}
}