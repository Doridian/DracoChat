package me.draconia.chat.client.gui;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.commands.BaseClientCommand;
import me.draconia.chat.types.*;

import javax.swing.*;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;

public class ChatTab {
	private JTextPane chatLog;
	protected JPanel chatTabPanel;
	private JButton sendButton;
	private JTextField chatEntry;
	private JList userList;
	private JScrollPane chatLogScrollPane;

	private final MessageContext relatedContext;

	public ChatTab(MessageContext relatedContext) {
		this.relatedContext = relatedContext;
		if (!(relatedContext instanceof Channel)) {
			userList.setVisible(false);
		}
		sendButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				sendChat();
			}
		});
		chatEntry.addKeyListener(new KeyListener() {
			@Override
			public void keyTyped(KeyEvent e) {
			}

			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					sendChat();
				}
			}

			@Override
			public void keyReleased(KeyEvent e) {
			}
		});

		if (relatedContext instanceof ClientUser) {
			ClientUser relatedUser = (ClientUser) relatedContext;
			synchronized (FormMain.instance.subscriptions_add) {
				FormMain.instance.subscriptions_del.remove(relatedUser);
				FormMain.instance.subscriptions_add.add(relatedUser);
			}
		}

		userListDataModel = new UserListDataModel();
		userList.setModel(userListDataModel);
	}

	private void sendChat() {
		final String text = chatEntry.getText();
		chatEntry.setText("");

		if (text.charAt(0) == '/' && BaseClientCommand.runCommand(ClientLib.myUser, relatedContext, text.substring(1))) {
			return;
		}

		TextMessage message = new TextMessage();
		message.content = text;
		message.type = TextMessage.TYPE_CHAT;
		message.context = relatedContext;

		if(text.charAt(0) == '/') {
			ClientLib.sendMessage(message);
		} else {
			ClientLib.sendEncryptableMessage(message);
		}
	}

	public void messageReceived(Message message) {
		int index = FormMain.instance.chatTabs.indexOfComponent(chatTabPanel);
		if(FormMain.instance.chatTabs.getSelectedIndex() != index) {
			FormMain.instance.chatTabs.setBackgroundAt(index, Color.RED);
		}

		if (message instanceof TextMessage) {
			TextMessage textMessage = (TextMessage) message;
			if (message.from.equals(User.getSYSTEM())) {
				addText(textMessage.content);
			} else {
				switch (textMessage.type) {
					case TextMessage.TYPE_CHAT:
						addText(textMessage.from.getDisplayName() + ": " + textMessage.content);
						break;
					case TextMessage.TYPE_ACTION:
						addText("* " + textMessage.from.getDisplayName() + " " + textMessage.content);
						break;
					case TextMessage.TYPE_EVENT:
						addText("**" + textMessage.content + "** [" + textMessage.from.getContextName() + "]");
						break;
				}
			}
		} else {
			//Well, erm....
		}
	}

	public void addText(String text) {
		text = chatLog.getText() + text + "\r\n";
		chatLog.setText(text);

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				chatLogScrollPane.getVerticalScrollBar().setValue(chatLogScrollPane.getVerticalScrollBar().getMaximum());
			}
		});
	}

	private class UserListDataModel implements ListModel<String> {
		private final HashSet<ListDataListener> listDataListeners = new HashSet<ListDataListener>();
		private final ArrayList<User> contents = new ArrayList<User>();
		private final HashMap<User, Integer> contentIndexes = new HashMap<User, Integer>();

		protected UserListDataModel(User[] users) {
			int i = 0;
			for (User clientUser : users) {
				contents.add(clientUser);
				contentIndexes.put(clientUser, i);
				i++;
			}
		}

		protected UserListDataModel(Collection<User> users) {
			int i = 0;
			for (User clientUser : users) {
				contents.add(clientUser);
				contentIndexes.put(clientUser, i);
				i++;
			}
		}

		protected UserListDataModel() {

		}

		@Override
		public int getSize() {
			return contents.size();
		}

		@Override
		public String getElementAt(int index) {
			return contents.get(index).getContextName();
		}

		@Override
		public void addListDataListener(ListDataListener l) {
			listDataListeners.add(l);
		}

		@Override
		public void removeListDataListener(ListDataListener l) {
			listDataListeners.remove(l);
		}

		protected void userNicknameChanged(User clientUser) {
			final Integer index = contentIndexes.get(clientUser);
			if (index == null) return;
			final ListDataEvent listDataEvent = new ListDataEvent(this, ListDataEvent.CONTENTS_CHANGED, index, index);
			for (ListDataListener l : listDataListeners) {
				l.contentsChanged(listDataEvent);
			}
		}

		protected void addUser(User clientUser) {
			final int newIndex;
			synchronized (contents) {
				newIndex = contents.size();
				contents.add(clientUser);
				contentIndexes.put(clientUser, newIndex);
			}
			final ListDataEvent listDataEvent = new ListDataEvent(this, ListDataEvent.INTERVAL_ADDED, newIndex, newIndex);
			for (ListDataListener l : listDataListeners) {
				l.intervalAdded(listDataEvent);
			}
		}

		protected void delUser(User clientUser) {
			final int oldIndex;
			synchronized (contents) {
				oldIndex = contentIndexes.remove(clientUser);
				contents.remove(oldIndex);
				for (int i = oldIndex; i < contents.size(); i++) {
					contentIndexes.put(contents.get(i), i);
				}
			}
			final ListDataEvent listDataEvent = new ListDataEvent(this, ListDataEvent.INTERVAL_ADDED, oldIndex, oldIndex);
			for (ListDataListener l : listDataListeners) {
				l.intervalRemoved(listDataEvent);
			}
		}
	}

	private UserListDataModel userListDataModel;

	public void addUserToList(User clientUser) {
		userListDataModel.addUser(clientUser);
	}

	public void removeUserFromList(User clientUser) {
		userListDataModel.delUser(clientUser);
	}

	public void setUserList(Collection<User> clientUsers) {
		userListDataModel = new UserListDataModel(clientUsers);
		userList.setModel(userListDataModel);
	}

	public void setUserList(User[] clientUsers) {
		userListDataModel = new UserListDataModel(clientUsers);
		userList.setModel(userListDataModel);
	}

	public void userNicknameChanged(User clientUser) {
		userListDataModel.userNicknameChanged(clientUser);
	}

	private ChatTabEntryDisabledThread chatTabEntryDisabledThread = null;

	private class ChatTabEntryDisabledThread extends Thread {
		private boolean enabled = true;
		private final int timeout;

		private ChatTabEntryDisabledThread(int timeout) {
			this.timeout = timeout;
		}

		@Override
		public void run() {
			chatEntry.setEnabled(false);
			sendButton.setEnabled(false);
			try {
				Thread.sleep(timeout);
			} catch (InterruptedException e) {
			}
			if (!enabled) return;
			chatEntry.setEnabled(true);
			sendButton.setEnabled(true);
		}
	}

	public void disableChatEntryFor(int millis) {
		if (millis <= 0) return;
		if (chatTabEntryDisabledThread != null) {
			chatTabEntryDisabledThread.enabled = false;
		}
		chatTabEntryDisabledThread = new ChatTabEntryDisabledThread(millis);
		chatTabEntryDisabledThread.start();
	}
}
