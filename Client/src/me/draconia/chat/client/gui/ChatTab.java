package me.draconia.chat.client.gui;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.filetransfer.FileReceiver;
import me.draconia.chat.client.filetransfer.FileSender;
import me.draconia.chat.client.filetransfer.IntCodec;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.commands.BaseClientCommand;
import me.draconia.chat.types.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.File;
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
	private JLabel statusBar;

	private final MessageContext relatedContext;

	private HashMap<Integer, FileReceiver> fileReceivers = new HashMap<Integer, FileReceiver>();

	public ChatTab(final MessageContext relatedContext) {
		this.relatedContext = relatedContext;
		if (!(relatedContext instanceof Channel)) {
			userList.setVisible(false);
		}

		if(relatedContext instanceof Channel) {
			typingStatusTextHook = new ChannelTypingStatusTextHook();
		} else if(relatedContext instanceof User) {
			typingStatusTextHook = new UserTypingStatusTextHook();

			final DropTarget fileTransferDropTarget = new DropTarget() {
				@Override
				public synchronized void drop(DropTargetDropEvent dtde) {
					try {
						Transferable transferable = dtde.getTransferable();
						if(transferable.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
							dtde.acceptDrop(DnDConstants.ACTION_COPY);
							java.util.List<File> files = (java.util.List<File>)transferable.getTransferData(DataFlavor.javaFileListFlavor);
							for(File file : files) {
								FileSender.sendFile((ClientUser)relatedContext, file);
							}
							dtde.dropComplete(true);
						}
					} catch (Exception e) {
						e.printStackTrace();
					}
				}

				@Override
				public synchronized void dragEnter(DropTargetDragEvent dtde) {
					if(dtde.getTransferable().isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
						dtde.acceptDrag(DnDConstants.ACTION_COPY);
					}
				}

				@Override
				public synchronized void dragOver(DropTargetDragEvent dtde) {
					if(dtde.getTransferable().isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
						dtde.acceptDrag(DnDConstants.ACTION_COPY);
					}
				}
			};

			chatEntry.setDropTarget(fileTransferDropTarget);
			chatTabPanel.setDropTarget(fileTransferDropTarget);
			chatLog.setDropTarget(fileTransferDropTarget);
		} else {
			typingStatusTextHook = null;
		}

		if(typingStatusTextHook != null) {
			addStatusTextHook(typingStatusTextHook);
		}

		sendButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				sendChat();
			}
		});
		chatEntry.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				refreshTypingState();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				refreshTypingState();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				refreshTypingState();
			}

			private void refreshTypingState() {
				if (chatEntry.getText().length() > 0) {
					setOwnTypingState(1);
				} else {
					setOwnTypingState(0);
				}
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

		new Thread() {
			@Override
			public void run() {
				try {
					Thread.sleep(1000);
				} catch (Exception e) { }
				while(statusBar.isValid()) {
					refreshStatusText();
					try {
						Thread.sleep(500);
					} catch (Exception e) { }
				}
			}
		}.start();

		new Thread() {
			@Override
			public void run() {
				try {
					Thread.sleep(1000);
				} catch (Exception e) { }
				while(statusBar.isValid()) {
					if(ownTypingState == 1 && typingStateLastSet < System.currentTimeMillis() - 10000) {
						setOwnTypingState(2);
					}
					try {
						Thread.sleep(100);
					} catch (InterruptedException e) { }
				}
			}
		}.start();
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

	private final IntCodec intCodec = new IntCodec();

	public void messageReceived(Message message) {
		if (message instanceof TextMessage) {
			if(!FormMain.instance.rootFrame.isFocused()) {
				Toolkit.getDefaultToolkit().beep();
			}

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
		} else if(message instanceof BinaryMessage) {
			final BinaryMessage binaryMessage = (BinaryMessage)message;
			if(message.type == BinaryMessage.TYPE_FILE_START) {
				final int fileID = intCodec.toNum(binaryMessage.content, 0);
				if(fileReceivers.containsKey(fileID))
					return;

				new Thread() {
					@Override
					public void run() {
						try {
							fileReceivers.put(fileID, new FileReceiver(binaryMessage));
						} catch (Exception e) { }
					}
				}.start();
			} else if(message.type == BinaryMessage.TYPE_FILE_DATA || message.type == BinaryMessage.TYPE_FILE_END) {
				final int fileID = intCodec.toNum(binaryMessage.content, 0);
				FileReceiver fileReceiver = fileReceivers.get(fileID);
				if(fileReceiver != null)
					fileReceiver.receivedMessage(binaryMessage);

				if(message.type == BinaryMessage.TYPE_FILE_END) {
					fileReceivers.remove(fileID);
				}
			} else if(message.type == BinaryMessage.TYPE_FILE_START_RESPONSE) {
				FileSender.fileTransferAckNackReceived(binaryMessage);
			} else if(message.type == BinaryMessage.TYPE_TYPING_STATE) {
				if(typingStatusTextHook != null) {
					typingStatusTextHook.setTypingState(message.from, binaryMessage.content[0]);
				}
			}
		}
	}

	public void addText(String text) {
		int index = FormMain.instance.chatTabs.indexOfComponent(chatTabPanel);
		if(FormMain.instance.chatTabs.getSelectedIndex() != index) {
			FormMain.instance.chatTabs.setBackgroundAt(index, Color.RED);
		}

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

	public interface StatusTextHook {
		public String getStatusText();
	}

	private byte ownTypingState = 0;
	private long typingStateLastSet = 0;
	private void setOwnTypingState(int state) {
		typingStateLastSet = System.currentTimeMillis();

		if(state == ownTypingState)
			return;
		ownTypingState = (byte)state;

		BinaryMessage binaryMessage = new BinaryMessage();
		binaryMessage.context = relatedContext;
		binaryMessage.from = ClientLib.myUser;
		binaryMessage.type = BinaryMessage.TYPE_TYPING_STATE;
		binaryMessage.content = new byte[] { ownTypingState };
		ClientLib.sendEncryptableMessage(binaryMessage, false);
	}

	private TypingStatusTextHook typingStatusTextHook;

	private interface TypingStatusTextHook extends StatusTextHook {
		public void setTypingState(User user, byte typingState);
	}

	private class UserTypingStatusTextHook implements TypingStatusTextHook {
		private byte typingState = 0;

		@Override
		public String getStatusText() {
			switch (typingState) {
				default:
				case 0:
					return null;
				case 1:
					return ((User)relatedContext).getNickname() + " is typing";
				case 2:
					return ((User)relatedContext).getNickname() + " has entered text";
			}
		}

		@Override
		public void setTypingState(User user, byte typingState) {
			this.typingState = typingState;
		}
	}

	private class ChannelTypingStatusTextHook implements TypingStatusTextHook {
		@Override
		public String getStatusText() {
			return null;
		}

		@Override
		public void setTypingState(User user, byte typingState) {

		}
	}

	private void refreshStatusText() {
		StringBuilder statusText = new StringBuilder();
		boolean isPop = false;
		for(StatusTextHook statusTextHook : statusTextHooks) {
			String res = statusTextHook.getStatusText();
			if(res != null && !res.isEmpty()) {
				if(!isPop) {
					isPop = true;
				} else {
					statusText.append(", ");
				}
				statusText.append(res);
			}
		}
		String sbText = statusText.toString();
		if(sbText.isEmpty()) {
			statusBar.setText("Idle");
		} else {
			statusBar.setText(statusText.toString());
		}
	}

	private final HashSet<StatusTextHook> statusTextHooks = new HashSet<StatusTextHook>();

	public void addStatusTextHook(StatusTextHook statusTextHook) {
		synchronized (statusTextHooks) {
			statusTextHooks.add(statusTextHook);
		}
	}

	public void removeStatusTextHook(StatusTextHook statusTextHook) {
		synchronized (statusTextHooks) {
			statusTextHooks.remove(statusTextHook);
		}
	}
}
