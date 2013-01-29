package me.draconia.chat.client.gui;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.ClientUser;
import me.draconia.chat.client.otr.OTRChatManager;
import me.draconia.chat.commands.BaseClientCommand;
import me.draconia.chat.net.packets.PacketNickgetRequest;
import me.draconia.chat.types.*;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

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
        if(!(relatedContext instanceof Channel)) {
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
            public void keyTyped(KeyEvent e) { }

            @Override
            public void keyPressed(KeyEvent e) {
                if(e.getKeyCode() == KeyEvent.VK_ENTER) {
                    sendChat();
                }
            }

            @Override
            public void keyReleased(KeyEvent e) { }
        });

        if(relatedContext instanceof ClientUser) {
            ClientUser relatedUser = (ClientUser)relatedContext;
            if(relatedUser.getNickname() == null) {
                PacketNickgetRequest packetNickgetRequest = new PacketNickgetRequest();
                packetNickgetRequest.users = new User[] { relatedUser };
                ClientLib.sendPacket(packetNickgetRequest);
            }
        }
    }

    private void sendChat() {
        final String text = chatEntry.getText();
        chatEntry.setText("");

        if(text.charAt(0) == '/' && BaseClientCommand.runCommand(ClientLib.myUser, relatedContext, text.substring(1))) {
            return;
        }

        TextMessage message = new TextMessage();
        message.content = text;
        message.type = TextMessage.TYPE_CHAT;
        message.context = relatedContext;
        ClientLib.sendEncryptableMessage(message);
        messageReceived(message);
    }

    public void messageReceived(Message message) {
        if(message instanceof TextMessage) {
            TextMessage textMessage = (TextMessage)message;
            if(message.from instanceof SystemUser) {
                addText(textMessage.content);
            } else {
                switch (textMessage.type) {
                    case TextMessage.TYPE_CHAT:
                        addText(textMessage.from.getContextName() + ": " + textMessage.content);
                        break;
                    case TextMessage.TYPE_ACTION:
                        addText("* " + textMessage.from.getContextName() + " " + textMessage.content);
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
}
