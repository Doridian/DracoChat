package me.draconia.chat.client.gui;

import me.draconia.chat.client.ClientLib;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.net.InetSocketAddress;

public class DialogLogin extends JDialog {
	private JPanel contentPane;
	private JButton buttonOK;
	private JButton buttonCancel;
	private JTextField textUsername;
	private JPasswordField textPassword;
	private JTextField textHost;

	public DialogLogin(Frame owner) {
		super(owner, "DracoChat Login");

		setContentPane(contentPane);
		setModal(true);
		getRootPane().setDefaultButton(buttonOK);

		buttonOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				onOK();
			}
		});

		buttonCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				onCancel();
			}
		});

// call onCancel() when cross is clicked
		setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				onCancel();
			}
		});

// call onCancel() on ESCAPE
		contentPane.registerKeyboardAction(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				onCancel();
			}
		}, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
	}

	private void onOK() {
		final String host = textHost.getText();
		final InetSocketAddress inetSocketAddress;
		final int colon = host.indexOf(':');
		if (colon >= 0) {
			inetSocketAddress = new InetSocketAddress(host.substring(0, colon), Integer.parseInt(host.substring(colon + 1)));
		} else {
			inetSocketAddress = new InetSocketAddress(host, 13137);
		}
		ClientLib.myHost = inetSocketAddress;
		ClientLib.myLogin = textUsername.getText();
		ClientLib.setPassword(new String(textPassword.getPassword()));
		ClientLib.login();
		dispose();
	}

	private void onCancel() {
		FormMain.exit();
		dispose();
	}
}
