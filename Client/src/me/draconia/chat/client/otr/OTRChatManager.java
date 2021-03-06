package me.draconia.chat.client.otr;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.gui.ChatTab;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.types.BinaryMessage;
import me.draconia.chat.types.Message;
import me.draconia.chat.types.TextMessage;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.jboss.netty.channel.ChannelFutureListener;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

public class OTRChatManager {
	private final static HashMap<ClientUser, PublicKey> userKeys = new HashMap<ClientUser, PublicKey>();

	private static class MessageInfo {
		Message message;
		ChannelFutureListener channelFutureListener;

		MessageInfo(Message message, ChannelFutureListener channelFutureListener) {
			this.message = message;
			this.channelFutureListener = channelFutureListener;
		}
	}

	private final static HashMap<ClientUser, Queue<MessageInfo>> outgoingMessageQueue = new HashMap<ClientUser, Queue<MessageInfo>>();
	private final static HashMap<ClientUser, Queue<BinaryMessage>> incomingMessageQueue = new HashMap<ClientUser, Queue<BinaryMessage>>();

	private static final SecureRandom secureRandom = new SecureRandom();

	public static void clearQueuesFor(ClientUser clientUser) {
		outgoingMessageQueue.remove(clientUser);
		incomingMessageQueue.remove(clientUser);
	}

	public static void initWith(ClientUser clientUser) {
		BinaryMessage binaryMessage = new BinaryMessage();
		binaryMessage.context = clientUser;
		binaryMessage.type = BinaryMessage.TYPE_OTR_PUBKEY_1;
		binaryMessage.content = OTRKeyGen.otrPublicKey.getEncoded();
		ClientLib.sendMessage(binaryMessage);
	}

	public static boolean isOTR(ClientUser otherUser) {
		return userKeys.containsKey(otherUser);
	}

	public static void sendMessage(Message message) {
		sendMessage(message, null);
	}

	public static void sendMessage(Message message, boolean showReceived) {
		sendMessage(message, null, showReceived);
	}

	public static void sendMessage(Message message, ChannelFutureListener channelFutureListener) {
		sendMessage(message, channelFutureListener, true);
	}

	public static void sendMessage(Message message, ChannelFutureListener channelFutureListener, boolean showReceived) {
		if (!(message.context instanceof ClientUser)) {
			throw new Error("Only PMs can be encrypted");
		}

		ClientUser clientUser = (ClientUser) message.context;
		PublicKey publicKey = userKeys.get(clientUser);
		if (publicKey == null) {
			FormMain.instance.getChatTab(message.context).addText("[OTR] Trying to establish OTR session...");

			Queue<MessageInfo> messages = outgoingMessageQueue.get(clientUser);
			if (messages == null) {
				messages = new ConcurrentLinkedQueue<MessageInfo>();
				outgoingMessageQueue.put(clientUser, messages);
			}
			messages.add(new MessageInfo(message, channelFutureListener));
			initWith(clientUser);
			return;
		}

		BinaryMessage binaryMessage = new BinaryMessage();
		binaryMessage.context = message.context;
		binaryMessage.type = BinaryMessage.TYPE_OTR_MESSGAE;

		try {
			final byte[] d = new byte[16];
			final byte[] e = new byte[16];
			secureRandom.nextBytes(d);
			secureRandom.nextBytes(e);
			final IESParameterSpec iesParameterSpec = new IESParameterSpec(d, e, 128);

			OTRECIES encryptionCipher = new OTRECIES();
			IEKeySpec ieKeySpec = new IEKeySpec(OTRKeyGen.otrPrivateKey, publicKey);
			encryptionCipher.init(Cipher.ENCRYPT_MODE, ieKeySpec, iesParameterSpec);
			byte messageClass = (message instanceof TextMessage) ? (byte) 0 : (byte) 1;

			encryptionCipher.update(new byte[]{messageClass, message.type});

			final byte[] encryptedContent;
			if (messageClass == 0) {
				encryptedContent = encryptionCipher.doFinal(((TextMessage) message).content.getBytes("UTF-8"));
			} else {
				encryptedContent = encryptionCipher.doFinal(((BinaryMessage) message).content);
			}
			binaryMessage.content = new byte[encryptedContent.length + 32];
			System.arraycopy(d, 0, binaryMessage.content, 0, 16);
			System.arraycopy(e, 0, binaryMessage.content, 16, 16);
			System.arraycopy(encryptedContent, 0, binaryMessage.content, 32, encryptedContent.length);
		} catch (Exception e) {
			e.printStackTrace();
			throw new Error("ERROR");
		}

		ClientLib.sendMessage(binaryMessage, channelFutureListener, false);
		if(showReceived) {
			FormMain.instance.getChatTab(message).messageReceived(message);
		}
	}

	public static void messageReceived(BinaryMessage binaryMessage) {
		if (!(binaryMessage.context instanceof ClientUser)) {
			return;
		}

		switch (binaryMessage.type) {
			case BinaryMessage.TYPE_OTR_PUBKEY_1:
				BinaryMessage responseMessage = new BinaryMessage();
				responseMessage.context = binaryMessage.from;
				responseMessage.type = BinaryMessage.TYPE_OTR_PUBKEY_2;
				responseMessage.content = OTRKeyGen.otrPublicKey.getEncoded();
				ClientLib.sendMessage(responseMessage);
			case BinaryMessage.TYPE_OTR_PUBKEY_2:
				ClientUser from = (ClientUser) binaryMessage.from;
				PublicKey oldKey = userKeys.get(from);
				if (oldKey != null) {
					if (Arrays.equals(oldKey.getEncoded(), binaryMessage.content)) return;
				}
				try {
					PublicKey newKey = KeyFactory.getInstance("EC", OTRKeyGen.provider).generatePublic(new X509EncodedKeySpec(binaryMessage.content));
					final ChatTab chatTab = FormMain.instance.getChatTab(from);
					chatTab.addText("[OTR] Session established");
					chatTab.addText("[OTR] Your PublicKey is " + OTRKeyGen.getFingerprint(OTRKeyGen.otrPublicKey));
					chatTab.addText("[OTR] Partner PublicKey is " + OTRKeyGen.getFingerprint(newKey));
					chatTab.addText("[OTR] PLEASE VERIFY THIS KEY WITH EXTERNAL MEANS BEFORE PROCEEDING YOUR CHAT");
					userKeys.put(from, newKey);
					chatTab.disableChatEntryFor(5000);
				} catch (Exception e) {
					e.printStackTrace();
					return;
				}
				Queue<MessageInfo> messages = outgoingMessageQueue.remove(from);
				if (messages != null) {
					for (MessageInfo message : messages) {
						sendMessage(message.message, message.channelFutureListener);
					}
				}
				Queue<BinaryMessage> binaryMessages = incomingMessageQueue.remove(from);
				if (binaryMessages != null) {
					PublicKey publicKey = userKeys.get(from);
					for (BinaryMessage message : binaryMessages) {
						receivedMessage(publicKey, message);
					}
				}
				break;

			case BinaryMessage.TYPE_OTR_MESSGAE:
				try {
					ClientUser clientUser = (ClientUser) binaryMessage.from;
					PublicKey publicKey = userKeys.get(clientUser);
					if (publicKey == null) {
						Queue<BinaryMessage> messageQueue = incomingMessageQueue.get(clientUser);
						if (messageQueue == null) {
							messageQueue = new ConcurrentLinkedQueue<BinaryMessage>();
							incomingMessageQueue.put(clientUser, messageQueue);
						}
						messageQueue.add(binaryMessage);
						initWith(clientUser);
						return;
					} else {
						receivedMessage(publicKey, binaryMessage);
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
				break;

			case BinaryMessage.TYPE_OTR_ERROR:
				clearQueuesFor((ClientUser) binaryMessage.context);
				FormMain.instance.getChatTab(binaryMessage.context).addText("[OTR] Error");
				break;
		}
	}

	private static void receivedMessage(PublicKey publicKey, BinaryMessage binaryMessage) {
		try {
			OTRECIES decryptionCipher = new OTRECIES();

			byte[] d = Arrays.copyOfRange(binaryMessage.content, 0, 16);
			byte[] e = Arrays.copyOfRange(binaryMessage.content, 16, 32);
			IESParameterSpec iesParameterSpec = new IESParameterSpec(d, e, 128);

			IEKeySpec ieKeySpec = new IEKeySpec(OTRKeyGen.otrPrivateKey, publicKey);
			decryptionCipher.init(Cipher.DECRYPT_MODE, ieKeySpec, iesParameterSpec);
			Message message;
			byte[] payload = decryptionCipher.doFinal(Arrays.copyOfRange(binaryMessage.content, 32, binaryMessage.content.length));
			final byte msgType = payload[1];
			final byte msgClass = payload[0];
			payload = Arrays.copyOfRange(payload, 2, payload.length);
			switch (msgClass) {
				case 0:
					TextMessage textMessage = new TextMessage();
					textMessage.content = new String(payload, "UTF-8");
					message = textMessage;
					if (msgType == TextMessage.TYPE_SYSTEM || msgType == TextMessage.TYPE_SYSTEM_ERROR) {
						return;
					}
					break;
				case 1:
					BinaryMessage decodedBinaryMessage = new BinaryMessage();
					decodedBinaryMessage.content = payload;
					message = decodedBinaryMessage;
					if (msgType == BinaryMessage.TYPE_OTR_MESSGAE || msgType == BinaryMessage.TYPE_OTR_PUBKEY_1 || msgType == BinaryMessage.TYPE_OTR_PUBKEY_2) {
						return;
					}
					break;
				default:
					return;
			}
			message.type = msgType;
			message.timestamp = binaryMessage.timestamp;
			message.context = binaryMessage.context;
			message.from = binaryMessage.from;
			message.encrypted = true;
			FormMain.instance.getChatTab(message).messageReceived(message);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
