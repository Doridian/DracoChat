package me.draconia.chat.client.otr;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.ClientUser;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.types.BinaryMessage;
import me.draconia.chat.types.Message;
import me.draconia.chat.types.TextMessage;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

public class OTRChatManager {
    private static HashMap<ClientUser, PublicKey> userKeys = new HashMap<ClientUser, PublicKey>();

    private static HashMap<ClientUser, Queue<Message>> messageQueue = new HashMap<ClientUser, Queue<Message>>();

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
        if(!(message.context instanceof ClientUser)) {
            throw new Error("Only PMs can be encrypted");
        }

        ClientUser clientUser = (ClientUser)message.context;
        PublicKey publicKey = userKeys.get(clientUser);
        if(publicKey == null) {
            Queue<Message> messages = messageQueue.get(clientUser);
            if(messages == null) {
                messages = new ConcurrentLinkedQueue<Message>();
                messageQueue.put(clientUser, messages);
            }
            messages.add(message);
            initWith(clientUser);
            return;
        }

        BinaryMessage binaryMessage = new BinaryMessage();
        binaryMessage.context = message.context;
        binaryMessage.type = BinaryMessage.TYPE_OTR_MESSGAE;

        try {
            Cipher encryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", OTRKeyGen.provider);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte messageClass = (message instanceof TextMessage) ? (byte)0 : (byte)1;
            encryptionCipher.update(new byte[] { messageClass, message.type });
            if(messageClass == 0) {
                encryptionCipher.update(((TextMessage)message).content.getBytes("UTF-8"));
            } else {
                encryptionCipher.update(((BinaryMessage)message).content);
            }
            binaryMessage.content = encryptionCipher.doFinal();
        } catch(Exception e) {
            e.printStackTrace();
            throw new Error("ERROR");
        }

        ClientLib.sendMessage(binaryMessage);
    }

    public static void messageReceived(BinaryMessage binaryMessage) {
        switch (binaryMessage.type) {
            case BinaryMessage.TYPE_OTR_PUBKEY_1:
                BinaryMessage responseMessage = new BinaryMessage();
                responseMessage.context = binaryMessage.from;
                responseMessage.type = BinaryMessage.TYPE_OTR_PUBKEY_2;
                responseMessage.content = OTRKeyGen.otrPublicKey.getEncoded();
                ClientLib.sendMessage(responseMessage);
            case BinaryMessage.TYPE_OTR_PUBKEY_2:
                ClientUser from = (ClientUser)binaryMessage.from;
                PublicKey oldKey = userKeys.get(from);
                if(oldKey != null) {
                    if(Arrays.equals(oldKey.getEncoded(), binaryMessage.content)) return;
                }
                try {
                    PublicKey newKey = KeyFactory.getInstance("RSA", OTRKeyGen.provider).generatePublic(new X509EncodedKeySpec(binaryMessage.content));
                    FormMain.instance.getChatTab(from).addText("[OTR] Your PublicKey is " + OTRKeyGen.getFingerprint(OTRKeyGen.otrPublicKey));
                    FormMain.instance.getChatTab(from).addText("[OTR] Partner PublicKey is " + OTRKeyGen.getFingerprint(newKey));
                    userKeys.put(from, newKey);
                } catch(Exception e) {
                    e.printStackTrace();
                }
                Queue<Message> messages = messageQueue.remove(from);
                if(messages != null) {
                    for(Message message : messages) {
                        sendMessage(message);
                    }
                }
                break;

            case BinaryMessage.TYPE_OTR_MESSGAE:
                try {
                    Cipher decryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", OTRKeyGen.provider);
                    decryptionCipher.init(Cipher.DECRYPT_MODE, OTRKeyGen.otrPrivateKey);
                    decryptionCipher.update(binaryMessage.content);
                    Message message;
                    byte[] payload = decryptionCipher.doFinal();
                    final byte msgType = payload[1];
                    final byte msgClass = payload[0];
                    payload = Arrays.copyOfRange(payload, 2, payload.length);
                    switch (msgClass) {
                        case 0:
                            TextMessage textMessage = new TextMessage();
                            textMessage.content = new String(payload, "UTF-8");
                            message = textMessage;
                            if(msgType == TextMessage.TYPE_SYSTEM || msgType == TextMessage.TYPE_SYSTEM_ERROR) {
                                return;
                            }
                            break;
                        case 1:
                            BinaryMessage decodedBinaryMessage = new BinaryMessage();
                            decodedBinaryMessage.content = payload;
                            message = decodedBinaryMessage;
                            if(msgType == BinaryMessage.TYPE_OTR_MESSGAE || msgType == BinaryMessage.TYPE_OTR_PUBKEY_1 || msgType == BinaryMessage.TYPE_OTR_PUBKEY_2) {
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
                    FormMain.instance.getChatTab(message.context).messageReceived(message);
                } catch(Exception e) {
                    e.printStackTrace();
                }
                break;
        }
    }
}
