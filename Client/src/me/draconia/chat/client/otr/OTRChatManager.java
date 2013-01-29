package me.draconia.chat.client.otr;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.ClientUser;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.types.BinaryMessage;
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

    private static HashMap<ClientUser, Queue<TextMessage>> messageQueue = new HashMap<ClientUser, Queue<TextMessage>>();

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

    public static void sendMessage(TextMessage textMessage) {
        if(!(textMessage.context instanceof ClientUser)) {
            throw new Error("Only PMs can be encrypted");
        }

        ClientUser clientUser = (ClientUser)textMessage.context;
        PublicKey publicKey = userKeys.get(clientUser);
        if(publicKey == null) {
            Queue<TextMessage> messages = messageQueue.get(clientUser);
            if(messages == null) {
                messages = new ConcurrentLinkedQueue<TextMessage>();
                messageQueue.put(clientUser, messages);
            }
            messages.add(textMessage);
            initWith(clientUser);
            return;
        }

        BinaryMessage binaryMessage = new BinaryMessage();
        binaryMessage.context = textMessage.context;
        binaryMessage.type = BinaryMessage.TYPE_OTR_MESSGAE;

        try {
            Cipher encryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", OTRKeyGen.provider);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptionCipher.update(new byte[] { textMessage.type });
            encryptionCipher.update(textMessage.content.getBytes("UTF-8"));
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
                Queue<TextMessage> messages = messageQueue.remove(from);
                if(messages != null) {
                    for(TextMessage message : messages) {
                        sendMessage(message);
                    }
                }
                break;

            case BinaryMessage.TYPE_OTR_MESSGAE:
                try {
                    Cipher decryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", OTRKeyGen.provider);
                    decryptionCipher.init(Cipher.DECRYPT_MODE, OTRKeyGen.otrPrivateKey);
                    decryptionCipher.update(binaryMessage.content);
                    TextMessage textMessage = new TextMessage();
                    byte[] text = decryptionCipher.doFinal();
                    textMessage.type = text[0];
                    textMessage.content = new String(Arrays.copyOfRange(text, 1, text.length), "UTF-8");
                    textMessage.timestamp = binaryMessage.timestamp;
                    textMessage.context = binaryMessage.context;
                    textMessage.from = binaryMessage.from;
                    textMessage.encrypted = true;
                    if(textMessage.type == TextMessage.TYPE_SYSTEM || textMessage.type == TextMessage.TYPE_SYSTEM_ERROR) {
                        return;
                    }
                    FormMain.instance.getChatTab(textMessage.context).messageReceived(textMessage);
                } catch(Exception e) {
                    e.printStackTrace();
                }
                break;
        }
    }
}
