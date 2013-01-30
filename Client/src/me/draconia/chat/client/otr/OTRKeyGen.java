package me.draconia.chat.client.otr;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.gui.FormMain;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.IESParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.*;
import java.security.*;

public class OTRKeyGen {
    public static final Provider provider;

    static PrivateKey otrPrivateKey;
    static PublicKey otrPublicKey;

    public static final ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
    public static final IESParameterSpec iesParameterSpec = new IESParameterSpec(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 }, 128);

    private static final byte[] SALT = { 11, 38, 58, 18, 58, 18, 125, -110 };
    private static final int ITERATIONS = 64;

    static {
        provider = new BouncyCastleProvider();
        generateKey();
    }

    public static void generateKey() {
        Cipher keyPairEncryptCipher;
        Key keyPairEncryptKey;
        PBEParameterSpec keyPairEncryptionParameters;
        try {
            SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithSHAAndTwofish-CBC", provider);
            PBEKeySpec keySpec = new PBEKeySpec(ClientLib.getPassword().toCharArray());
            keyPairEncryptKey = kf.generateSecret(keySpec);
            keyPairEncryptCipher = Cipher.getInstance("PBEWithSHAAndTwofish-CBC", provider);
            keyPairEncryptionParameters = new PBEParameterSpec(SALT, ITERATIONS);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        KeyPair keyPair = null;
        try {
            keyPairEncryptCipher.init(Cipher.DECRYPT_MODE, keyPairEncryptKey, keyPairEncryptionParameters);
            ObjectInputStream objectInputStream = new ObjectInputStream(new CipherInputStream(new FileInputStream(ClientLib.myLogin + ".key"), keyPairEncryptCipher));
            keyPair = (KeyPair)objectInputStream.readObject();
            objectInputStream.close();
        } catch (FileNotFoundException e) {
            //IGNORE
        } catch(Exception e) {
            e.printStackTrace();
        }

        if(keyPair == null) {
            FormMain.genericChatTab.addText("[OTR] Generating new key");
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECIES", provider);
                keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());
                keyPair = keyPairGenerator.generateKeyPair();
            } catch(Exception e) {
                e.printStackTrace();
                return;
            }

            try {
                keyPairEncryptCipher.init(Cipher.ENCRYPT_MODE, keyPairEncryptKey, keyPairEncryptionParameters);
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(new CipherOutputStream(new FileOutputStream(ClientLib.myLogin + ".key"), keyPairEncryptCipher));
                objectOutputStream.writeObject(keyPair);
                objectOutputStream.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        otrPrivateKey = keyPair.getPrivate();
        otrPublicKey = keyPair.getPublic();
    }

    public static String getFingerprint(PublicKey publicKey) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.update(publicKey.getEncoded());
            byte[] hash = messageDigest.digest();

            StringBuilder hexBuilder = new StringBuilder();
            int imax = hash.length - 1;
            for(int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xFF & hash[i]);
                if (hex.length() == 1) {
                    hexBuilder.append('0');
                }
                hexBuilder.append(hex);
                if(i < imax) {
                    hexBuilder.append(':');
                }
            }
            return hexBuilder.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "ERROR";
        }
    }
}
