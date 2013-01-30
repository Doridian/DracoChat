package me.draconia.chat.client.otr;

import org.bouncycastle.jce.provider.JCEIESCipher;
import org.bouncycastle.jce.spec.IEKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class OTRECIES extends JCEIESCipher.ECIES {
    public void init(int mode, IEKeySpec ieKeySpec, AlgorithmParameterSpec algorithmParameterSpec) throws InvalidKeyException, InvalidAlgorithmParameterException {
        super.engineInit(mode, ieKeySpec, algorithmParameterSpec, new SecureRandom());
    }

    public void update(byte[] bytes) {
        super.engineUpdate(bytes, 0, bytes.length);
    }

    public byte[] doFinal(byte[] bytes) throws IllegalBlockSizeException, BadPaddingException {
        return super.engineDoFinal(bytes, 0, bytes.length);
    }
}
