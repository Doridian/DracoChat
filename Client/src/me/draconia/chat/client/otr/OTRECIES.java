package me.draconia.chat.client.otr;

import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jce.provider.JCEIESCipher;
import org.bouncycastle.jce.spec.IEKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class OTRECIES extends JCEIESCipher {
	public OTRECIES() {
		super(new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest())));
	}

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
