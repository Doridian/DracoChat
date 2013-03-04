package me.draconia.chat.client.filetransfer;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.types.BinaryMessage;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;

public class FileSender {
	private final File file;
	private final FileInputStream fileInputStream;
	private final ClientUser sendTo;
	private long pos = 0;
	private long len;

	private final Cipher cipher;
	private SecretKey aesSecretKey;

	private final Thread fileSenderThread;

	private boolean boolFinished = false;
	public boolean isFinished() {
		return boolFinished;
	}

	public FileSender(ClientUser sendTo, File file) {
		if(file.isDirectory() || !file.exists())
			throw new Error("Wat?");

		this.file = file;
		this.sendTo = sendTo;

		try {
			this.fileInputStream = new FileInputStream(file);

			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			aesSecretKey = keyGenerator.generateKey();
			byte[] aesKey = aesSecretKey.getEncoded();
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			BinaryMessage binaryMessage = new BinaryMessage();
			binaryMessage.context = sendTo;
			binaryMessage.from = ClientLib.myUser;
			binaryMessage.type = BinaryMessage.TYPE_FILE_START;

			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);

			dataOutputStream.writeUTF(file.getName());

			len = file.length();
			dataOutputStream.writeLong(len);

			dataOutputStream.write(aesKey);

			dataOutputStream.flush();
			byteArrayOutputStream.flush();
			binaryMessage.content = byteArrayOutputStream.toByteArray();
			dataOutputStream.close();

			ClientLib.sendEncryptableMessage(binaryMessage, false);
		} catch (Exception e) {
			e.printStackTrace();
			throw new Error("Wat?");
		}

		fileSenderThread = new Thread() {
			@Override
			public void run() {
				processFileTransfer();
				boolFinished = true;
			}
		};
		fileSenderThread.start();
	}

	private final LongCodec longCodec = new LongCodec();
	private final IntCodec intCodec = new IntCodec();
	private static final int PACKET_SIZE = 4096;

	private void processFileTransfer() {
		while(pos < len) {
			sendFileData();
		}
		try {
			fileInputStream.close();
		} catch (Exception e) { }
		sendFileEnd();
	}

	private final byte[] packetData = new byte[PACKET_SIZE + 32 + 8 + 8 + 16];
	private final byte[] fileData = new byte[PACKET_SIZE];

	private synchronized void sendFileData() {
		try {
			int readLen = fileInputStream.read(fileData, 0, PACKET_SIZE);
			if(readLen < 1) return;

			cipher.init(Cipher.ENCRYPT_MODE, aesSecretKey);
			final byte[] encFileData = cipher.doFinal(fileData, 0, readLen);

			System.arraycopy(cipher.getIV(), 0, packetData, 12, 16);

			System.arraycopy(encFileData, 0, packetData, 28, encFileData.length);
			System.arraycopy(longCodec.toBytes(pos), 0, packetData, 0, 8);
			System.arraycopy(intCodec.toBytes(encFileData.length), 0, packetData, 8, 4);

			pos += readLen;

			BinaryMessage binaryMessage = new BinaryMessage();
			binaryMessage.context = sendTo;
			binaryMessage.from = ClientLib.myUser;
			binaryMessage.type = BinaryMessage.TYPE_FILE_DATA;
			binaryMessage.content = packetData;

			ClientLib.sendMessage(binaryMessage, false);
		} catch (Exception e) {
			e.printStackTrace();
			throw new Error("Wat?");
		}
	}

	private void sendFileEnd() {
		BinaryMessage binaryMessage = new BinaryMessage();
		binaryMessage.context = sendTo;
		binaryMessage.from = ClientLib.myUser;
		binaryMessage.type = BinaryMessage.TYPE_FILE_END;
		binaryMessage.content = new byte[0];
		ClientLib.sendEncryptableMessage(binaryMessage, false);
	}
}
