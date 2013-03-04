package me.draconia.chat.client.filetransfer;

import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.types.BinaryMessage;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.RandomAccessFile;

public class FileReceiver {
	private final File file;
	private final RandomAccessFile randomAccessFile;
	private final ClientUser recvFrom;
	private final long len;
	private long written = 0;

	private final Cipher cipher;
	private final SecretKey secretKey;

	public FileReceiver(BinaryMessage binaryMessage) {
		try {
			recvFrom = (ClientUser)binaryMessage.from;

			ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(binaryMessage.content);
			DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

			String fileName = dataInputStream.readUTF();
			if(fileName.indexOf('/') >= 0 || fileName.indexOf('\\') >= 0)
				throw new Error("Sorry, invalid!");

			len = dataInputStream.readLong();

			byte[] aesKey = new byte[16];
			dataInputStream.read(aesKey);
			secretKey = new SecretKeySpec(aesKey, "AES");
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			File tmpFile = new File("files/" + binaryMessage.from.login + "/");
			tmpFile.mkdirs();
			file = new File(tmpFile, fileName);
			randomAccessFile = new RandomAccessFile(file, "rw");
			randomAccessFile.setLength(len);
		} catch(Exception e) {
			e.printStackTrace();
			throw new Error("Wat?");
		}
	}

	public void receivedMessage(BinaryMessage binaryMessage) {
		if((!(binaryMessage.context instanceof ClientUser)) || binaryMessage.from != recvFrom) return;
		try {
			switch (binaryMessage.type) {
				case BinaryMessage.TYPE_FILE_DATA:
					receivedFileData(binaryMessage);
					break;
				case BinaryMessage.TYPE_FILE_END:
					receivedFileEnd(binaryMessage);
					break;
			}
		} catch(Exception e) {
			e.printStackTrace();
			throw new Error("Wat?");
		}
	}

	private final LongCodec longCodec = new LongCodec();
	private final IntCodec intCodec = new IntCodec();
	private final byte[] IV = new byte[16];

	private synchronized void receivedFileData(BinaryMessage binaryMessage) throws Exception {
		long packetPos = longCodec.toNum(binaryMessage.content, 0);
		int packetLen = intCodec.toNum(binaryMessage.content, 8);

		System.arraycopy(binaryMessage.content, 12, IV, 0, 16);

		cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));
		final byte[] decFileData = cipher.doFinal(binaryMessage.content, 28, packetLen);

		packetLen = decFileData.length;

		randomAccessFile.seek(packetPos);
		randomAccessFile.write(decFileData);
		written += packetLen;
		if(written >= len) {
			randomAccessFile.close();
			FormMain.instance.getChatTab(binaryMessage).addText("[FILE] Received " + file.getName());
		}
	}

	private void receivedFileEnd(BinaryMessage binaryMessage) throws Exception {

	}
}
