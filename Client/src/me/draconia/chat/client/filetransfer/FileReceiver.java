package me.draconia.chat.client.filetransfer;

import me.draconia.chat.client.gui.ChatTab;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.types.BinaryMessage;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.RandomAccessFile;

public class FileReceiver implements ChatTab.StatusTextHook {
	private final File file;
	private final RandomAccessFile randomAccessFile;
	private final ClientUser recvFrom;
	private final long len;
	private long written = 0;

	private final PaddedBufferedBlockCipher cipher;
	private KeyParameter aesSecretKey;

	public FileReceiver(BinaryMessage binaryMessage) {
		try {
			recvFrom = (ClientUser)binaryMessage.from;

			ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(binaryMessage.content);
			DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

			String fileName = dataInputStream.readUTF();
			if(fileName.indexOf('/') >= 0 || fileName.indexOf('\\') >= 0)
				throw new Error("Sorry, invalid!");

			len = dataInputStream.readLong();

			byte[] aesKey = new byte[32];
			dataInputStream.read(aesKey);
			aesSecretKey = new KeyParameter(aesKey);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

			File tmpFile = new File("files/" + binaryMessage.from.login + "/");
			tmpFile.mkdirs();
			file = new File(tmpFile, fileName);
			randomAccessFile = new RandomAccessFile(file, "rw");
			randomAccessFile.setLength(len);
		} catch(Exception e) {
			e.printStackTrace();
			throw new Error("Wat?");
		}

		FormMain.instance.getChatTab(binaryMessage).addStatusTextHook(this);
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
	private byte[] decFileData = new byte[0];

	private synchronized void receivedFileData(BinaryMessage binaryMessage) throws Exception {
		long packetPos = longCodec.toNum(binaryMessage.content, 0);
		int packetLen = intCodec.toNum(binaryMessage.content, 8);

		cipher.init(false, aesSecretKey);
		packetLen = cipher.getOutputSize(packetLen);
		if(decFileData.length < packetLen) {
			decFileData = new byte[packetLen];
		}

		packetLen = cipher.processBytes(binaryMessage.content, 12, packetLen, decFileData, 0);
		packetLen += cipher.doFinal(decFileData, packetLen);

		randomAccessFile.seek(packetPos);
		randomAccessFile.write(decFileData, 0, packetLen);
		written += packetLen;
		if(written >= len) {
			randomAccessFile.close();
			ChatTab chatTab = FormMain.instance.getChatTab(binaryMessage);
			chatTab.addText("[FILE] Received " + file.getName());
			chatTab.removeStatusTextHook(this);
		}
	}

	private void receivedFileEnd(BinaryMessage binaryMessage) throws Exception {

	}

	@Override
	public String getStatusText() {
		return "Receiving " + file.getName() + " [" + ((int)((((float)written) / ((float)len)) * 100)) + "%]";
	}
}
