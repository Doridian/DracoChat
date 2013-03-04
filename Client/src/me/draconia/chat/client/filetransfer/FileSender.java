package me.draconia.chat.client.filetransfer;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.gui.ChatTab;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.types.BinaryMessage;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;

public class FileSender implements ChatTab.StatusTextHook {
	private final File file;
	private final FileInputStream fileInputStream;
	private final ClientUser sendTo;
	private long pos = 0;
	private long len;

	private final Cipher cipher;
	private SecretKey aesSecretKey;

	@Override
	public String getStatusText() {
		return "Sending " + file.getName() + " [" + ((int)((((float)pos) / ((float)len)) * 100)) + "%]";
	}

	private boolean boolFinished = false;
	public boolean isFinished() {
		return boolFinished;
	}

	private static final HashMap<ClientUser, FileSender> fileSenders = new HashMap<ClientUser, FileSender>();
	public static void sendFile(ClientUser clientUser, File file) {
		FileSender fileSender;
		synchronized (fileSenders) {
			if((fileSender = fileSenders.get(clientUser)) != null) {
				if(!fileSender.isFinished()) {
					throw new Error("Sorry, there is already a file transfer with that user in progress");
				}
			}
			fileSender = new FileSender(clientUser, file);
			fileSenders.put(clientUser, fileSender);
		}
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

		FormMain.instance.getChatTab(sendTo).addStatusTextHook(this);

		processFileTransfer();
	}

	private final LongCodec longCodec = new LongCodec();
	private final IntCodec intCodec = new IntCodec();
	private static final int PACKET_SIZE = 4096;

	private void processFileTransfer() {
		if(pos < len) {
			sendFileData();
			return;
		}

		try {
			fileInputStream.close();
		} catch (Exception e) { }

		sendFileEnd();

		boolFinished = true;

		ChatTab chatTab = FormMain.instance.getChatTab(sendTo);
		chatTab.addText("[FILE] Sent " + file.getName());
		chatTab.removeStatusTextHook(this);
	}

	private final byte[] packetData = new byte[PACKET_SIZE + 32 + 8 + 8 + 16];
	private final byte[] fileData = new byte[PACKET_SIZE];

	private synchronized void sendFileData() {
		try {
			int readLen = fileInputStream.read(fileData, 0, PACKET_SIZE);
			if(readLen < 1) {
				new Thread() {
					@Override
					public void run() {
						try {
							Thread.sleep(10);
						} catch (Exception e) { }
						processFileTransfer();
					}
				}.start();
				return;
			}

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

			ChannelFuture channelFuture = ClientLib.sendMessage(binaryMessage, false);
			channelFuture.addListener(new ChannelFutureListener() {
				@Override
				public void operationComplete(ChannelFuture channelFuture) throws Exception {
					if(channelFuture.isSuccess())
						processFileTransfer();
				}
			});
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
