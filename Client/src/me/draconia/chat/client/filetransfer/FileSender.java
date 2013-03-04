package me.draconia.chat.client.filetransfer;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.gui.ChatTab;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.client.types.ClientUser;
import me.draconia.chat.types.BinaryMessage;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.SecureRandom;
import java.util.HashMap;

public class FileSender implements ChatTab.StatusTextHook {
	private final File file;
	private final FileInputStream fileInputStream;
	private final ClientUser sendTo;
	private long pos = 0;
	private long len;

	private final int fileID;

	private final PaddedBufferedBlockCipher cipher;
	private KeyParameter aesSecretKey;

	private static final SecureRandom secureRandom = new SecureRandom();

	private boolean pending = true;

	private class FileSenderChannelFutureListener implements ChannelFutureListener {
		@Override
		public void operationComplete(ChannelFuture channelFuture) throws Exception {
			if(channelFuture.isSuccess())
				processFileTransfer();
		}
	}

	private final FileSenderChannelFutureListener fileSenderChannelFutureListener = new FileSenderChannelFutureListener();

	@Override
	public String getStatusText() {
		if(pending)
			return "Sending " + file.getName() + " [Pending]";
		else
			return "Sending " + file.getName() + " [" + ((int)((((float)pos) / ((float)len)) * 100)) + "%]";
	}

	private boolean boolFinished = false;
	public boolean isFinished() {
		return boolFinished;
	}

	private static class ClientUserInteger {
		final ClientUser clientUser;
		final int fileID;

		private ClientUserInteger(ClientUser clientUser, int fileID) {
			this.clientUser = clientUser;
			this.fileID = fileID;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			ClientUserInteger that = (ClientUserInteger) o;

			if (fileID != that.fileID) return false;
			if (clientUser != null ? !clientUser.equals(that.clientUser) : that.clientUser != null) return false;

			return true;
		}

		@Override
		public int hashCode() {
			int result = clientUser != null ? clientUser.hashCode() : 0;
			result = 31 * result + fileID;
			return result;
		}
	}

	private static final HashMap<ClientUserInteger, FileSender> fileSenders = new HashMap<ClientUserInteger, FileSender>();
	public static void sendFile(ClientUser clientUser, File file) {
		FileSender fileSender = new FileSender(clientUser, file);
		synchronized (fileSenders) {
			fileSenders.put(new ClientUserInteger(clientUser, fileSender.fileID), fileSender);
		}
	}

	public static void fileTransferAckNackReceived(BinaryMessage binaryMessage) {
		ClientUserInteger clientUserInteger = new ClientUserInteger((ClientUser)binaryMessage.from, new IntCodec().toNum(binaryMessage.content, 0));
		boolean accepted = (binaryMessage.content[4] == 1);
		synchronized (fileSenders) {
			FileSender fileSender = fileSenders.get(clientUserInteger);
			if(fileSender == null)
				return;
			fileSender.pending = false;
			if(accepted) {
				fileSender.kickFileTransfer();
				FormMain.instance.getChatTab(fileSender.sendTo).addText("[FILE] Client accepted file " + fileSender.file.getName());
			} else {
				fileSenders.remove(clientUserInteger);
				ChatTab chatTab = FormMain.instance.getChatTab(fileSender.sendTo);
				chatTab.addText("[FILE] Client declined file " + fileSender.file.getName());
				chatTab.removeStatusTextHook(fileSender);
			}
		}
	}

	public FileSender(ClientUser sendTo, File file) {
		if(file.isDirectory() || !file.exists())
			throw new Error("Wat?");

		this.file = file;
		this.sendTo = sendTo;

		this.fileID = secureRandom.nextInt();

		try {
			this.fileInputStream = new FileInputStream(file);

			byte[] aesKey = new byte[32];
			secureRandom.nextBytes(aesKey);
			aesSecretKey = new KeyParameter(aesKey);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

			BinaryMessage binaryMessage = new BinaryMessage();
			binaryMessage.context = sendTo;
			binaryMessage.from = ClientLib.myUser;
			binaryMessage.type = BinaryMessage.TYPE_FILE_START;

			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);

			dataOutputStream.writeInt(fileID);

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
	}

	private final LongCodec longCodec = new LongCodec();
	private final IntCodec intCodec = new IntCodec();
	private static final int PACKET_SIZE = 4096;

	private void kickFileTransfer() {
		new Thread() {
			@Override
			public void run() {
				try {
					Thread.sleep(10);
				} catch (Exception e) { }
				processFileTransfer();
			}
		}.start();
	}

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

	private final byte[] packetData = new byte[PACKET_SIZE + 32 + 8 + 8 + 4];
	private final byte[] fileData = new byte[PACKET_SIZE];

	private synchronized void sendFileData() {
		try {
			int readLen = fileInputStream.read(fileData, 0, PACKET_SIZE);
			if(readLen < 1) {
				kickFileTransfer();
				return;
			}

			cipher.init(true, aesSecretKey);
			int outputtedSize = cipher.getOutputSize(readLen);
			final byte[] encFileData = new byte[outputtedSize];

			outputtedSize = cipher.processBytes(fileData, 0, readLen, encFileData, 0);
			outputtedSize += cipher.doFinal(encFileData, outputtedSize);

			System.arraycopy(encFileData, 0, packetData, 16, outputtedSize);

			System.arraycopy(intCodec.toBytes(fileID), 0, packetData, 0, 4);
			System.arraycopy(longCodec.toBytes(pos), 0, packetData, 4, 8);
			System.arraycopy(intCodec.toBytes(outputtedSize), 0, packetData, 12, 4);

			pos += readLen;

			BinaryMessage binaryMessage = new BinaryMessage();
			binaryMessage.context = sendTo;
			binaryMessage.from = ClientLib.myUser;
			binaryMessage.type = BinaryMessage.TYPE_FILE_DATA;
			binaryMessage.content = packetData;

			ClientLib.sendMessage(binaryMessage, fileSenderChannelFutureListener, false);
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
		binaryMessage.content = intCodec.toBytes(fileID);
		ClientLib.sendEncryptableMessage(binaryMessage, false);
	}
}
