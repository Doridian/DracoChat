package me.draconia.chat.net.packets;

import me.draconia.chat.net.Packets;
import me.draconia.chat.types.*;
import org.jboss.netty.buffer.ChannelBuffer;

@Packet.PacketID(Packets.MESSAGE)
@Packet.PacketSide(Packet.Side.CLIENT_TO_SERVER)
public class PacketMessageToServer extends Packet {
	public Message message;

	private static final byte FLAG_CONTEXT = 3;
	private static final byte CONTEXT_GENERIC = 0;
	private static final byte CONTEXT_USER = 1;
	private static final byte CONTEXT_CHANNEL = 2;
	private static final byte CONTEXT_UNUSED = 3;

	private static final byte FLAG_CONTENTS_COMPRESSED = 4;
	private static final byte FLAG_BINARY = 8;

	@Override
	protected void encode(ChannelBuffer channelBuffer) {
		byte messageFlags = 0;

		channelBuffer.markWriterIndex();
		channelBuffer.writeByte(0);

		if (message instanceof TextMessage) {
			TextMessage textMessage = (TextMessage) message;
			if (textMessage.compressContents) {
				messageFlags |= FLAG_CONTENTS_COMPRESSED;
				writeCompressedString(channelBuffer, textMessage.content);
			} else {
				writeString(channelBuffer, textMessage.content);
			}
		} else if (message instanceof BinaryMessage) {
			messageFlags |= FLAG_BINARY;
			BinaryMessage binaryMessage = (BinaryMessage) message;
			channelBuffer.writeInt(binaryMessage.content.length);
			channelBuffer.writeBytes(binaryMessage.content);
		}

		if (message.context instanceof User) {
			User user = (User) message.context;
			messageFlags |= CONTEXT_USER;
			writeString(channelBuffer, user.login);
		} else if (message.context instanceof Channel) {
			Channel channel = (Channel) message.context;
			messageFlags |= CONTEXT_CHANNEL;
			writeString(channelBuffer, channel.name);
		} else {
			messageFlags |= CONTEXT_GENERIC;
		}

		channelBuffer.writeByte(message.type);

		final int wIndex = channelBuffer.writerIndex();
		channelBuffer.resetWriterIndex();
		channelBuffer.writeByte(messageFlags);
		channelBuffer.writerIndex(wIndex);
	}

	@Override
	protected void decode(ChannelBuffer channelBuffer) {
		byte messageFlags = channelBuffer.readByte();

		if ((messageFlags & FLAG_BINARY) == FLAG_BINARY) {
			BinaryMessage binaryMessage = new BinaryMessage();
			binaryMessage.content = new byte[channelBuffer.readInt()];
			channelBuffer.readBytes(binaryMessage.content);
			message = binaryMessage;
		} else {
			TextMessage textMessage = new TextMessage();
			if ((messageFlags & FLAG_CONTENTS_COMPRESSED) == FLAG_CONTENTS_COMPRESSED) {
				textMessage.content = readCompressedString(channelBuffer);
			} else {
				textMessage.content = readString(channelBuffer);
			}
			message = textMessage;
		}

		switch (messageFlags & FLAG_CONTEXT) {
			case CONTEXT_USER:
				message.context = UserFactory.instance.getFromLogin(readString(channelBuffer));
				break;
			case CONTEXT_CHANNEL:
				message.context = ChannelFactory.instance.createFromName(readString(channelBuffer));
				break;
			case CONTEXT_GENERIC:
				message.context = GenericContext.instance;
				break;
		}

		message.type = channelBuffer.readByte();
	}
}
