package me.draconia.chat.types;

public class BinaryMessage extends Message {
	public static final byte TYPE_OTR_PUBKEY_1 = 1;
	public static final byte TYPE_OTR_PUBKEY_2 = 2;
	public static final byte TYPE_OTR_MESSGAE = 3;
	public static final byte TYPE_OTR_ERROR = 4;

	public byte[] content;
}
