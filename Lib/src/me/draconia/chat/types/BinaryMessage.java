package me.draconia.chat.types;

public class BinaryMessage extends Message {
	public static final byte TYPE_OTR_PUBKEY_1 = 1;
	public static final byte TYPE_OTR_PUBKEY_2 = 2;
	public static final byte TYPE_OTR_MESSGAE = 3;
	public static final byte TYPE_OTR_ERROR = 4;

	public static final byte TYPE_FILE_START = 10;
	public static final byte TYPE_FILE_DATA = 11;
	public static final byte TYPE_FILE_END = 12;
	public static final byte TYPE_FILE_START_RESPONSE = 13;

	public static final byte TYPE_TYPING_STATE = 20;

	public byte[] content;
}
