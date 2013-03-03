package me.draconia.chat.types;

public abstract class Message {
	public static final byte TYPE_DEFAULT = 0;

	public boolean encrypted = false;
	public MessageContext context;
	public User from;
	public byte type = TYPE_DEFAULT;
	public long timestamp = System.currentTimeMillis();
}
