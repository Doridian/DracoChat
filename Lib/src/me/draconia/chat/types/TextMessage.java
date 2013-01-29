package me.draconia.chat.types;

public class TextMessage extends Message {
    public static final byte TYPE_CHAT = 1; //"Hi there" etc
    public static final byte TYPE_ACTION = 2; // *hugs you* etc
    public static final byte TYPE_EVENT = 3; // **the world exploded** etc
    public static final byte TYPE_SYSTEM = 4; //System messages
    public static final byte TYPE_SYSTEM_ERROR = 5; //System error messages

    public boolean encrypted = false;
    public boolean compressContents = false;
    public String content;
}
