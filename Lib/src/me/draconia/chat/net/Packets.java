package me.draconia.chat.net;

public class Packets {
    public static final byte PING = 0;
    public static final byte DISCONNECT = 1;
    public static final byte LOGIN = 2;
    public static final byte MESSAGE = 3;
    public static final byte NICK_GET = 4;
    public static final byte NICK_SET = 5;
    public static final byte CHANNEL_ACTION = 6;
    public static final byte CHANNEL_USER_SNAPSHOT = 7;
}
