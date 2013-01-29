package me.draconia.chat.types;

public abstract class ChannelFactory {
    public static ChannelFactory instance;

    public abstract Channel createFromName(String name);
}
