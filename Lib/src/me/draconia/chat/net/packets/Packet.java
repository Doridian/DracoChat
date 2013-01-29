package me.draconia.chat.net.packets;

import me.draconia.chat.util.IntUtils;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;

import java.io.UnsupportedEncodingException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.List;

public abstract class Packet {
    public enum Side {
        SERVER_TO_CLIENT,
        CLIENT_TO_SERVER
    }

    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) protected @interface PacketSide { Side value(); }
    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) protected @interface PacketID { byte value(); }

    private static final Constructor<? extends Packet>[] READABLE_PACKETS = new Constructor[256];

    public static void initialize(Side receivingSide) {
        List<Class<? extends Packet>> packets = IntUtils.getSubClasses(Packet.class, Packet.class.getPackage().getName());
        for(Class<? extends Packet> packet : packets) {
            if(packet.isAnnotationPresent(PacketSide.class) && !packet.getAnnotation(PacketSide.class).value().equals(receivingSide))
                continue;
            if(!packet.isAnnotationPresent(PacketID.class))
                continue;
            int packetID = packet.getAnnotation(PacketID.class).value();
            try {
                Constructor<? extends Packet> constructor = packet.getConstructor();
                READABLE_PACKETS[packetID] = constructor;
            } catch(Exception e) {
                System.out.println("[ERROR] Readable Packet ID " + packetID + " failed to load because: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private boolean idSet = false;
    private byte id;

    protected Packet() {

    }

    public int getID() {
        if(!idSet) {
            id = this.getClass().getAnnotation(PacketID.class).value();
            idSet = true;
        }
        return id;
    }

    protected abstract void decode(ChannelBuffer channelBuffer);

    protected abstract void encode(ChannelBuffer channelBuffer);

    /* STRING */
    protected static String readString(ChannelBuffer channelBuffer) {
        int strLen = channelBuffer.readInt();
        byte[] strBytes = new byte[strLen];
        channelBuffer.readBytes(strBytes);
        try {
            return new String(strBytes, "UTF-8");
        } catch(UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
    protected static void writeString(ChannelBuffer channelBuffer, String string) {
        byte[] strBytes;
        try {
            strBytes = string.getBytes("UTF-8");
        } catch(UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        channelBuffer.writeInt(strBytes.length);
        channelBuffer.writeBytes(strBytes);
    }

    protected static String readCompressedString(ChannelBuffer channelBuffer) {
        int strLen = channelBuffer.readInt();
        byte[] strBytes = new byte[strLen];
        channelBuffer.readBytes(strBytes);
        try {
            return new String(strBytes, "UTF-8");
        } catch(UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    protected static void writeCompressedString(ChannelBuffer channelBuffer, String string) {
        byte[] strBytes;
        try {
            strBytes = string.getBytes("UTF-8");
        } catch(UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        channelBuffer.writeInt(strBytes.length);
        channelBuffer.writeBytes(strBytes);
    }

    /* BOOLEAN */
    protected static boolean readBoolean(ChannelBuffer channelBuffer) {
        return (channelBuffer.readByte() == 1);
    }
    protected static void writeBoolean(ChannelBuffer channelBuffer, boolean bool) {
        channelBuffer.writeByte(bool ? 1 : 0);
    }


    public static Packet createPacketFrom(byte id, ChannelBuffer channelBuffer) {
        try {
            Packet packet = READABLE_PACKETS[id].newInstance();
            packet.id = id;
            packet.decode(channelBuffer);
            return packet;
        } catch(Exception e) {
            System.out.println("Error decoding packet ID " + (int)id);
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private boolean isDirty = true;
    private ChannelBuffer packetBuffer = null;

    protected void makeDirty() {
        isDirty = true;
    }

    public ChannelBuffer getData() {
        if(isDirty) {
            isDirty = false;
            synchronized (this) {
                packetBuffer = ChannelBuffers.dynamicBuffer(64);
                packetBuffer.writerIndex(5);
                this.encode(packetBuffer);
                packetBuffer.markWriterIndex();
                int length = packetBuffer.writerIndex() - 5;
                packetBuffer.writerIndex(0);
                packetBuffer.writeByte(this.getID());
                packetBuffer.writeInt(length);
                packetBuffer.resetWriterIndex();
            }
        }
        return packetBuffer;
    }
}
