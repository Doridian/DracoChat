package me.draconia.chat.client.filetransfer;

import java.nio.ByteBuffer;

public class LongCodec {
	private final ByteBuffer buffer = ByteBuffer.allocate(8);

	public byte[] toBytes(long x) {
		buffer.rewind();
		buffer.putLong(0, x);
		return buffer.array();
	}

	public long toNum(byte[] bytes, int start) {
		buffer.rewind();
		buffer.put(bytes, start, 8);
		buffer.flip();//need flip
		return buffer.getLong();
	}
}
