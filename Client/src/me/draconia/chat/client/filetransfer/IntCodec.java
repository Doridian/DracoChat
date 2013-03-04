package me.draconia.chat.client.filetransfer;

import java.nio.ByteBuffer;

public class IntCodec {
	private final ByteBuffer buffer = ByteBuffer.allocate(4);

	public byte[] toBytes(int x) {
		buffer.rewind();
		buffer.putInt(0, x);
		return buffer.array();
	}

	public int toNum(byte[] bytes, int start) {
		buffer.rewind();
		buffer.put(bytes, start, 4);
		buffer.flip();//need flip
		return buffer.getInt();
	}
}
