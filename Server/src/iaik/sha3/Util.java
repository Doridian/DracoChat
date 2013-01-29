//    IAIK SHA3 Provider, a Java-library containing SHA3 candidate implementations  
//    Copyright (C) 2012 Stiftung Secure Information and Communication Technologies SIC 
//                       http://jce.iaik.tugraz.at
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
package iaik.sha3;

/**
 * Utility class that contains amongst others important methods for dealing with
 * byte, int, and long arrays.
 * 
 * @author Christian Hanser
 */
final class Util {

  public final static int DEFAULT_JVM_DATA_MODEL = 32;

  /**
   * Returns the bit mode of the underlying JVM.
   * 
   * @return the bit mode
   */
  public static int getJVMDataMode() {
    int dataModel;

    try {
      String bitmode = System.getProperty("sun.arch.data.model");
      if (bitmode == null) {
        bitmode = System.getProperty("oracle.arch.data.model");
      }

      dataModel = Integer.parseInt(bitmode);
    } catch (final Throwable e) {
      dataModel = DEFAULT_JVM_DATA_MODEL;
    }

    return dataModel;
  }

  /**
   * Fills the specified sub-array of the given byte array with zeros.
   * <p>
   * Starting at the given <code>off</code> position, <code>len</code> bytes of
   * the given array are set to zero. To, for instance, set three bytes to zero,
   * starting at position 2, use: <blockquote>
   * 
   * <pre>
   * byte[] block = ...;
   * CryptoUtils.zeroBlock(block, 2, 3);
   * </pre>
   * 
   * </blockquote>
   * 
   * @param block
   *          the byte array of which some bytes have to be set to zero
   * @param off
   *          the offset indicating the start position within the byte array;
   *          the following <code>len</code> bytes are set to zero
   * @param len
   *          the number of bytes to be set to zero, starting at
   *          <code>off</code>
   */
  public static void zeroBlock(byte[] block, int off, int len) {
    for (int i = off; i < (off + len); ++i) {
      block[i] = 0;
    }
  }

  /**
   * Spreads ints into bytes.
   * <p>
   * In Java, the primitive data type <i>byte</i> internally is represented as 8
   * bit signed number, and <i>int</i> denotes a signed 32 bit number. This
   * method transforms the int values of the given <code>inInts</code> array
   * into proper byte values for the specified <code>outBytes</code> array. The
   * transforming computation will yield four bytes for each int value of the
   * specified sequence of the input int array. So, if the given
   * <code>inInts</code> array will consist of <code>n</code> ints, the
   * following "transformation" will take place (when both <code>inOff</code>
   * and <code>outOff</code>, indicating the start position from where to read
   * the int values from the <code>inInts</code> array and the destination
   * position where to write the resulting byte values to the
   * <code>outBytes</code> array, are set to <code>0</code>): <blockquote>
   * 
   * <pre>
   *  inInts[0] goes to outBytes[0...3]
   *  inInts[1] goes to outBytes[4...7]
   *    ...
   *  inInts[n-1] goes to outInts[n*4-4...n*4-1]
   * </pre>
   * 
   * </blockquote> The last parameter value <code>intLen</code> denotes the size
   * of the input int array. To spread, for instance, a sequence of 2 ints, set
   * <code>intLen</code> to <code>2</code>: <blockquote>
   * 
   * <pre>
   * int[] in = new int[2];
   * byte[] out = new byte[8];
   *  ...
   * CryptoUtils.spreadLongsToBytes(in, 0, out, 0, 2);
   * </pre>
   * 
   * </blockquote>
   * 
   * @param inInts
   *          the int array supplying the integers to be spread to bytes
   * @param inOff
   *          the offset indicating the start position within the input int
   *          array; the following <code>intLen</code> integers will be spread
   *          to bytes
   * @param outBytes
   *          the byte array to which the resulting byte values are written,
   *          starting at position <code>outOff</code>
   * @param outOff
   *          the offset indicating the start position within the destination
   *          byte array, to which the resulting byte values are written
   * @param intLen
   *          the number of int values that have to spread to bytes
   */
  public static void spreadIntsToBytes(int[] inInts, int inOff, byte[] outBytes, int outOff,
      int intLen) {
    for (int i = outOff; i < (outOff + (intLen << 2));) {
      outBytes[i++] = (byte) (inInts[inOff] >>> 24);
      outBytes[i++] = (byte) (inInts[inOff] >>> 16);
      outBytes[i++] = (byte) (inInts[inOff] >>> 8);
      outBytes[i++] = (byte) inInts[inOff++];
    }
  }

  /**
   * Spreads ints into bytes in little endian bytes ordering. That means least
   * significant byte first, most significant byte last.
   * 
   * @see #spreadIntsToBytes
   */
  public static void spreadIntsToBytesLE(int[] inInts, int inOff, byte[] outBytes, int outOff,
      int intLen) {
    for (int i = outOff; i < (outOff + (intLen << 2));) {
      outBytes[i++] = (byte) (inInts[inOff]);
      outBytes[i++] = (byte) (inInts[inOff] >>> 8);
      outBytes[i++] = (byte) (inInts[inOff] >>> 16);
      outBytes[i++] = (byte) (inInts[inOff++] >>> 24);
    }
  }

  /**
   * Fills the given byte array with zeros.
   * <p>
   * 
   * @param block
   *          the byte array to be filled with zeros
   */
  public static void zeroBlock(byte[] block) {
    zeroBlock(block, 0, block.length);
  }

  /**
   * Squashes bytes down to ints.
   * <p>
   * In Java, the primitive data type <i>byte</i> internally is represented as 8
   * bit signed number, and <i>int</i> denotes a signed 32 bit number. This
   * method transforms the bytes of the given <code>inBytes</code> array into
   * proper int values for the specified <code>outInts</code> int array. The
   * bytes are grouped in sequences each of it consisting of 4 bytes (32 bits)
   * to compute the corresponding int values. So, if the given
   * <code>inBytes</code> array will consist of <code>n</code> bytes (
   * <code>n&nbsp;=&nbsp;4&nbsp;*&nbsp;m;
   * m&nbsp;>=&nbsp;1</code>), the following "transformation" will take place
   * (when both <code>inOff</code> and <code>outOff</code>, indicating the start
   * position from where to read the bytes from the <code>inBytes</code> array
   * and the destination position where to write the resulting int values to the
   * <code>outInts</code> array, are set to <code>0</code>): <blockquote>
   * 
   * <pre>
   *  inBytes[0...3] goes to outInts[0]
   *  inBytes[4...7] goes to outInts[1]
   *    ...
   *  inBytes[n-4...n-1] goes to outInts[n/4-1]
   * </pre>
   * 
   * </blockquote> The last parameter value <code>intLen</code> denotes the
   * number of the resulting int values. To squash, for instance, a sequence of
   * 8 bytes, set <code>intLen</code> to <code>2</code> indicating that two int
   * values will result from the transforming computations: <blockquote>
   * 
   * <pre>
   * byte[] in = new byte[8];
   * int[] out = new int[2];
   *  ...
   * CryptoUtils.squashBytesToInts(in, 0, out, 0, 2);
   * </pre>
   * 
   * </blockquote>
   * 
   * @param inBytes
   *          the byte array supplying the bytes to be squashed to ints
   * @param inOff
   *          the offset indicating the start position within the input byte
   *          array; the following <code>4 * intLen</code> bytes will be
   *          squashed to ints
   * @param outInts
   *          the int array to which the resulting int values are written,
   *          starting at position <code>outOff</code>
   * @param outOff
   *          the offset indicating the start position within the destination
   *          int array, to which the resulting int values are written
   * @param intLen
   *          the number of int values that will result from the "bytes-to-ints"
   *          transformation
   */
  public static void squashBytesToInts(byte[] inBytes, int inOff, int[] outInts, int outOff,
      int intLen) {
    for (int i = inOff; i < (inOff + (intLen << 2));) {
      outInts[outOff++] = ((inBytes[i++] & 0xff) << 24) | ((inBytes[i++] & 0xff) << 16)
          | ((inBytes[i++] & 0xff) << 8) | (inBytes[i++] & 0xff);
    }
  }

  /**
   * Fill an integer array with zeros.
   */
  public static void zeroBlock(int[] block) {
    Util.zeroBlock(block, 0, block.length);
  }

  /**
   * Spreads long integers into bytes.
   * <p>
   * In Java, the primitive data type <i>byte</i> internally is represented as 8
   * bit signed number, and <i>long</i> denotes a signed 64 bit number. This
   * method transforms the long values of the given <code>inLongs</code> array
   * into proper byte values for the specified <code>outBytes</code> array. The
   * transforming computation will yield eight bytes for each long value of the
   * specified sequence of the input long array. So, if the given
   * <code>inLongs</code> array will consist of <code>n</code> longs, the
   * following "transformation" will take place (when both <code>inOff</code>
   * and <code>outOff</code>, indicating the start position from where to read
   * the long values from the <code>inLongs</code> array and the destination
   * position where to write the resulting byte values to the
   * <code>outBytes</code> array, are set to <code>0</code>): <blockquote>
   * 
   * <pre>
   *  inLongs[0] goes to outBytes[0...7]
   *  inLongs[1] goes to outBytes[8...15]
   *    ...
   *  inLongs[n-1] goes to outInts[n*8-8...n*8-1]
   * </pre>
   * 
   * </blockquote> The last parameter value <code>longLen</code> denotes the
   * size of the input long array. To spread, for instance, a sequence of 2
   * long, set <code>longLen</code> to <code>2</code>: <blockquote>
   * 
   * <pre>
   * long[] in = new long[2];
   * byte[] out = new byte[16];
   *  ...
   * CryptoUtils.spreadLongsToBytes(in, 0, out, 0, 2);
   * </pre>
   * 
   * </blockquote>
   * 
   * @param inLongs
   *          the long array supplying the integers to be spread to bytes
   * @param inOff
   *          the offset indicating the start position within the input int
   *          array; the following <code>intLen</code> integers will be spread
   *          to bytes
   * @param outBytes
   *          the byte array to which the resulting byte values are written,
   *          starting at position <code>outOff</code>
   * @param outOff
   *          the offset indicating the start position within the destination
   *          byte array, to which the resulting byte values are written
   * @param longLen
   *          the number of long values that have to spread to bytes
   */
  public static void spreadLongsToBytes(long[] inLongs, int inOff, byte[] outBytes, int outOff,
      int longLen) {
    for (int i = outOff; i < (outOff + (longLen << 3));) {
      outBytes[i++] = (byte) (inLongs[inOff] >>> 56);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 48);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 40);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 32);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 24);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 16);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 8);
      outBytes[i++] = (byte) inLongs[inOff++];
    }
  }

  /**
   * Squashes bytes down to longs.
   * <p>
   * In Java, the primitive data type <i>byte</i> internally is represented as 8
   * bit signed number, and <i>longs</i> denotes a signed 64 bit number. This
   * method transforms the bytes of the given <code>inBytes</code> array into
   * proper long values for the specified <code>outLongs</code> int array. The
   * bytes are grouped in sequences each of it consisting of 8 bytes (64 bits)
   * to compute the corresponding int values. So, if the given
   * <code>inBytes</code> array will consist of <code>n</code> bytes (
   * <code>n&nbsp;=&nbsp;8&nbsp;*&nbsp;m;
   * m&nbsp;>=&nbsp;1</code>), the following "transformation" will take place
   * (when both <code>inOff</code> and <code>outOff</code>, indicating the start
   * position from where to read the bytes from the <code>inBytes</code> array
   * and the destination position where to write the resulting long values to
   * the <code>outLongs</code> array, are set to <code>0</code>): <blockquote>
   * 
   * <pre>
   *  inBytes[0...7] goes to outLongs[0]
   *  inBytes[8...15] goes to outLongs[1]
   *    ...
   *  inBytes[n-8...n-1] goes to outLongs[n/8-1]
   * </pre>
   * 
   * </blockquote> The last parameter value <code>longLen</code> denotes the
   * number of the resulting long values. To squash, for instance, a sequence of
   * 16 bytes, set <code>longLen</code> to <code>2</code> indicating that two
   * long values will result from the transforming computations: <blockquote>
   * 
   * <pre>
   * byte[] in = new byte[16];
   * long[] out = new long[2];
   *  ...
   * CryptoUtils.squashBytesToInts(in, 0, out, 0, 2);
   * </pre>
   * 
   * </blockquote>
   * 
   * @param inBytes
   *          the byte array supplying the bytes to be squashed to ints
   * @param inOff
   *          the offset indicating the start position within the input byte
   *          array; the following <code>4 * intLen</code> bytes will be
   *          squashed to longs
   * @param outLongs
   *          the long array to which the resulting int values are written,
   *          starting at position <code>outOff</code>
   * @param outOff
   *          the offset indicating the start position within the destination
   *          int array, to which the resulting int values are written
   * @param longLen
   *          the number of long values that will result from the
   *          "bytes-to-longs" transformation
   */
  public static void squashBytesToLongs(byte[] inBytes, int inOff, long[] outLongs, int outOff,
      int longLen) {
    for (int i = inOff; i < (inOff + (longLen << 3));) {
      outLongs[outOff++] = ((long) (inBytes[i++] & 0xff) << 56)
          | ((long) (inBytes[i++] & 0xff) << 48) | ((long) (inBytes[i++] & 0xff) << 40)
          | ((long) (inBytes[i++] & 0xff) << 32) | ((long) (inBytes[i++] & 0xff) << 24)
          | ((long) (inBytes[i++] & 0xff) << 16) | ((long) (inBytes[i++] & 0xff) << 8)
          | ((inBytes[i++] & 0xff));
    }
  }

  /**
   * Fill a long array with zeros.
   */
  public static void zeroBlock(long[] block) {
    Util.zeroBlock(block, 0, block.length);
  }

  /**
   * Squashes bytes down to ints assuming little endian byte ordering. That
   * means least significant byte first, most significant byte last.
   * 
   * @see squashBytesToInts
   */
  public static void squashBytesToIntsLE(byte[] inBytes, int inOff, int[] outInts, int outOff,
      int intLen) {
    for (int i = inOff; i < (inOff + (intLen << 2));) {
      outInts[outOff++] = ((inBytes[i++] & 0xff)) | ((inBytes[i++] & 0xff) << 8)
          | ((inBytes[i++] & 0xff) << 16) | ((inBytes[i++]) << 24);
    }
  }

  /**
   * Squashes bytes down to longs assuming little endian byte ordering. That
   * means least significant byte first, most significant byte last.
   * 
   * @see squashBytesToLongs
   */
  public static void squashBytesToLongsLE(byte[] inBytes, int inOff, long[] outLongs, int outOff,
      int longLen) {
    for (int i = inOff; i < (inOff + (longLen << 3));) {
      outLongs[outOff++] = ((inBytes[i++] & 0xff)) | ((long) (inBytes[i++] & 0xff) << 8)
          | ((long) (inBytes[i++] & 0xff) << 16) | ((long) (inBytes[i++] & 0xff) << 24)
          | ((long) (inBytes[i++] & 0xff) << 32) | ((long) (inBytes[i++] & 0xff) << 40)
          | ((long) (inBytes[i++] & 0xff) << 48) | ((long) (inBytes[i++] & 0xff) << 56);
    }
  }

  /**
   * Spreads longs into bytes in little endian bytes ordering. That means least
   * significant byte first, most significant byte last.
   * 
   * @see spreadLongsToBytes
   */
  public static void spreadLongsToBytesLE(long[] inLongs, int inOff, byte[] outBytes, int outOff,
      int longLen) {
    for (int i = outOff; i < (outOff + (longLen << 3));) {
      outBytes[i++] = (byte) (inLongs[inOff]);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 8);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 16);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 24);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 32);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 40);
      outBytes[i++] = (byte) (inLongs[inOff] >>> 48);
      outBytes[i++] = (byte) (inLongs[inOff++] >>> 56);
    }
  }

  /**
   * Fill part of an integer array with zeros.
   */
  public static void zeroBlock(int[] block, int off, int len) {
    for (int i = off; i < (off + len); ++i) {
      block[i] = 0;
    }
  }

  /**
   * Fill part of a long array with zeros.
   */
  public static void zeroBlock(long[] block, int off, int len) {
    for (int i = off; i < (off + len); ++i) {
      block[i] = 0;
    }
  }

  /**
   * Hidden default constructor.
   */
  private Util() {
    // hidden
  }

}
