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
 * 32-bit Groestl implementation for hash lengths <= 256 bit.
 * 
 * @author Christian Hanser
 */
final class RawGroestl32BitShort extends RawGroestl32Bit {

  private static final int COLS = 8;

  // helper variables
  private final int[] y_ = new int[COLS << 1];
  private final int[] z_ = new int[COLS << 1];
  private final int[] tempQ_ = new int[COLS << 1];
  private final int[] tempP_ = new int[COLS << 1];

  /**
   * Constructs a new instance.
   * 
   * @param digestLength_
   *          the digest length in bytes
   */
  public RawGroestl32BitShort(int digestLength) {
    super(digestLength, COLS);

    engineReset();
  }

  // compute one round of P (short variants)
  private static void RNDP(int[] x, int[] y, int r) {
    x[0] ^= r;
    x[2] ^= 0x10000000 ^ r;
    x[4] ^= 0x20000000 ^ r;
    x[6] ^= 0x30000000 ^ r;
    x[8] ^= 0x40000000 ^ r;
    x[10] ^= 0x50000000 ^ r;
    x[12] ^= 0x60000000 ^ r;
    x[14] ^= 0x70000000 ^ r;

    COLUMN(x, y, 0, 0, 2, 4, 6, 9, 11, 13, 15);
    COLUMN(x, y, 1, 9, 11, 13, 15, 0, 2, 4, 6);
    COLUMN(x, y, 2, 2, 4, 6, 8, 11, 13, 15, 1);
    COLUMN(x, y, 3, 11, 13, 15, 1, 2, 4, 6, 8);
    COLUMN(x, y, 4, 4, 6, 8, 10, 13, 15, 1, 3);
    COLUMN(x, y, 5, 13, 15, 1, 3, 4, 6, 8, 10);
    COLUMN(x, y, 6, 6, 8, 10, 12, 15, 1, 3, 5);
    COLUMN(x, y, 7, 15, 1, 3, 5, 6, 8, 10, 12);
    COLUMN(x, y, 8, 8, 10, 12, 14, 1, 3, 5, 7);
    COLUMN(x, y, 9, 1, 3, 5, 7, 8, 10, 12, 14);
    COLUMN(x, y, 10, 10, 12, 14, 0, 3, 5, 7, 9);
    COLUMN(x, y, 11, 3, 5, 7, 9, 10, 12, 14, 0);
    COLUMN(x, y, 12, 12, 14, 0, 2, 5, 7, 9, 11);
    COLUMN(x, y, 13, 5, 7, 9, 11, 12, 14, 0, 2);
    COLUMN(x, y, 14, 14, 0, 2, 4, 7, 9, 11, 13);
    COLUMN(x, y, 15, 7, 9, 11, 13, 14, 0, 2, 4);
  }

  // compute one round of Q (short variants)
  private static void RNDQ(int[] x, int[] y, int r) {
    x[0] = ~x[0];
    x[1] ^= r;
    x[2] = ~x[2];
    x[3] ^= 0x10 ^ r;
    x[4] = ~x[4];
    x[5] ^= 0x20 ^ r;
    x[6] = ~x[6];
    x[7] ^= 0x30 ^ r;
    x[8] = ~x[8];
    x[9] ^= 0x40 ^ r;
    x[10] = ~x[10];
    x[11] ^= 0x50 ^ r;
    x[12] = ~x[12];
    x[13] ^= 0x60 ^ r;
    x[14] = ~x[14];
    x[15] ^= 0x70 ^ r;

    COLUMN(x, y, 0, 2, 6, 10, 14, 1, 5, 9, 13);
    COLUMN(x, y, 1, 1, 5, 9, 13, 2, 6, 10, 14);
    COLUMN(x, y, 2, 4, 8, 12, 0, 3, 7, 11, 15);
    COLUMN(x, y, 3, 3, 7, 11, 15, 4, 8, 12, 0);
    COLUMN(x, y, 4, 6, 10, 14, 2, 5, 9, 13, 1);
    COLUMN(x, y, 5, 5, 9, 13, 1, 6, 10, 14, 2);
    COLUMN(x, y, 6, 8, 12, 0, 4, 7, 11, 15, 3);
    COLUMN(x, y, 7, 7, 11, 15, 3, 8, 12, 0, 4);
    COLUMN(x, y, 8, 10, 14, 2, 6, 9, 13, 1, 5);
    COLUMN(x, y, 9, 9, 13, 1, 5, 10, 14, 2, 6);
    COLUMN(x, y, 10, 12, 0, 4, 8, 11, 15, 3, 7);
    COLUMN(x, y, 11, 11, 15, 3, 7, 12, 0, 4, 8);
    COLUMN(x, y, 12, 14, 2, 6, 10, 13, 1, 5, 9);
    COLUMN(x, y, 13, 13, 1, 5, 9, 14, 2, 6, 10);
    COLUMN(x, y, 14, 0, 4, 8, 12, 15, 3, 7, 11);
    COLUMN(x, y, 15, 15, 3, 7, 11, 0, 4, 8, 12);
  }

  @Override
  public void engineCompress(byte[] input, int offset) {
    Util.squashBytesToInts(input, offset, z_, 0, (COLS << 1));

    for (int i = 0; i < (COLS << 1); i++) {
      tempP_[i] = chaining_[i] ^ z_[i];
    }

    // compute Q(m)
    RNDQ(z_, y_, ~0);
    RNDQ(y_, z_, ~1);
    RNDQ(z_, y_, ~2);
    RNDQ(y_, z_, ~3);
    RNDQ(z_, y_, ~4);
    RNDQ(y_, z_, ~5);
    RNDQ(z_, y_, ~6);
    RNDQ(y_, z_, ~7);
    RNDQ(z_, y_, ~8);
    RNDQ(y_, tempQ_, ~9);

    // compute P(h+m)
    RNDP(tempP_, y_, 0x00000000);
    RNDP(y_, z_, 0x01000000);
    RNDP(z_, y_, 0x02000000);
    RNDP(y_, z_, 0x03000000);
    RNDP(z_, y_, 0x04000000);
    RNDP(y_, z_, 0x05000000);
    RNDP(z_, y_, 0x06000000);
    RNDP(y_, z_, 0x07000000);
    RNDP(z_, y_, 0x08000000);
    RNDP(y_, tempP_, 0x09000000);

    // compute P(h+m) + Q(m) + h
    for (int i = 0; i < (COLS << 1); i++) {
      chaining_[i] ^= tempP_[i] ^ tempQ_[i];
    }
  }

  @Override
  public void engineGetDigest(byte[] output, int offset) {
    final int length = chaining_.length;
    final int[] temp = new int[length];
    System.arraycopy(chaining_, 0, temp, 0, length);

    RNDP(temp, y_, 0x00000000);
    RNDP(y_, z_, 0x01000000);
    RNDP(z_, y_, 0x02000000);
    RNDP(y_, z_, 0x03000000);
    RNDP(z_, y_, 0x04000000);
    RNDP(y_, z_, 0x05000000);
    RNDP(z_, y_, 0x06000000);
    RNDP(y_, z_, 0x07000000);
    RNDP(z_, y_, 0x08000000);
    RNDP(y_, temp, 0x09000000);

    for (int i = 0; i < (COLS << 1); i++) {
      chaining_[i] ^= temp[i];
    }

    Util.spreadIntsToBytes(chaining_, chaining_.length - (outputTemp_.length >>> 2), outputTemp_,
        0, outputTemp_.length >>> 2);

    // truncate
    System
        .arraycopy(outputTemp_, outputTemp_.length - digestLength_, output, offset, digestLength_);
  }

  @Override
  public void engineReset() {
    super.engineReset();

    Util.zeroBlock(y_);
    Util.zeroBlock(z_);
    Util.zeroBlock(tempQ_);
    Util.zeroBlock(tempP_);
  }

}
