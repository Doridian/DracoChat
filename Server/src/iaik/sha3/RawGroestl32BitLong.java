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
 * 32-bit Groestl implementation for hash lengths > 256 bit.
 * 
 * @author Christian Hanser
 */
final class RawGroestl32BitLong extends RawGroestl32Bit {

  private static final int COLS = 16;

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
  public RawGroestl32BitLong(int digestLength) {
    super(digestLength, COLS);

    engineReset();
  }

  // compute one round of P (short variants)
  private static void RNDP1(int[] x, int r) {
    x[0] ^= r;
    x[2] ^= 0x10000000 ^ r;
    x[4] ^= 0x20000000 ^ r;
    x[6] ^= 0x30000000 ^ r;
    x[8] ^= 0x40000000 ^ r;
    x[10] ^= 0x50000000 ^ r;
    x[12] ^= 0x60000000 ^ r;
    x[14] ^= 0x70000000 ^ r;
    x[16] ^= 0x80000000 ^ r;
    x[18] ^= 0x90000000 ^ r;
    x[20] ^= 0xa0000000 ^ r;
    x[22] ^= 0xb0000000 ^ r;
    x[24] ^= 0xc0000000 ^ r;
    x[26] ^= 0xd0000000 ^ r;
    x[28] ^= 0xe0000000 ^ r;
    x[30] ^= 0xf0000000 ^ r;
  }

  // compute one round of P (short variants)
  private static void RNDP2(int[] x, int[] y) {
    COLUMN(x, y, 0, 0, 2, 4, 6, 9, 11, 13, 23);
    COLUMN(x, y, 2, 2, 4, 6, 8, 11, 13, 15, 25);
    COLUMN(x, y, 4, 4, 6, 8, 10, 13, 15, 17, 27);
    COLUMN(x, y, 6, 6, 8, 10, 12, 15, 17, 19, 29);
    COLUMN(x, y, 8, 8, 10, 12, 14, 17, 19, 21, 31);
    COLUMN(x, y, 10, 10, 12, 14, 16, 19, 21, 23, 1);
    COLUMN(x, y, 12, 12, 14, 16, 18, 21, 23, 25, 3);
    COLUMN(x, y, 14, 14, 16, 18, 20, 23, 25, 27, 5);
    COLUMN(x, y, 16, 16, 18, 20, 22, 25, 27, 29, 7);
    COLUMN(x, y, 18, 18, 20, 22, 24, 27, 29, 31, 9);
    COLUMN(x, y, 20, 20, 22, 24, 26, 29, 31, 1, 11);
    COLUMN(x, y, 22, 22, 24, 26, 28, 31, 1, 3, 13);
    COLUMN(x, y, 24, 24, 26, 28, 30, 1, 3, 5, 15);
    COLUMN(x, y, 26, 26, 28, 30, 0, 3, 5, 7, 17);
    COLUMN(x, y, 28, 28, 30, 0, 2, 5, 7, 9, 19);
    COLUMN(x, y, 30, 30, 0, 2, 4, 7, 9, 11, 21);

    COLUMN(x, y, 1, 9, 11, 13, 23, 0, 2, 4, 6);
    COLUMN(x, y, 3, 11, 13, 15, 25, 2, 4, 6, 8);
    COLUMN(x, y, 5, 13, 15, 17, 27, 4, 6, 8, 10);
    COLUMN(x, y, 7, 15, 17, 19, 29, 6, 8, 10, 12);
    COLUMN(x, y, 9, 17, 19, 21, 31, 8, 10, 12, 14);
    COLUMN(x, y, 11, 19, 21, 23, 1, 10, 12, 14, 16);
    COLUMN(x, y, 13, 21, 23, 25, 3, 12, 14, 16, 18);
    COLUMN(x, y, 15, 23, 25, 27, 5, 14, 16, 18, 20);
    COLUMN(x, y, 17, 25, 27, 29, 7, 16, 18, 20, 22);
    COLUMN(x, y, 19, 27, 29, 31, 9, 18, 20, 22, 24);
    COLUMN(x, y, 21, 29, 31, 1, 11, 20, 22, 24, 26);
    COLUMN(x, y, 23, 31, 1, 3, 13, 22, 24, 26, 28);
    COLUMN(x, y, 25, 1, 3, 5, 15, 24, 26, 28, 30);
    COLUMN(x, y, 27, 3, 5, 7, 17, 26, 28, 30, 0);
    COLUMN(x, y, 29, 5, 7, 9, 19, 28, 30, 0, 2);
    COLUMN(x, y, 31, 7, 9, 11, 21, 30, 0, 2, 4);
  }

  // compute one round of Q (short variants)
  private static void RNDQ1(int[] x, int r) {
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
    x[16] = ~x[16];
    x[17] ^= 0x80 ^ r;
    x[18] = ~x[18];
    x[19] ^= 0x90 ^ r;
    x[20] = ~x[20];
    x[21] ^= 0xa0 ^ r;
    x[22] = ~x[22];
    x[23] ^= 0xb0 ^ r;
    x[24] = ~x[24];
    x[25] ^= 0xc0 ^ r;
    x[26] = ~x[26];
    x[27] ^= 0xd0 ^ r;
    x[28] = ~x[28];
    x[29] ^= 0xe0 ^ r;
    x[30] = ~x[30];
    x[31] ^= 0xf0 ^ r;
  }

  // compute one round of Q (short variants)
  private static void RNDQ2(int[] x, int[] y) {
    COLUMN(x, y, 0, 2, 6, 10, 22, 1, 5, 9, 13);
    COLUMN(x, y, 1, 1, 5, 9, 13, 2, 6, 10, 22);
    COLUMN(x, y, 2, 4, 8, 12, 24, 3, 7, 11, 15);
    COLUMN(x, y, 3, 3, 7, 11, 15, 4, 8, 12, 24);
    COLUMN(x, y, 4, 6, 10, 14, 26, 5, 9, 13, 17);
    COLUMN(x, y, 5, 5, 9, 13, 17, 6, 10, 14, 26);
    COLUMN(x, y, 6, 8, 12, 16, 28, 7, 11, 15, 19);
    COLUMN(x, y, 7, 7, 11, 15, 19, 8, 12, 16, 28);
    COLUMN(x, y, 8, 10, 14, 18, 30, 9, 13, 17, 21);
    COLUMN(x, y, 9, 9, 13, 17, 21, 10, 14, 18, 30);
    COLUMN(x, y, 10, 12, 16, 20, 0, 11, 15, 19, 23);
    COLUMN(x, y, 11, 11, 15, 19, 23, 12, 16, 20, 0);
    COLUMN(x, y, 12, 14, 18, 22, 2, 13, 17, 21, 25);
    COLUMN(x, y, 13, 13, 17, 21, 25, 14, 18, 22, 2);
    COLUMN(x, y, 14, 16, 20, 24, 4, 15, 19, 23, 27);
    COLUMN(x, y, 15, 15, 19, 23, 27, 16, 20, 24, 4);

    COLUMN(x, y, 16, 18, 22, 26, 6, 17, 21, 25, 29);
    COLUMN(x, y, 17, 17, 21, 25, 29, 18, 22, 26, 6);
    COLUMN(x, y, 18, 20, 24, 28, 8, 19, 23, 27, 31);
    COLUMN(x, y, 19, 19, 23, 27, 31, 20, 24, 28, 8);
    COLUMN(x, y, 20, 22, 26, 30, 10, 21, 25, 29, 1);
    COLUMN(x, y, 21, 21, 25, 29, 1, 22, 26, 30, 10);
    COLUMN(x, y, 22, 24, 28, 0, 12, 23, 27, 31, 3);
    COLUMN(x, y, 23, 23, 27, 31, 3, 24, 28, 0, 12);
    COLUMN(x, y, 24, 26, 30, 2, 14, 25, 29, 1, 5);
    COLUMN(x, y, 25, 25, 29, 1, 5, 26, 30, 2, 14);
    COLUMN(x, y, 26, 28, 0, 4, 16, 27, 31, 3, 7);
    COLUMN(x, y, 27, 27, 31, 3, 7, 28, 0, 4, 16);
    COLUMN(x, y, 28, 30, 2, 6, 18, 29, 1, 5, 9);
    COLUMN(x, y, 29, 29, 1, 5, 9, 30, 2, 6, 18);
    COLUMN(x, y, 30, 0, 4, 8, 20, 31, 3, 7, 11);
    COLUMN(x, y, 31, 31, 3, 7, 11, 0, 4, 8, 20);
  }

  @Override
  public void engineCompress(byte[] input, int offset) {
    Util.squashBytesToInts(input, offset, z_, 0, (COLS << 1));

    for (int i = 0; i < (COLS << 1); i++) {
      tempP_[i] = chaining_[i] ^ z_[i];
    }

    // compute Q(m)
    RNDQ1(z_, ~0);
    RNDQ2(z_, y_);
    RNDQ1(y_, ~1);
    RNDQ2(y_, z_);
    RNDQ1(z_, ~2);
    RNDQ2(z_, y_);
    RNDQ1(y_, ~3);
    RNDQ2(y_, z_);
    RNDQ1(z_, ~4);
    RNDQ2(z_, y_);
    RNDQ1(y_, ~5);
    RNDQ2(y_, z_);
    RNDQ1(z_, ~6);
    RNDQ2(z_, y_);
    RNDQ1(y_, ~7);
    RNDQ2(y_, z_);
    RNDQ1(z_, ~8);
    RNDQ2(z_, y_);
    RNDQ1(y_, ~9);
    RNDQ2(y_, z_);
    RNDQ1(z_, ~10);
    RNDQ2(z_, y_);
    RNDQ1(y_, ~11);
    RNDQ2(y_, z_);
    RNDQ1(z_, ~12);
    RNDQ2(z_, y_);
    RNDQ1(y_, ~13);
    RNDQ2(y_, tempQ_);

    // c2ompute P(h+m)
    RNDP1(tempP_, 0);
    RNDP2(tempP_, y_);
    RNDP1(y_, 1 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 2 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 3 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 4 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 5 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 6 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 7 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 8 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 9 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 10 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 11 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 12 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 13 << 24);
    RNDP2(y_, tempP_);

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

    // output transformation
    RNDP1(temp, 0);
    RNDP2(temp, y_);
    RNDP1(y_, 1 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 2 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 3 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 4 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 5 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 6 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 7 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 8 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 9 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 10 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 11 << 24);
    RNDP2(y_, z_);
    RNDP1(z_, 12 << 24);
    RNDP2(z_, y_);
    RNDP1(y_, 13 << 24);
    RNDP2(y_, temp);

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
