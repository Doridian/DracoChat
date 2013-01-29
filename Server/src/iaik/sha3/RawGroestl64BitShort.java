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
 * 64-bit Groestl implementation for hash lengths <= 256 bit.
 * 
 * @author Christian Hanser
 */
final class RawGroestl64BitShort extends RawGroestl64Bit {

  private static final int COLS = 8;
  private final long[] y_ = new long[COLS];
  private final long[] z_ = new long[COLS];
  private final long[] outQ_ = new long[COLS];
  private final long[] inP_ = new long[COLS];

  /**
   * Creates a new instance.
   * 
   * @param digestLength_
   *          the hash length in bytes
   */
  public RawGroestl64BitShort(int digestLength) {
    super(digestLength, COLS);

    engineReset();
  }

  private static void RNDP1(long[] x, long r) {
    x[0] ^= r;
    x[1] ^= r ^ 0x1000000000000000l;
    x[2] ^= r ^ 0x2000000000000000l;
    x[3] ^= r ^ 0x3000000000000000l;
    x[4] ^= r ^ 0x4000000000000000l;
    x[5] ^= r ^ 0x5000000000000000l;
    x[6] ^= r ^ 0x6000000000000000l;
    x[7] ^= r ^ 0x7000000000000000l;
  }

  private static void RNDP2(long[] x, long[] y) {
    y[0] = T[(((byte) (x[0] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[1] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[2] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[3] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[4] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[5] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[6] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[7])) & BYTE_MASK)];
    y[1] = T[(((byte) (x[1] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[2] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[3] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[4] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[5] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[6] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[7] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[0])) & BYTE_MASK)];
    y[2] = T[(((byte) (x[2] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[3] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[4] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[5] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[6] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[7] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[0] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[1])) & BYTE_MASK)];
    y[3] = T[(((byte) (x[3] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[4] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[5] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[6] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[7] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[0] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[1] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[2])) & BYTE_MASK)];
    y[4] = T[(((byte) (x[4] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[5] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[6] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[7] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[0] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[1] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[2] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[3])) & BYTE_MASK)];
    y[5] = T[(((byte) (x[5] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[6] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[7] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[0] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[1] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[2] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[3] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[4])) & BYTE_MASK)];
    y[6] = T[(((byte) (x[6] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[7] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[0] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[1] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[2] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[3] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[4] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[5])) & BYTE_MASK)];
    y[7] = T[(((byte) (x[7] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[0] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[1] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[2] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[3] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[4] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[5] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[6])) & BYTE_MASK)];
  }

  private static void RNDQ1(long[] x, long r) {
    x[0] ^= r;
    x[1] ^= r ^ 0x10;
    x[2] ^= r ^ 0x20;
    x[3] ^= r ^ 0x30;
    x[4] ^= r ^ 0x40;
    x[5] ^= r ^ 0x50;
    x[6] ^= r ^ 0x60;
    x[7] ^= r ^ 0x70;
  }

  private static void RNDQ2(long[] x, long[] y) {
    y[0] = T[(((byte) (x[1] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[3] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[5] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[7] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[0] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[2] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[4] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[6])) & BYTE_MASK)];
    y[1] = T[(((byte) (x[2] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[4] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[6] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[0] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[1] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[3] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[5] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[7])) & BYTE_MASK)];
    y[2] = T[(((byte) (x[3] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[5] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[7] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[1] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[2] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[4] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[6] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[0])) & BYTE_MASK)];
    y[3] = T[(((byte) (x[4] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[6] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[0] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[2] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[3] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[5] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[7] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[1])) & BYTE_MASK)];
    y[4] = T[(((byte) (x[5] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[7] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[1] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[3] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[4] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[6] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[0] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[2])) & BYTE_MASK)];
    y[5] = T[(((byte) (x[6] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[0] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[2] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[4] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[5] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[7] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[1] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[3])) & BYTE_MASK)];
    y[6] = T[(((byte) (x[7] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[1] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[3] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[5] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[6] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[0] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[2] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[4])) & BYTE_MASK)];
    y[7] = T[(((byte) (x[0] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[2] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[4] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[6] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[7] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[1] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[3] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[5])) & BYTE_MASK)];
  }

  /**
   * The compression function (short variant).
   * 
   * @param input
   *          the input to be compressed
   * @param offset
   *          the input offset
   */
  @Override
  public final void engineCompress(byte[] input, int offset) {
    final long[] z = z_;
    final long[] y = y_;
    final long[] inP = inP_;
    final long[] outQ = outQ_;
    final long[] chaining = chaining_;

    Util.squashBytesToLongs(input, offset, z, 0, COLS);

    for (int i = 0; i < COLS; i++) {
      inP[i] = chaining[i] ^ z[i];
    }

    // compute Q(m)
    RNDQ1(z, ~0);
    RNDQ2(z, y);
    RNDQ1(y, ~1);
    RNDQ2(y, z);
    RNDQ1(z, ~2);
    RNDQ2(z, y);
    RNDQ1(y, ~3);
    RNDQ2(y, z);
    RNDQ1(z, ~4);
    RNDQ2(z, y);
    RNDQ1(y, ~5);
    RNDQ2(y, z);
    RNDQ1(z, ~6);
    RNDQ2(z, y);
    RNDQ1(y, ~7);
    RNDQ2(y, z);
    RNDQ1(z, ~8);
    RNDQ2(z, y);
    RNDQ1(y, ~9);
    RNDQ2(y, outQ);

    // compute P(h+m)
    inP[1] ^= 0x1000000000000000l;
    inP[2] ^= 0x2000000000000000l;
    inP[3] ^= 0x3000000000000000l;
    inP[4] ^= 0x4000000000000000l;
    inP[5] ^= 0x5000000000000000l;
    inP[6] ^= 0x6000000000000000l;
    inP[7] ^= 0x7000000000000000l;
    RNDP2(inP, z);
    RNDP1(z, 0x0100000000000000l);
    RNDP2(z, y);
    RNDP1(y, 0x0200000000000000l);
    RNDP2(y, z);
    RNDP1(z, 0x0300000000000000l);
    RNDP2(z, y);
    RNDP1(y, 0x0400000000000000l);
    RNDP2(y, z);
    RNDP1(z, 0x0500000000000000l);
    RNDP2(z, y);
    RNDP1(y, 0x0600000000000000l);
    RNDP2(y, z);
    RNDP1(z, 0x0700000000000000l);
    RNDP2(z, y);
    RNDP1(y, 0x0800000000000000l);
    RNDP2(y, z);
    RNDP1(z, 0x0900000000000000l);
    RNDP2(z, y);

    // h' == h + Q(m) + P(h+m)
    for (int i = 0; i < COLS; i++) {
      chaining[i] ^= outQ[i] ^ y[i];
    }
  }

  /**
   * Performs the output transformation and returns the digest.
   */
  @Override
  public void engineGetDigest(byte[] output, int offset) {
    final long[] temp = chaining_.clone();

    // output transformation
    RNDP1(temp, 0x0000000000000000l);
    RNDP2(temp, z_);
    RNDP1(z_, 0x0100000000000000l);
    RNDP2(z_, y_);
    RNDP1(y_, 0x0200000000000000l);
    RNDP2(y_, z_);
    RNDP1(z_, 0x0300000000000000l);
    RNDP2(z_, y_);
    RNDP1(y_, 0x0400000000000000l);
    RNDP2(y_, z_);
    RNDP1(z_, 0x0500000000000000l);
    RNDP2(z_, y_);
    RNDP1(y_, 0x0600000000000000l);
    RNDP2(y_, z_);
    RNDP1(z_, 0x0700000000000000l);
    RNDP2(z_, y_);
    RNDP1(y_, 0x0800000000000000l);
    RNDP2(y_, z_);
    RNDP1(z_, 0x0900000000000000l);
    RNDP2(z_, temp);

    for (int i = 0; i < COLS; i++) {
      chaining_[i] ^= temp[i];
    }

    Util.spreadLongsToBytes(chaining_, chaining_.length - (outputTemp_.length >>> 3), outputTemp_,
        0, outputTemp_.length >>> 3);

    // truncate
    System
        .arraycopy(outputTemp_, outputTemp_.length - digestLength_, output, offset, digestLength_);
  }

  @Override
  public void engineReset() {
    super.engineReset();

    Util.zeroBlock(y_);
    Util.zeroBlock(z_);
    Util.zeroBlock(outQ_);
    Util.zeroBlock(inP_);
  }

}
