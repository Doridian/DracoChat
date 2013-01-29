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
 * 64-bit Groestl implementation for hash lengths > 256 bit.
 * 
 * @author Christian Hanser
 */
final class RawGroestl64BitLong extends RawGroestl64Bit {

  // some constants
  private static final long ROUNDS = 14;
  private static final int COLS = 16;

  // helper variables
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
  public RawGroestl64BitLong(int digestLength) {
    super(digestLength, COLS);

    engineReset();
  }

  /**
   * Compute a round in P (long variant).
   */
  private static void RNDP1(final long[] x, final long r) {
    x[0] ^= r;
    x[1] ^= r ^ 0x1000000000000000l;
    x[2] ^= r ^ 0x2000000000000000l;
    x[3] ^= r ^ 0x3000000000000000l;
    x[4] ^= r ^ 0x4000000000000000l;
    x[5] ^= r ^ 0x5000000000000000l;
    x[6] ^= r ^ 0x6000000000000000l;
    x[7] ^= r ^ 0x7000000000000000l;
    x[8] ^= r ^ 0x8000000000000000l;
    x[9] ^= r ^ 0x9000000000000000l;
    x[10] ^= r ^ 0xa000000000000000l;
    x[11] ^= r ^ 0xb000000000000000l;
    x[12] ^= r ^ 0xc000000000000000l;
    x[13] ^= r ^ 0xd000000000000000l;
    x[14] ^= r ^ 0xe000000000000000l;
    x[15] ^= r ^ 0xf000000000000000l;
  }

  private static void RNDP2(final long[] x, final long[] y) {
    y[0] = T[(((byte) (x[0] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[1] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[2] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[3] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[4] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[5] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[6] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[11])) & BYTE_MASK)];
    y[1] = T[(((byte) (x[1] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[2] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[3] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[4] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[5] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[6] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[7] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[12])) & BYTE_MASK)];
    y[2] = T[(((byte) (x[2] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[3] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[4] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[5] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[6] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[7] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[8] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[13])) & BYTE_MASK)];
    y[3] = T[(((byte) (x[3] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[4] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[5] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[6] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[7] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[8] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[9] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[14])) & BYTE_MASK)];
    y[4] = T[(((byte) (x[4] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[5] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[6] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[7] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[8] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[9] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[10] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[15])) & BYTE_MASK)];
    y[5] = T[(((byte) (x[5] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[6] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[7] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[8] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[9] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[10] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[11] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[0])) & BYTE_MASK)];
    y[6] = T[(((byte) (x[6] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[7] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[8] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[9] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[10] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[11] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[12] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[1])) & BYTE_MASK)];
    y[7] = T[(((byte) (x[7] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[8] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[9] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[10] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[11] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[12] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[13] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[2])) & BYTE_MASK)];
    y[8] = T[(((byte) (x[8] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[9] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[10] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[11] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[12] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[13] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[14] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[3])) & BYTE_MASK)];
    y[9] = T[(((byte) (x[9] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[10] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[11] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[12] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[13] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[14] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[15] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[4])) & BYTE_MASK)];
    y[10] = T[(((byte) (x[10] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[11] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[12] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[13] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[14] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[15] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[0] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[5])) & BYTE_MASK)];
    y[11] = T[(((byte) (x[11] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[12] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[13] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[14] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[15] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[0] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[1] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[6])) & BYTE_MASK)];
    y[12] = T[(((byte) (x[12] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[13] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[14] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[15] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[0] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[1] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[2] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[7])) & BYTE_MASK)];
    y[13] = T[(((byte) (x[13] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[14] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[15] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[0] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[1] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[2] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[3] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[8])) & BYTE_MASK)];
    y[14] = T[(((byte) (x[14] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[15] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[0] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[1] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[2] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[3] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[4] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[9])) & BYTE_MASK)];
    y[15] = T[(((byte) (x[15] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[0] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[1] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[2] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[3] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[4] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[5] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[10])) & BYTE_MASK)];
  }

  /**
   * Compute a round in Q (long variant).
   */
  private static void RNDQ1(final long[] x, final long r) {
    x[0] ^= r;
    x[1] ^= r ^ 0x10;
    x[2] ^= r ^ 0x20;
    x[3] ^= r ^ 0x30;
    x[4] ^= r ^ 0x40;
    x[5] ^= r ^ 0x50;
    x[6] ^= r ^ 0x60;
    x[7] ^= r ^ 0x70;
    x[8] ^= r ^ 0x80;
    x[9] ^= r ^ 0x90;
    x[10] ^= r ^ 0xa0;
    x[11] ^= r ^ 0xb0;
    x[12] ^= r ^ 0xc0;
    x[13] ^= r ^ 0xd0;
    x[14] ^= r ^ 0xe0;
    x[15] ^= r ^ 0xf0;
  }

  private static void RNDQ2(final long[] x, final long[] y) {
    y[0] = T[(((byte) (x[1] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[3] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[5] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[11] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[0] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[2] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[4] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[6])) & BYTE_MASK)];
    y[1] = T[(((byte) (x[2] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[4] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[6] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[12] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[1] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[3] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[5] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[7])) & BYTE_MASK)];
    y[2] = T[(((byte) (x[3] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[5] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[7] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[13] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[2] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[4] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[6] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[8])) & BYTE_MASK)];
    y[3] = T[(((byte) (x[4] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[6] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[8] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[14] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[3] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[5] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[7] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[9])) & BYTE_MASK)];
    y[4] = T[(((byte) (x[5] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[7] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[9] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[15] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[4] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[6] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[8] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[10])) & BYTE_MASK)];
    y[5] = T[(((byte) (x[6] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[8] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[10] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[0] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[5] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[7] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[9] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[11])) & BYTE_MASK)];
    y[6] = T[(((byte) (x[7] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[9] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[11] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[1] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[6] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[8] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[10] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[12])) & BYTE_MASK)];
    y[7] = T[(((byte) (x[8] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[10] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[12] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[2] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[7] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[9] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[11] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[13])) & BYTE_MASK)];
    y[8] = T[(((byte) (x[9] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[11] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[13] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[3] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[8] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[10] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[12] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[14])) & BYTE_MASK)];
    y[9] = T[(((byte) (x[10] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[12] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[14] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[4] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[9] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[11] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[13] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[15])) & BYTE_MASK)];
    y[10] = T[(((byte) (x[11] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[13] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[15] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[5] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[10] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[12] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[14] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[0])) & BYTE_MASK)];
    y[11] = T[(((byte) (x[12] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[14] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[0] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[6] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[11] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[13] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[15] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[1])) & BYTE_MASK)];
    y[12] = T[(((byte) (x[13] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[15] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[1] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[7] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[12] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[14] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[0] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[2])) & BYTE_MASK)];
    y[13] = T[(((byte) (x[14] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[0] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[2] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[8] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[13] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[15] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[1] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[3])) & BYTE_MASK)];
    y[14] = T[(((byte) (x[15] >>> 56)) & BYTE_MASK)]
        ^ T[256 + (((byte) (x[1] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[3] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[9] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[14] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[0] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[2] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[4])) & BYTE_MASK)];
    y[15] = T[(((byte) (x[0] >>> 56)) & BYTE_MASK)] ^ T[256 + (((byte) (x[2] >>> 48)) & BYTE_MASK)]
        ^ T[512 + (((byte) (x[4] >>> 40)) & BYTE_MASK)]
        ^ T[768 + (((byte) (x[10] >>> 32)) & BYTE_MASK)]
        ^ T[1024 + (((byte) (x[15] >>> 24)) & BYTE_MASK)]
        ^ T[1280 + (((byte) (x[1] >>> 16)) & BYTE_MASK)]
        ^ T[1536 + (((byte) (x[3] >>> 8)) & BYTE_MASK)] ^ T[1792 + (((byte) (x[5])) & BYTE_MASK)];
  }

  /**
   * The compression function (long variant).
   * 
   * @param input
   *          the input to be compressed
   * @param offset
   *          the input offset
   */
  @Override
  public final void engineCompress(final byte[] input, final int offset) {
    final long[] z = z_;
    final long[] y = y_;
    final long[] inP = inP_;
    final long[] outQ = outQ_;
    final long[] chaining = chaining_;

    Util.squashBytesToLongs(input, offset, z, 0, COLS);

    // for (int i = 0; i < COLS; i++) {
    // inP[i] = chaining[i] ^ z[i];
    // }

    inP[0] = chaining[0] ^ z[0];
    inP[1] = chaining[1] ^ z[1];
    inP[2] = chaining[2] ^ z[2];
    inP[3] = chaining[3] ^ z[3];
    inP[4] = chaining[4] ^ z[4];
    inP[5] = chaining[5] ^ z[5];
    inP[6] = chaining[6] ^ z[6];
    inP[7] = chaining[7] ^ z[7];
    inP[8] = chaining[8] ^ z[8];
    inP[9] = chaining[9] ^ z[9];
    inP[10] = chaining[10] ^ z[10];
    inP[11] = chaining[11] ^ z[11];
    inP[12] = chaining[12] ^ z[12];
    inP[13] = chaining[13] ^ z[13];
    inP[14] = chaining[14] ^ z[14];
    inP[15] = chaining[15] ^ z[15];

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
    RNDQ2(y, z);
    RNDQ1(z, ~10);
    RNDQ2(z, y);
    RNDQ1(y, ~11);
    RNDQ2(y, z);
    RNDQ1(z, ~12);
    RNDQ2(z, y);
    RNDQ1(y, ~13);
    RNDQ2(y, outQ);

    // compute P(h+m)
    inP[1] ^= 0x1000000000000000l;
    inP[2] ^= 0x2000000000000000l;
    inP[3] ^= 0x3000000000000000l;
    inP[4] ^= 0x4000000000000000l;
    inP[5] ^= 0x5000000000000000l;
    inP[6] ^= 0x6000000000000000l;
    inP[7] ^= 0x7000000000000000l;
    inP[8] ^= 0x8000000000000000l;
    inP[9] ^= 0x9000000000000000l;
    inP[10] ^= 0xa000000000000000l;
    inP[11] ^= 0xb000000000000000l;
    inP[12] ^= 0xc000000000000000l;
    inP[13] ^= 0xd000000000000000l;
    inP[14] ^= 0xe000000000000000l;
    inP[15] ^= 0xf000000000000000l;
    RNDP2(inP, z);
    RNDP1(z, 1L << 56);
    RNDP2(z, y);
    RNDP1(y, 2L << 56);
    RNDP2(y, z);
    RNDP1(z, 3L << 56);
    RNDP2(z, y);
    RNDP1(y, 4L << 56);
    RNDP2(y, z);
    RNDP1(z, 5L << 56);
    RNDP2(z, y);
    RNDP1(y, 6L << 56);
    RNDP2(y, z);
    RNDP1(z, 7L << 56);
    RNDP2(z, y);
    RNDP1(y, 8L << 56);
    RNDP2(y, z);
    RNDP1(z, 9L << 56);
    RNDP2(z, y);
    RNDP1(y, 10L << 56);
    RNDP2(y, z);
    RNDP1(z, 11L << 56);
    RNDP2(z, y);
    RNDP1(y, 12L << 56);
    RNDP2(y, z);
    RNDP1(z, 13L << 56);
    RNDP2(z, y);

    // h' == h + Q(m) + P(h+m)
    chaining[0] ^= outQ[0] ^ y[0];
    chaining[1] ^= outQ[1] ^ y[1];
    chaining[2] ^= outQ[2] ^ y[2];
    chaining[3] ^= outQ[3] ^ y[3];
    chaining[4] ^= outQ[4] ^ y[4];
    chaining[5] ^= outQ[5] ^ y[5];
    chaining[6] ^= outQ[6] ^ y[6];
    chaining[7] ^= outQ[7] ^ y[7];
    chaining[8] ^= outQ[8] ^ y[8];
    chaining[9] ^= outQ[9] ^ y[9];
    chaining[10] ^= outQ[10] ^ y[10];
    chaining[11] ^= outQ[11] ^ y[11];
    chaining[12] ^= outQ[12] ^ y[12];
    chaining[13] ^= outQ[13] ^ y[13];
    chaining[14] ^= outQ[14] ^ y[14];
    chaining[15] ^= outQ[15] ^ y[15];

    // for (int i = 0; i < COLS; i++) {
    // chaining[i] ^= outQ[i] ^ y[i];
    // }
  }

  /**
   * Performs the output transformation and returns the digest.
   */
  @Override
  public void engineGetDigest(byte[] output, int offset) {
    final long[] temp = chaining_.clone();

    // output transformation
    RNDP1(temp, 0);
    RNDP2(temp, y_);
    for (long i = 1; i < (ROUNDS - 1); i += 2) {
      RNDP1(y_, i << 56);
      RNDP2(y_, z_);
      RNDP1(z_, (i + 1) << 56);
      RNDP2(z_, y_);
    }
    RNDP1(y_, (ROUNDS - 1) << 56);
    RNDP2(y_, temp);

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
