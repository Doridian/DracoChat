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
 * JH implementation optimized for 64-bit platforms.
 * 
 * @author Christian Hanser
 */
final class RawJH64Bit extends RawJH {

  private static final int BLOCK_SIZE = 8;

  private final static long[] ROUND_CONSTANTS = new long[42 * 4];

  // compile the round constants
  static {
    Util.squashBytesToLongsLE(ROUND_CONSTANTS_BYTES, 0, ROUND_CONSTANTS, 0, ROUND_CONSTANTS.length);
  }

  // the initialization vectors
  private final long[] iv_ = new long[16];

  // the chaining vars
  private long H0_, H1_, H2_, H3_, H4_, H5_, H6_, H7_, H8_, H9_, H10_, H11_, H12_, H13_, H14_,
      H15_;

  // helper variables
  private final byte[] digestTemp_;
  private final long[] inTemp_ = new long[8];
  private final long[] temp_ = new long[2];

  /**
   * Constructs a new instance.
   * 
   * @param digestLength_
   *          the digest length in bytes
   * @param blockSize_
   *          the block size in bytes
   * @param initValue
   *          the initialization vectors
   */
  public RawJH64Bit(int digestLength, int blockSize, byte[] initValue) {
    super(digestLength, blockSize);
    Util.squashBytesToLongsLE(initValue, 0, iv_, 0, iv_.length);
    digestTemp_ = new byte[((digestLength + 7) >>> 3) << 3];

    engineReset();
  }

  /**
   * Swaps bit 2i with bit 2i+1 of x
   * 
   * @param x
   *          the long value x
   */
  private static long SWAP1(long x) {
    return ((x & 0x5555555555555555L) << 1) | ((x & 0xaaaaaaaaaaaaaaaaL) >>> 1);
  }

  /**
   * Swaps bits 4i||4i+1 with bits 4i+2||4i+3 of x
   * 
   * @param x
   *          the long value x
   */
  private static long SWAP2(long x) {
    return ((x & 0x3333333333333333L) << 2) | ((x & 0xccccccccccccccccL) >>> 2);
  }

  /**
   * Swaps bits 8i||8i+1||8i+2||8i+3 with bits 8i+4||8i+5||8i+6||8i+7 of 64-bit
   * x
   * 
   * @param x
   *          the long value x
   */
  private static long SWAP4(long x) {
    return ((x & 0x0f0f0f0f0f0f0f0fL) << 4) | ((x & 0xf0f0f0f0f0f0f0f0L) >>> 4);
  }

  /**
   * Swaps bits 16i||16i+1||......||16i+7 with bits 16i+8||16i+9||......||16i+15
   * of 64-bit x
   * 
   * @param x
   *          the long value x
   */
  private static long SWAP8(long x) {
    return ((x & 0x00ff00ff00ff00ffL) << 8) | ((x & 0xff00ff00ff00ff00L) >>> 8);
  }

  /**
   * Swaps bits 32i||32i+1||......||32i+15 with bits <<
   * 5)i+16||32i+17||......||32i+31 of x
   * 
   * @param x
   *          the long value x
   */
  private static long SWAP16(long x) {
    return ((x & 0x0000ffff0000ffffL) << 16) | ((x & 0xffff0000ffff0000L) >>> 16);
  }

  /**
   * Swaps bits 64i||64i+1||......||64i+31 with bits
   * 64i+32||64i+33||......||64i+63 of x
   * 
   * @param x
   *          the long value x
   */
  private static long SWAP32(long x) {
    return (x << 32) | (x >>> 32);
  }

  /**
   * The bijective function E8, in bitslice form
   * 
   * @param state
   *          reference to the current state
   */
  private void E8(long[] temp) {
    for (int r = 0; r < (42 * 4); r += 28) {
      // round 7*roundnumber+0: Sbox, MDS and Swapping layers
      int j = r;
      final long cc0 = ROUND_CONSTANTS[j];
      final long cc1 = ROUND_CONSTANTS[j + 2];
      H12_ = ~H12_;
      H14_ = ~H14_;
      H0_ ^= (~H8_ & cc0);
      H2_ ^= (~H10_ & cc1);
      temp[0] = cc0 ^ (H0_ & H4_);
      temp[1] = cc1 ^ (H2_ & H6_);
      H0_ ^= (H8_ & H12_);
      H2_ ^= (H10_ & H14_);
      H12_ ^= (~H4_ & H8_);
      H14_ ^= (~H6_ & H10_);
      H4_ ^= (H0_ & H8_);
      H6_ ^= (H2_ & H10_);
      H8_ ^= (H0_ & ~H12_);
      H10_ ^= (H2_ & ~H14_);
      H0_ ^= (H4_ | H12_);
      H2_ ^= (H6_ | H14_);
      H12_ ^= (H4_ & H8_);
      H14_ ^= (H6_ & H10_);
      H4_ ^= (temp[0] & H0_);
      H6_ ^= (temp[1] & H2_);
      H8_ ^= temp[0];
      H10_ ^= temp[1];
      H2_ ^= H4_;
      H6_ ^= H8_;
      H10_ ^= H0_ ^ H12_;
      H14_ ^= H0_;
      H0_ ^= H6_;
      H4_ ^= H10_;
      H8_ ^= H2_ ^ H14_;
      H12_ ^= H2_;
      H2_ = SWAP1(H2_);
      H6_ = SWAP1(H6_);
      H10_ = SWAP1(H10_);
      H14_ = SWAP1(H14_);

      final long cc01 = ROUND_CONSTANTS[++j];
      final long cc11 = ROUND_CONSTANTS[j + 2];
      H13_ = ~H13_;
      H15_ = ~H15_;
      H1_ ^= (~H9_ & cc01);
      H3_ ^= (~H11_ & cc11);
      temp[0] = cc01 ^ (H1_ & H5_);
      temp[1] = cc11 ^ (H3_ & H7_);
      H1_ ^= (H9_ & H13_);
      H3_ ^= (H11_ & H15_);
      H13_ ^= (~H5_ & H9_);
      H15_ ^= (~H7_ & H11_);
      H5_ ^= (H1_ & H9_);
      H7_ ^= (H3_ & H11_);
      H9_ ^= (H1_ & ~H13_);
      H11_ ^= (H3_ & ~H15_);
      H1_ ^= (H5_ | H13_);
      H3_ ^= (H7_ | H15_);
      H13_ ^= (H5_ & H9_);
      H15_ ^= (H7_ & H11_);
      H5_ ^= (temp[0] & H1_);
      H7_ ^= (temp[1] & H3_);
      H9_ ^= temp[0];
      H11_ ^= temp[1];
      H3_ ^= H5_;
      H7_ ^= H9_;
      H11_ ^= H1_ ^ H13_;
      H15_ ^= H1_;
      H1_ ^= H7_;
      H5_ ^= H11_;
      H9_ ^= H3_ ^ H15_;
      H13_ ^= H3_;
      H3_ = SWAP1(H3_);
      H7_ = SWAP1(H7_);
      H11_ = SWAP1(H11_);
      H15_ = SWAP1(H15_);

      // round 7*roundnumber+1: Sbox, MDS and Swapping layers
      j = r + 4;
      final long cc02 = ROUND_CONSTANTS[j];
      final long cc12 = ROUND_CONSTANTS[j + 2];
      H12_ = ~H12_;
      H14_ = ~H14_;
      H0_ ^= (~H8_ & cc02);
      H2_ ^= (~H10_ & cc12);
      temp[0] = cc02 ^ (H0_ & H4_);
      temp[1] = cc12 ^ (H2_ & H6_);
      H0_ ^= (H8_ & H12_);
      H2_ ^= (H10_ & H14_);
      H12_ ^= (~H4_ & H8_);
      H14_ ^= (~H6_ & H10_);
      H4_ ^= (H0_ & H8_);
      H6_ ^= (H2_ & H10_);
      H8_ ^= (H0_ & ~H12_);
      H10_ ^= (H2_ & ~H14_);
      H0_ ^= (H4_ | H12_);
      H2_ ^= (H6_ | H14_);
      H12_ ^= (H4_ & H8_);
      H14_ ^= (H6_ & H10_);
      H4_ ^= (temp[0] & H0_);
      H6_ ^= (temp[1] & H2_);
      H8_ ^= temp[0];
      H10_ ^= temp[1];
      H2_ ^= H4_;
      H6_ ^= H8_;
      H10_ ^= H0_ ^ H12_;
      H14_ ^= H0_;
      H0_ ^= H6_;
      H4_ ^= H10_;
      H8_ ^= H2_ ^ H14_;
      H12_ ^= H2_;
      H2_ = SWAP2(H2_);
      H6_ = SWAP2(H6_);
      H10_ = SWAP2(H10_);
      H14_ = SWAP2(H14_);

      final long cc03 = ROUND_CONSTANTS[++j];
      final long cc13 = ROUND_CONSTANTS[j + 2];
      H13_ = ~H13_;
      H15_ = ~H15_;
      H1_ ^= (~H9_ & cc03);
      H3_ ^= (~H11_ & cc13);
      temp[0] = cc03 ^ (H1_ & H5_);
      temp[1] = cc13 ^ (H3_ & H7_);
      H1_ ^= (H9_ & H13_);
      H3_ ^= (H11_ & H15_);
      H13_ ^= (~H5_ & H9_);
      H15_ ^= (~H7_ & H11_);
      H5_ ^= (H1_ & H9_);
      H7_ ^= (H3_ & H11_);
      H9_ ^= (H1_ & ~H13_);
      H11_ ^= (H3_ & ~H15_);
      H1_ ^= (H5_ | H13_);
      H3_ ^= (H7_ | H15_);
      H13_ ^= (H5_ & H9_);
      H15_ ^= (H7_ & H11_);
      H5_ ^= (temp[0] & H1_);
      H7_ ^= (temp[1] & H3_);
      H9_ ^= temp[0];
      H11_ ^= temp[1];
      H3_ ^= H5_;
      H7_ ^= H9_;
      H11_ ^= H1_ ^ H13_;
      H15_ ^= H1_;
      H1_ ^= H7_;
      H5_ ^= H11_;
      H9_ ^= H3_ ^ H15_;
      H13_ ^= H3_;

      H3_ = SWAP2(H3_);
      H7_ = SWAP2(H7_);
      H11_ = SWAP2(H11_);
      H15_ = SWAP2(H15_);

      // round 7*roundnumber+2: Sbox, MDS and Swapping layers
      j = r + 8;
      final long cc04 = ROUND_CONSTANTS[j];
      final long cc14 = ROUND_CONSTANTS[j + 2];
      H12_ = ~H12_;
      H14_ = ~H14_;
      H0_ ^= (~H8_ & cc04);
      H2_ ^= (~H10_ & cc14);
      temp[0] = cc04 ^ (H0_ & H4_);
      temp[1] = cc14 ^ (H2_ & H6_);
      H0_ ^= (H8_ & H12_);
      H2_ ^= (H10_ & H14_);
      H12_ ^= (~H4_ & H8_);
      H14_ ^= (~H6_ & H10_);
      H4_ ^= (H0_ & H8_);
      H6_ ^= (H2_ & H10_);
      H8_ ^= (H0_ & ~H12_);
      H10_ ^= (H2_ & ~H14_);
      H0_ ^= (H4_ | H12_);
      H2_ ^= (H6_ | H14_);
      H12_ ^= (H4_ & H8_);
      H14_ ^= (H6_ & H10_);
      H4_ ^= (temp[0] & H0_);
      H6_ ^= (temp[1] & H2_);
      H8_ ^= temp[0];
      H10_ ^= temp[1];
      H2_ ^= H4_;
      H6_ ^= H8_;
      H10_ ^= H0_ ^ H12_;
      H14_ ^= H0_;
      H0_ ^= H6_;
      H4_ ^= H10_;
      H8_ ^= H2_ ^ H14_;
      H12_ ^= H2_;
      H2_ = SWAP4(H2_);
      H6_ = SWAP4(H6_);
      H10_ = SWAP4(H10_);
      H14_ = SWAP4(H14_);

      final long cc05 = ROUND_CONSTANTS[++j];
      final long cc15 = ROUND_CONSTANTS[j + 2];
      H13_ = ~H13_;
      H15_ = ~H15_;
      H1_ ^= (~H9_ & cc05);
      H3_ ^= (~H11_ & cc15);
      temp[0] = cc05 ^ (H1_ & H5_);
      temp[1] = cc15 ^ (H3_ & H7_);
      H1_ ^= (H9_ & H13_);
      H3_ ^= (H11_ & H15_);
      H13_ ^= (~H5_ & H9_);
      H15_ ^= (~H7_ & H11_);
      H5_ ^= (H1_ & H9_);
      H7_ ^= (H3_ & H11_);
      H9_ ^= (H1_ & ~H13_);
      H11_ ^= (H3_ & ~H15_);
      H1_ ^= (H5_ | H13_);
      H3_ ^= (H7_ | H15_);
      H13_ ^= (H5_ & H9_);
      H15_ ^= (H7_ & H11_);
      H5_ ^= (temp[0] & H1_);
      H7_ ^= (temp[1] & H3_);
      H9_ ^= temp[0];
      H11_ ^= temp[1];
      H3_ ^= H5_;
      H7_ ^= H9_;
      H11_ ^= H1_ ^ H13_;
      H15_ ^= H1_;
      H1_ ^= H7_;
      H5_ ^= H11_;
      H9_ ^= H3_ ^ H15_;
      H13_ ^= H3_;
      H3_ = SWAP4(H3_);
      H7_ = SWAP4(H7_);
      H11_ = SWAP4(H11_);
      H15_ = SWAP4(H15_);

      // round 7*roundnumber+3: Sbox, MDS and Swapping layers
      j = r + 12;
      final long cc06 = ROUND_CONSTANTS[j];
      final long cc16 = ROUND_CONSTANTS[j + 2];
      H12_ = ~H12_;
      H14_ = ~H14_;
      H0_ ^= (~H8_ & cc06);
      H2_ ^= (~H10_ & cc16);
      temp[0] = cc06 ^ (H0_ & H4_);
      temp[1] = cc16 ^ (H2_ & H6_);
      H0_ ^= (H8_ & H12_);
      H2_ ^= (H10_ & H14_);
      H12_ ^= (~H4_ & H8_);
      H14_ ^= (~H6_ & H10_);
      H4_ ^= (H0_ & H8_);
      H6_ ^= (H2_ & H10_);
      H8_ ^= (H0_ & ~H12_);
      H10_ ^= (H2_ & ~H14_);
      H0_ ^= (H4_ | H12_);
      H2_ ^= (H6_ | H14_);
      H12_ ^= (H4_ & H8_);
      H14_ ^= (H6_ & H10_);
      H4_ ^= (temp[0] & H0_);
      H6_ ^= (temp[1] & H2_);
      H8_ ^= temp[0];
      H10_ ^= temp[1];
      H2_ ^= H4_;
      H6_ ^= H8_;
      H10_ ^= H0_ ^ H12_;
      H14_ ^= H0_;
      H0_ ^= H6_;
      H4_ ^= H10_;
      H8_ ^= H2_ ^ H14_;
      H12_ ^= H2_;
      H2_ = SWAP8(H2_);
      H6_ = SWAP8(H6_);
      H10_ = SWAP8(H10_);
      H14_ = SWAP8(H14_);

      final long cc07 = ROUND_CONSTANTS[++j];
      final long cc17 = ROUND_CONSTANTS[j + 2];
      H13_ = ~H13_;
      H15_ = ~H15_;
      H1_ ^= (~H9_ & cc07);
      H3_ ^= (~H11_ & cc17);
      temp[0] = cc07 ^ (H1_ & H5_);
      temp[1] = cc17 ^ (H3_ & H7_);
      H1_ ^= (H9_ & H13_);
      H3_ ^= (H11_ & H15_);
      H13_ ^= (~H5_ & H9_);
      H15_ ^= (~H7_ & H11_);
      H5_ ^= (H1_ & H9_);
      H7_ ^= (H3_ & H11_);
      H9_ ^= (H1_ & ~H13_);
      H11_ ^= (H3_ & ~H15_);
      H1_ ^= (H5_ | H13_);
      H3_ ^= (H7_ | H15_);
      H13_ ^= (H5_ & H9_);
      H15_ ^= (H7_ & H11_);
      H5_ ^= (temp[0] & H1_);
      H7_ ^= (temp[1] & H3_);
      H9_ ^= temp[0];
      H11_ ^= temp[1];
      H3_ ^= H5_;
      H7_ ^= H9_;
      H11_ ^= H1_ ^ H13_;
      H15_ ^= H1_;
      H1_ ^= H7_;
      H5_ ^= H11_;
      H9_ ^= H3_ ^ H15_;
      H13_ ^= H3_;
      H3_ = SWAP8(H3_);
      H7_ = SWAP8(H7_);
      H11_ = SWAP8(H11_);
      H15_ = SWAP8(H15_);

      // round 7*roundnumber+4: Sbox, MDS and Swapping layers
      j = r + 16;
      final long cc08 = ROUND_CONSTANTS[j];
      final long cc18 = ROUND_CONSTANTS[j + 2];
      H12_ = ~H12_;
      H14_ = ~H14_;
      H0_ ^= (~H8_ & cc08);
      H2_ ^= (~H10_ & cc18);
      temp[0] = cc08 ^ (H0_ & H4_);
      temp[1] = cc18 ^ (H2_ & H6_);
      H0_ ^= (H8_ & H12_);
      H2_ ^= (H10_ & H14_);
      H12_ ^= (~H4_ & H8_);
      H14_ ^= (~H6_ & H10_);
      H4_ ^= (H0_ & H8_);
      H6_ ^= (H2_ & H10_);
      H8_ ^= (H0_ & ~H12_);
      H10_ ^= (H2_ & ~H14_);
      H0_ ^= (H4_ | H12_);
      H2_ ^= (H6_ | H14_);
      H12_ ^= (H4_ & H8_);
      H14_ ^= (H6_ & H10_);
      H4_ ^= (temp[0] & H0_);
      H6_ ^= (temp[1] & H2_);
      H8_ ^= temp[0];
      H10_ ^= temp[1];
      H2_ ^= H4_;
      H6_ ^= H8_;
      H10_ ^= H0_ ^ H12_;
      H14_ ^= H0_;
      H0_ ^= H6_;
      H4_ ^= H10_;
      H8_ ^= H2_ ^ H14_;
      H12_ ^= H2_;
      H2_ = SWAP16(H2_);
      H6_ = SWAP16(H6_);
      H10_ = SWAP16(H10_);
      H14_ = SWAP16(H14_);

      final long cc09 = ROUND_CONSTANTS[++j];
      final long cc19 = ROUND_CONSTANTS[j + 2];
      H13_ = ~H13_;
      H15_ = ~H15_;
      H1_ ^= (~H9_ & cc09);
      H3_ ^= (~H11_ & cc19);
      temp[0] = cc09 ^ (H1_ & H5_);
      temp[1] = cc19 ^ (H3_ & H7_);
      H1_ ^= (H9_ & H13_);
      H3_ ^= (H11_ & H15_);
      H13_ ^= (~H5_ & H9_);
      H15_ ^= (~H7_ & H11_);
      H5_ ^= (H1_ & H9_);
      H7_ ^= (H3_ & H11_);
      H9_ ^= (H1_ & ~H13_);
      H11_ ^= (H3_ & ~H15_);
      H1_ ^= (H5_ | H13_);
      H3_ ^= (H7_ | H15_);
      H13_ ^= (H5_ & H9_);
      H15_ ^= (H7_ & H11_);
      H5_ ^= (temp[0] & H1_);
      H7_ ^= (temp[1] & H3_);
      H9_ ^= temp[0];
      H11_ ^= temp[1];
      H3_ ^= H5_;
      H7_ ^= H9_;
      H11_ ^= H1_ ^ H13_;
      H15_ ^= H1_;
      H1_ ^= H7_;
      H5_ ^= H11_;
      H9_ ^= H3_ ^ H15_;
      H13_ ^= H3_;
      H3_ = SWAP16(H3_);
      H7_ = SWAP16(H7_);
      H11_ = SWAP16(H11_);
      H15_ = SWAP16(H15_);

      // round 7*roundnumber+5: Sbox, MDS and Swapping layers
      j = r + 20;
      final long cc010 = ROUND_CONSTANTS[j];
      final long cc110 = ROUND_CONSTANTS[j + 2];
      H12_ = ~H12_;
      H14_ = ~H14_;
      H0_ ^= (~H8_ & cc010);
      H2_ ^= (~H10_ & cc110);
      temp[0] = cc010 ^ (H0_ & H4_);
      temp[1] = cc110 ^ (H2_ & H6_);
      H0_ ^= (H8_ & H12_);
      H2_ ^= (H10_ & H14_);
      H12_ ^= (~H4_ & H8_);
      H14_ ^= (~H6_ & H10_);
      H4_ ^= (H0_ & H8_);
      H6_ ^= (H2_ & H10_);
      H8_ ^= (H0_ & ~H12_);
      H10_ ^= (H2_ & ~H14_);
      H0_ ^= (H4_ | H12_);
      H2_ ^= (H6_ | H14_);
      H12_ ^= (H4_ & H8_);
      H14_ ^= (H6_ & H10_);
      H4_ ^= (temp[0] & H0_);
      H6_ ^= (temp[1] & H2_);
      H8_ ^= temp[0];
      H10_ ^= temp[1];
      H2_ ^= H4_;
      H6_ ^= H8_;
      H10_ ^= H0_ ^ H12_;
      H14_ ^= H0_;
      H0_ ^= H6_;
      H4_ ^= H10_;
      H8_ ^= H2_ ^ H14_;
      H12_ ^= H2_;
      H2_ = SWAP32(H2_);
      H6_ = SWAP32(H6_);
      H10_ = SWAP32(H10_);
      H14_ = SWAP32(H14_);

      final long cc011 = ROUND_CONSTANTS[++j];
      final long cc111 = ROUND_CONSTANTS[j + 2];
      H13_ = ~H13_;
      H15_ = ~H15_;
      H1_ ^= (~H9_ & cc011);
      H3_ ^= (~H11_ & cc111);
      temp[0] = cc011 ^ (H1_ & H5_);
      temp[1] = cc111 ^ (H3_ & H7_);
      H1_ ^= (H9_ & H13_);
      H3_ ^= (H11_ & H15_);
      H13_ ^= (~H5_ & H9_);
      H15_ ^= (~H7_ & H11_);
      H5_ ^= (H1_ & H9_);
      H7_ ^= (H3_ & H11_);
      H9_ ^= (H1_ & ~H13_);
      H11_ ^= (H3_ & ~H15_);
      H1_ ^= (H5_ | H13_);
      H3_ ^= (H7_ | H15_);
      H13_ ^= (H5_ & H9_);
      H15_ ^= (H7_ & H11_);
      H5_ ^= (temp[0] & H1_);
      H7_ ^= (temp[1] & H3_);
      H9_ ^= temp[0];
      H11_ ^= temp[1];
      H3_ ^= H5_;
      H7_ ^= H9_;
      H11_ ^= H1_ ^ H13_;
      H15_ ^= H1_;
      H1_ ^= H7_;
      H5_ ^= H11_;
      H9_ ^= H3_ ^ H15_;
      H13_ ^= H3_;
      H3_ = SWAP32(H3_);
      H7_ = SWAP32(H7_);
      H11_ = SWAP32(H11_);
      H15_ = SWAP32(H15_);

      // round 7*roundnumber+6: Sbox and MDS layers
      j = r + 24;
      final long cc012 = ROUND_CONSTANTS[j];
      final long cc112 = ROUND_CONSTANTS[j + 2];
      H12_ = ~H12_;
      H14_ = ~H14_;
      H0_ ^= (~H8_ & cc012);
      H2_ ^= (~H10_ & cc112);
      temp[0] = cc012 ^ (H0_ & H4_);
      temp[1] = cc112 ^ (H2_ & H6_);
      H0_ ^= (H8_ & H12_);
      H2_ ^= (H10_ & H14_);
      H12_ ^= (~H4_ & H8_);
      H14_ ^= (~H6_ & H10_);
      H4_ ^= (H0_ & H8_);
      H6_ ^= (H2_ & H10_);
      H8_ ^= (H0_ & ~H12_);
      H10_ ^= (H2_ & ~H14_);
      H0_ ^= (H4_ | H12_);
      H2_ ^= (H6_ | H14_);
      H12_ ^= (H4_ & H8_);
      H14_ ^= (H6_ & H10_);
      H4_ ^= (temp[0] & H0_);
      H6_ ^= (temp[1] & H2_);
      H8_ ^= temp[0];
      H10_ ^= temp[1];
      H2_ ^= H4_;
      H6_ ^= H8_;
      H10_ ^= H0_ ^ H12_;
      H14_ ^= H0_;
      H0_ ^= H6_;
      H4_ ^= H10_;
      H8_ ^= H2_ ^ H14_;
      H12_ ^= H2_;

      final long cc013 = ROUND_CONSTANTS[++j];
      final long cc113 = ROUND_CONSTANTS[j + 2];
      H13_ = ~H13_;
      H15_ = ~H15_;
      H1_ ^= (~H9_ & cc013);
      H3_ ^= (~H11_ & cc113);
      temp[0] = cc013 ^ (H1_ & H5_);
      temp[1] = cc113 ^ (H3_ & H7_);
      H1_ ^= (H9_ & H13_);
      H3_ ^= (H11_ & H15_);
      H13_ ^= (~H5_ & H9_);
      H15_ ^= (~H7_ & H11_);
      H5_ ^= (H1_ & H9_);
      H7_ ^= (H3_ & H11_);
      H9_ ^= (H1_ & ~H13_);
      H11_ ^= (H3_ & ~H15_);
      H1_ ^= (H5_ | H13_);
      H3_ ^= (H7_ | H15_);
      H13_ ^= (H5_ & H9_);
      H15_ ^= (H7_ & H11_);
      H5_ ^= (temp[0] & H1_);
      H7_ ^= (temp[1] & H3_);
      H9_ ^= temp[0];
      H11_ ^= temp[1];
      H3_ ^= H5_;
      H7_ ^= H9_;
      H11_ ^= H1_ ^ H13_;
      H15_ ^= H1_;
      H1_ ^= H7_;
      H5_ ^= H11_;
      H9_ ^= H3_ ^ H15_;
      H13_ ^= H3_;

      // round 7*roundnumber+6: swapping layer
      long swapTemp = H2_;
      H2_ = H3_;
      H3_ = swapTemp;

      swapTemp = H6_;
      H6_ = H7_;
      H7_ = swapTemp;

      swapTemp = H10_;
      H10_ = H11_;
      H11_ = swapTemp;

      swapTemp = H14_;
      H14_ = H15_;
      H15_ = swapTemp;
    }
  }

  @Override
  void engineCompress(byte[] input, int offset) {
    Util.squashBytesToLongsLE(input, offset, inTemp_, 0, BLOCK_SIZE);

    H0_ ^= inTemp_[0];
    H1_ ^= inTemp_[1];
    H2_ ^= inTemp_[2];
    H3_ ^= inTemp_[3];
    H4_ ^= inTemp_[4];
    H5_ ^= inTemp_[5];
    H6_ ^= inTemp_[6];
    H7_ ^= inTemp_[7];

    // the bijective function E8
    E8(temp_);

    H8_ ^= inTemp_[0];
    H9_ ^= inTemp_[1];
    H10_ ^= inTemp_[2];
    H11_ ^= inTemp_[3];
    H12_ ^= inTemp_[4];
    H13_ ^= inTemp_[5];
    H14_ ^= inTemp_[6];
    H15_ ^= inTemp_[7];
  }

  @Override
  protected void engineReset() {
    super.engineReset();

    H0_ = iv_[0];
    H1_ = iv_[1];
    H2_ = iv_[2];
    H3_ = iv_[3];
    H4_ = iv_[4];
    H5_ = iv_[5];
    H6_ = iv_[6];
    H7_ = iv_[7];
    H8_ = iv_[8];
    H9_ = iv_[9];
    H10_ = iv_[10];
    H11_ = iv_[11];
    H12_ = iv_[12];
    H13_ = iv_[13];
    H14_ = iv_[14];
    H15_ = iv_[15];

    Util.zeroBlock(digestTemp_);
    Util.zeroBlock(temp_);
    Util.zeroBlock(inTemp_);
  }

  @Override
  void engineGetDigest(byte[] output, int offset) {
    final long[] state = { H0_, H1_, H2_, H3_, H4_, H5_, H6_, H7_, H8_, H9_, H10_, H11_, H12_,
        H13_, H14_, H15_ };

    Util.spreadLongsToBytesLE(state, state.length - (digestTemp_.length >>> 3), digestTemp_, 0,
        digestTemp_.length >>> 3);

    System
        .arraycopy(digestTemp_, digestTemp_.length - digestLength_, output, offset, digestLength_);
  }

}
