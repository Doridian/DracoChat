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
 * JH implementation optimized for 32-bit platforms.
 * 
 * @author Christian Hanser
 */
final class RawJH32Bit extends RawJH {

  private final static int[] ROUND_CONSTANTS = new int[42 << 3];

  // compile the round constants
  static {
    Util.squashBytesToIntsLE(ROUND_CONSTANTS_BYTES, 0, ROUND_CONSTANTS, 0, ROUND_CONSTANTS.length);
  }

  // the initialization vectors
  private final int[] iv_ = new int[32];

  // the chaining vars
  private final int[] state_ = new int[32];

  // helper variables
  private final byte[] digestTemp_;
  private final int[] inTemp_ = new int[16];

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
  public RawJH32Bit(int digestLength, int blockSize, byte[] iv) {
    super(digestLength, blockSize);
    Util.squashBytesToIntsLE(iv, 0, iv_, 0, iv_.length);
    digestTemp_ = new byte[((digestLength + 7) >>> 3) << 3];

    engineReset();
  }

  /**
   * Swaps bit 2i with bit 2i+1 of x
   * 
   * @param x
   *          the long value x
   */
  private static int SWAP1(int x) {
    return ((x & 0x55555555) << 1) | ((x & 0xaaaaaaaa) >>> 1);
  }

  /**
   * Swaps bits 4i||4i+1 with bits 4i+2||4i+3 of x
   * 
   * @param x
   *          the long value x
   */
  private static int SWAP2(int x) {
    return ((x & 0x33333333) << 2) | ((x & 0xcccccccc) >>> 2);
  }

  /**
   * swapping bits 8i||8i+1||8i+2||8i+3 with bits 8i+4||8i+5||8i+6||8i+7 of
   * 64-bit x
   * 
   * @param x
   *          the long value x
   */
  private static int SWAP4(int x) {
    return ((x & 0x0f0f0f0f) << 4) | ((x & 0xf0f0f0f0) >>> 4);
  }

  /**
   * swapping bits 16i||16i+1||......||16i+7 with bits
   * 16i+8||16i+9||......||16i+15 of 64-bit x
   * 
   * @param x
   *          the long value x
   */
  private static int SWAP8(int x) {
    return ((x & 0x00ff00ff) << 8) | ((x & 0xff00ff00) >>> 8);
  }

  /**
   * Swaps bits 32j||32j+1||......||32j+15 with bits
   * 32j+16||32j+17||......||32j+31 of x
   * 
   * @param x
   *          the long value x
   */
  private static int SWAP16(int x) {
    return (x << 16) | (x >>> 16);
  }

  private static void L(int[] state, int m0, int m1, int m2, int m3, int m4, int m5, int m6, int m7) {
    state[m4] ^= state[m1];
    state[m5] ^= state[m2];
    state[m6] ^= state[m0] ^ state[m3];
    state[m7] ^= state[m0];
    state[m0] ^= state[m5];
    state[m1] ^= state[m6];
    state[m2] ^= state[m4] ^ state[m7];
    state[m3] ^= state[m4];
  }

  /**
   * The bijective function E8, in bitslice form
   * 
   * @param state
   *          reference to the current state
   */
  private static void E8(int[] state) {
    int swapTemp;
    int temp;

    // perform 42 rounds
    for (int r = 0; r < 42; r += 7) {
      // round 7*roundnumber+0: Sbox, MDS and swapping layer
      for (int i = 0; i < 4; i++) {
        final int m1 = 8 + i;
        final int m2 = 16 + i;
        final int m3 = 24 + i;
        final int cc = ROUND_CONSTANTS[(r << 3) + i];
        state[m3] = ~state[m3];
        state[i] ^= (~state[m2] & cc);
        temp = cc ^ (state[i] & state[m1]);
        state[i] ^= (state[m2] & state[m3]);
        state[m3] ^= (~state[m1] & state[m2]);
        state[m1] ^= (state[i] & state[m2]);
        state[m2] ^= (state[i] & ~state[m3]);
        state[i] ^= (state[m1] | state[m3]);
        state[m3] ^= (state[m1] & state[m2]);
        state[m1] ^= (temp & state[i]);
        state[m2] ^= temp;
        final int m0 = 4 + i;
        final int m11 = 12 + i;
        final int m21 = 20 + i;
        final int m31 = 28 + i;
        final int cc1 = ROUND_CONSTANTS[(r << 3) + i + 4];
        state[m31] = ~state[m31];
        state[m0] ^= (~state[m21] & cc1);
        temp = cc1 ^ (state[m0] & state[m11]);
        state[m0] ^= (state[m21] & state[m31]);
        state[m31] ^= (~state[m11] & state[m21]);
        state[m11] ^= (state[m0] & state[m21]);
        state[m21] ^= (state[m0] & ~state[m31]);
        state[m0] ^= (state[m11] | state[m31]);
        state[m31] ^= (state[m11] & state[m21]);
        state[m11] ^= (temp & state[m0]);
        state[m21] ^= temp;
        L(state, i, 8 + i, 16 + i, 24 + i, 4 + i, 12 + i, 20 + i, 28 + i);

        state[4 + i] = SWAP1(state[4 + i]);
        state[12 + i] = SWAP1(state[12 + i]);
        state[20 + i] = SWAP1(state[20 + i]);
        state[28 + i] = SWAP1(state[28 + i]);
      }

      // round 7*roundnumber+1: Sbox, MDS and swapping layer
      for (int i = 0; i < 4; i++) {
        final int m1 = 8 + i;
        final int m2 = 16 + i;
        final int m3 = 24 + i;
        final int cc = ROUND_CONSTANTS[((r + 1) << 3) + i];
        state[m3] = ~state[m3];
        state[i] ^= (~state[m2] & cc);
        temp = cc ^ (state[i] & state[m1]);
        state[i] ^= (state[m2] & state[m3]);
        state[m3] ^= (~state[m1] & state[m2]);
        state[m1] ^= (state[i] & state[m2]);
        state[m2] ^= (state[i] & ~state[m3]);
        state[i] ^= (state[m1] | state[m3]);
        state[m3] ^= (state[m1] & state[m2]);
        state[m1] ^= (temp & state[i]);
        state[m2] ^= temp;
        final int m0 = 4 + i;
        final int m11 = 12 + i;
        final int m21 = 20 + i;
        final int m31 = 28 + i;
        final int cc1 = ROUND_CONSTANTS[((r + 1) << 3) + i + 4];
        state[m31] = ~state[m31];
        state[m0] ^= (~state[m21] & cc1);
        temp = cc1 ^ (state[m0] & state[m11]);
        state[m0] ^= (state[m21] & state[m31]);
        state[m31] ^= (~state[m11] & state[m21]);
        state[m11] ^= (state[m0] & state[m21]);
        state[m21] ^= (state[m0] & ~state[m31]);
        state[m0] ^= (state[m11] | state[m31]);
        state[m31] ^= (state[m11] & state[m21]);
        state[m11] ^= (temp & state[m0]);
        state[m21] ^= temp;
        L(state, i, 8 + i, 16 + i, 24 + i, 4 + i, 12 + i, 20 + i, 28 + i);

        state[4 + i] = SWAP2(state[4 + i]);
        state[12 + i] = SWAP2(state[12 + i]);
        state[20 + i] = SWAP2(state[20 + i]);
        state[28 + i] = SWAP2(state[28 + i]);
      }

      // round 7*roundnumber+2: Sbox, MDS and swapping layer
      for (int i = 0; i < 4; i++) {
        final int m1 = 8 + i;
        final int m2 = 16 + i;
        final int m3 = 24 + i;
        final int cc = ROUND_CONSTANTS[((r + 2) << 3) + i];
        state[m3] = ~state[m3];
        state[i] ^= (~state[m2] & cc);
        temp = cc ^ (state[i] & state[m1]);
        state[i] ^= (state[m2] & state[m3]);
        state[m3] ^= (~state[m1] & state[m2]);
        state[m1] ^= (state[i] & state[m2]);
        state[m2] ^= (state[i] & ~state[m3]);
        state[i] ^= (state[m1] | state[m3]);
        state[m3] ^= (state[m1] & state[m2]);
        state[m1] ^= (temp & state[i]);
        state[m2] ^= temp;
        final int m0 = 4 + i;
        final int m11 = 12 + i;
        final int m21 = 20 + i;
        final int m31 = 28 + i;
        final int cc1 = ROUND_CONSTANTS[((r + 2) << 3) + i + 4];
        state[m31] = ~state[m31];
        state[m0] ^= (~state[m21] & cc1);
        temp = cc1 ^ (state[m0] & state[m11]);
        state[m0] ^= (state[m21] & state[m31]);
        state[m31] ^= (~state[m11] & state[m21]);
        state[m11] ^= (state[m0] & state[m21]);
        state[m21] ^= (state[m0] & ~state[m31]);
        state[m0] ^= (state[m11] | state[m31]);
        state[m31] ^= (state[m11] & state[m21]);
        state[m11] ^= (temp & state[m0]);
        state[m21] ^= temp;
        L(state, i, 8 + i, 16 + i, 24 + i, 4 + i, 12 + i, 20 + i, 28 + i);

        state[4 + i] = SWAP4(state[4 + i]);
        state[12 + i] = SWAP4(state[12 + i]);
        state[20 + i] = SWAP4(state[20 + i]);
        state[28 + i] = SWAP4(state[28 + i]);
      }

      // round 7*roundnumber+3: Sbox, MDS and swapping layer
      for (int i = 0; i < 4; i++) {
        final int m1 = 8 + i;
        final int m2 = 16 + i;
        final int m3 = 24 + i;
        final int cc = ROUND_CONSTANTS[((r + 3) << 3) + i];
        state[m3] = ~state[m3];
        state[i] ^= (~state[m2] & cc);
        temp = cc ^ (state[i] & state[m1]);
        state[i] ^= (state[m2] & state[m3]);
        state[m3] ^= (~state[m1] & state[m2]);
        state[m1] ^= (state[i] & state[m2]);
        state[m2] ^= (state[i] & ~state[m3]);
        state[i] ^= (state[m1] | state[m3]);
        state[m3] ^= (state[m1] & state[m2]);
        state[m1] ^= (temp & state[i]);
        state[m2] ^= temp;
        final int m0 = 4 + i;
        final int m11 = 12 + i;
        final int m21 = 20 + i;
        final int m31 = 28 + i;
        final int cc1 = ROUND_CONSTANTS[((r + 3) << 3) + i + 4];
        state[m31] = ~state[m31];
        state[m0] ^= (~state[m21] & cc1);
        temp = cc1 ^ (state[m0] & state[m11]);
        state[m0] ^= (state[m21] & state[m31]);
        state[m31] ^= (~state[m11] & state[m21]);
        state[m11] ^= (state[m0] & state[m21]);
        state[m21] ^= (state[m0] & ~state[m31]);
        state[m0] ^= (state[m11] | state[m31]);
        state[m31] ^= (state[m11] & state[m21]);
        state[m11] ^= (temp & state[m0]);
        state[m21] ^= temp;
        L(state, i, 8 + i, 16 + i, 24 + i, 4 + i, 12 + i, 20 + i, 28 + i);

        state[4 + i] = SWAP8(state[4 + i]);
        state[12 + i] = SWAP8(state[12 + i]);
        state[20 + i] = SWAP8(state[20 + i]);
        state[28 + i] = SWAP8(state[28 + i]);
      }

      // round 7*roundnumber+4: Sbox, MDS and swapping layer
      for (int i = 0; i < 4; i++) {
        final int m1 = 8 + i;
        final int m2 = 16 + i;
        final int m3 = 24 + i;
        final int cc = ROUND_CONSTANTS[((r + 4) << 3) + i];
        state[m3] = ~state[m3];
        state[i] ^= (~state[m2] & cc);
        temp = cc ^ (state[i] & state[m1]);
        state[i] ^= (state[m2] & state[m3]);
        state[m3] ^= (~state[m1] & state[m2]);
        state[m1] ^= (state[i] & state[m2]);
        state[m2] ^= (state[i] & ~state[m3]);
        state[i] ^= (state[m1] | state[m3]);
        state[m3] ^= (state[m1] & state[m2]);
        state[m1] ^= (temp & state[i]);
        state[m2] ^= temp;
        final int m0 = 4 + i;
        final int m11 = 12 + i;
        final int m21 = 20 + i;
        final int m31 = 28 + i;
        final int cc1 = ROUND_CONSTANTS[((r + 4) << 3) + i + 4];
        state[m31] = ~state[m31];
        state[m0] ^= (~state[m21] & cc1);
        temp = cc1 ^ (state[m0] & state[m11]);
        state[m0] ^= (state[m21] & state[m31]);
        state[m31] ^= (~state[m11] & state[m21]);
        state[m11] ^= (state[m0] & state[m21]);
        state[m21] ^= (state[m0] & ~state[m31]);
        state[m0] ^= (state[m11] | state[m31]);
        state[m31] ^= (state[m11] & state[m21]);
        state[m11] ^= (temp & state[m0]);
        state[m21] ^= temp;
        L(state, i, 8 + i, 16 + i, 24 + i, 4 + i, 12 + i, 20 + i, 28 + i);

        state[4 + i] = SWAP16(state[4 + i]);
        state[12 + i] = SWAP16(state[12 + i]);
        state[20 + i] = SWAP16(state[20 + i]);
        state[28 + i] = SWAP16(state[28 + i]);
      }

      // round 7*roundnumber+5: Sbox and MDS layer
      for (int i = 0; i < 4; i++) {
        final int m1 = 8 + i;
        final int m2 = 16 + i;
        final int m3 = 24 + i;
        final int cc = ROUND_CONSTANTS[((r + 5) << 3) + i];
        state[m3] = ~state[m3];
        state[i] ^= (~state[m2] & cc);
        temp = cc ^ (state[i] & state[m1]);
        state[i] ^= (state[m2] & state[m3]);
        state[m3] ^= (~state[m1] & state[m2]);
        state[m1] ^= (state[i] & state[m2]);
        state[m2] ^= (state[i] & ~state[m3]);
        state[i] ^= (state[m1] | state[m3]);
        state[m3] ^= (state[m1] & state[m2]);
        state[m1] ^= (temp & state[i]);
        state[m2] ^= temp;
        final int m0 = 4 + i;
        final int m11 = 12 + i;
        final int m21 = 20 + i;
        final int m31 = 28 + i;
        final int cc1 = ROUND_CONSTANTS[((r + 5) << 3) + i + 4];
        state[m31] = ~state[m31];
        state[m0] ^= (~state[m21] & cc1);
        temp = cc1 ^ (state[m0] & state[m11]);
        state[m0] ^= (state[m21] & state[m31]);
        state[m31] ^= (~state[m11] & state[m21]);
        state[m11] ^= (state[m0] & state[m21]);
        state[m21] ^= (state[m0] & ~state[m31]);
        state[m0] ^= (state[m11] | state[m31]);
        state[m31] ^= (state[m11] & state[m21]);
        state[m11] ^= (temp & state[m0]);
        state[m21] ^= temp;
        L(state, i, 8 + i, 16 + i, 24 + i, 4 + i, 12 + i, 20 + i, 28 + i);
      }

      // round 7*roundnumber+5: swapping layer
      for (int j = 4; j < 32; j += 8) {
        swapTemp = state[j];
        state[j] = state[j + 1];
        state[j + 1] = swapTemp;

        swapTemp = state[j + 2];
        state[j + 2] = state[j + 3];
        state[j + 3] = swapTemp;
      }

      // round 7*roundnumber+6: Sbox and MDS layer
      for (int i = 0; i < 4; i++) {
        final int m1 = 8 + i;
        final int m2 = 16 + i;
        final int m3 = 24 + i;
        final int cc = ROUND_CONSTANTS[((r + 6) << 3) + i];
        state[m3] = ~state[m3];
        state[i] ^= (~state[m2] & cc);
        temp = cc ^ (state[i] & state[m1]);
        state[i] ^= (state[m2] & state[m3]);
        state[m3] ^= (~state[m1] & state[m2]);
        state[m1] ^= (state[i] & state[m2]);
        state[m2] ^= (state[i] & ~state[m3]);
        state[i] ^= (state[m1] | state[m3]);
        state[m3] ^= (state[m1] & state[m2]);
        state[m1] ^= (temp & state[i]);
        state[m2] ^= temp;
        final int m0 = 4 + i;
        final int m11 = 12 + i;
        final int m21 = 20 + i;
        final int m31 = 28 + i;
        final int cc1 = ROUND_CONSTANTS[((r + 6) << 3) + i + 4];
        state[m31] = ~state[m31];
        state[m0] ^= (~state[m21] & cc1);
        temp = cc1 ^ (state[m0] & state[m11]);
        state[m0] ^= (state[m21] & state[m31]);
        state[m31] ^= (~state[m11] & state[m21]);
        state[m11] ^= (state[m0] & state[m21]);
        state[m21] ^= (state[m0] & ~state[m31]);
        state[m0] ^= (state[m11] | state[m31]);
        state[m31] ^= (state[m11] & state[m21]);
        state[m11] ^= (temp & state[m0]);
        state[m21] ^= temp;
        L(state, i, 8 + i, 16 + i, 24 + i, 4 + i, 12 + i, 20 + i, 28 + i);
      }

      // round 7*roundnumber+6: swapping layer
      for (int j = 4; j < 32; j += 8) {
        swapTemp = state[j];
        state[j] = state[j + 2];
        state[j + 2] = swapTemp;

        swapTemp = state[j + 1];
        state[j + 1] = state[j + 3];
        state[j + 3] = swapTemp;
      }
    }
  }

  @Override
  void engineCompress(byte[] input, int offset) {
    Util.squashBytesToIntsLE(input, offset, inTemp_, 0, inTemp_.length);

    // xor the 512-bit message with the first half of the 1024-bit hash state_
    for (int i = 0; i < 16; i += 4) {
      state_[i] ^= inTemp_[i];
      state_[i + 1] ^= inTemp_[i + 1];
      state_[i + 2] ^= inTemp_[i + 2];
      state_[i + 3] ^= inTemp_[i + 3];
    }

    // perform 42 rounds
    E8(state_);

    // xor the 512-bit message with the second half of the 1024-bit hash state_
    for (int i = 0; i < 16; i += 4) {
      state_[i + 16] ^= inTemp_[i];
      state_[i + 17] ^= inTemp_[i + 1];
      state_[i + 18] ^= inTemp_[i + 2];
      state_[i + 19] ^= inTemp_[i + 3];
    }
  }

  @Override
  protected void engineReset() {
    super.engineReset();
    System.arraycopy(iv_, 0, state_, 0, iv_.length);

    Util.zeroBlock(digestTemp_);
    Util.zeroBlock(inTemp_);
  }

  @Override
  void engineGetDigest(byte[] output, int offset) {
    Util.spreadIntsToBytesLE(state_, state_.length - (digestTemp_.length >>> 2), digestTemp_, 0,
        digestTemp_.length >>> 2);

    System
        .arraycopy(digestTemp_, digestTemp_.length - digestLength_, output, offset, digestLength_);
  }

}
