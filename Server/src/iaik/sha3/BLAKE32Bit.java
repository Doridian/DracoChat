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
 * Super class for the 32-bit BLAKE message digest implementations.
 * 
 * @author Christian Hanser
 */
abstract class BLAKE32Bit extends BLAKE {

  private static final int BLOCK_SIZE = 64;
  private static final int BLOCK_BITSIZE = BLOCK_SIZE << 3;
  private static final byte PADDING_MARKER = (byte) 0x80;
  private static final int INCREASE_HIGH_COUNT_MASK = ~0x1FF;
  private final static int NB_ROUNDS32 = 14;

  // constants for BLAKE-32 and BLAKE-28
  private static final int[] CONSTANTS = { 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
      0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89, 0x452821E6, 0x38D01377, 0xBE5466CF,
      0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917 };

  private final int[] h_ = new int[8];
  private final byte[] paddingTail_ = new byte[8 + 1];
  // private final int[] salt_;
  private int lengthLow_;
  private int lengthHigh_;

  private boolean incorporateLength_ = true;

  private final int[] iv_;
  private final int[] vTemp_ = new int[16];
  private final int[] mTemp_ = new int[16];

  /**
   * Constructs a new instance.
   * 
   * @param digestLength_
   *          the digest length in bytes
   * @param iv
   *          the initialization vectors
   * @param lengthEncodingMarker
   *          the value that marks the start of the length encoding
   */
  public BLAKE32Bit(int digestLength, int[] iv, byte lengthEncodingMarker) {
    super(digestLength, BLOCK_SIZE, lengthEncodingMarker, digestLength >>> 2);
    iv_ = iv;
    // salt_ = null;

    engineReset();
  }

  @Override
  void engineCompress(byte[] input, int offset) {
    Util.squashBytesToInts(input, offset, mTemp_, 0, mTemp_.length);

    // initialization
    vTemp_[0] = h_[0];
    vTemp_[1] = h_[1];
    vTemp_[2] = h_[2];
    vTemp_[3] = h_[3];
    vTemp_[4] = h_[4];
    vTemp_[5] = h_[5];
    vTemp_[6] = h_[6];
    vTemp_[7] = h_[7];
    vTemp_[8] = 0x243F6A88;
    vTemp_[9] = 0x85A308D3;
    vTemp_[10] = 0x13198A2E;
    vTemp_[11] = 0x03707344;
    vTemp_[12] = 0xA4093822;
    vTemp_[13] = 0x299F31D0;
    vTemp_[14] = 0x082EFA98;
    vTemp_[15] = 0xEC4E6C89;

    if (incorporateLength_) {
      if (lengthLow_ == INCREASE_HIGH_COUNT_MASK) {
        lengthHigh_++;
      }
      lengthLow_ += BLOCK_BITSIZE;

      vTemp_[12] ^= lengthLow_;
      vTemp_[13] ^= lengthLow_;
      vTemp_[14] ^= lengthHigh_;
      vTemp_[15] ^= lengthHigh_;
    }

    // if (salt_ != null) {
    // vTemp_[8] ^= salt_[0];
    // vTemp_[9] ^= salt_[1];
    // vTemp_[10] ^= salt_[2];
    // vTemp_[11] ^= salt_[3];
    // }

    for (int j = 0; j < (NB_ROUNDS32 << 4); j += 16) {
      vTemp_[0] += vTemp_[4] + (mTemp_[SIGMA[j]] ^ CONSTANTS[SIGMA[j + 1]]);
      vTemp_[12] = ((vTemp_[12] ^ vTemp_[0]) << 16) | ((vTemp_[12] ^ vTemp_[0]) >>> 16);
      vTemp_[8] += vTemp_[12];
      vTemp_[4] = ((vTemp_[4] ^ vTemp_[8]) << 20) | ((vTemp_[4] ^ vTemp_[8]) >>> 12);
      vTemp_[0] += vTemp_[4] + (mTemp_[SIGMA[j + 1]] ^ CONSTANTS[SIGMA[j]]);
      vTemp_[12] = ((vTemp_[12] ^ vTemp_[0]) << 24) | ((vTemp_[12] ^ vTemp_[0]) >>> 8);
      vTemp_[8] += vTemp_[12];
      vTemp_[4] = ((vTemp_[4] ^ vTemp_[8]) << 25) | ((vTemp_[4] ^ vTemp_[8]) >>> 7);
      vTemp_[1] += vTemp_[5] + (mTemp_[SIGMA[j + 2]] ^ CONSTANTS[SIGMA[j + 3]]);
      vTemp_[13] = ((vTemp_[13] ^ vTemp_[1]) << 16) | ((vTemp_[13] ^ vTemp_[1]) >>> 16);
      vTemp_[9] += vTemp_[13];
      vTemp_[5] = ((vTemp_[5] ^ vTemp_[9]) << 20) | ((vTemp_[5] ^ vTemp_[9]) >>> 12);
      vTemp_[1] += vTemp_[5] + (mTemp_[SIGMA[j + 3]] ^ CONSTANTS[SIGMA[j + 2]]);
      vTemp_[13] = ((vTemp_[13] ^ vTemp_[1]) << 24) | ((vTemp_[13] ^ vTemp_[1]) >>> 8);
      vTemp_[9] += vTemp_[13];
      vTemp_[5] = ((vTemp_[5] ^ vTemp_[9]) << 25) | ((vTemp_[5] ^ vTemp_[9]) >>> 7);
      vTemp_[2] += vTemp_[6] + (mTemp_[SIGMA[j + 4]] ^ CONSTANTS[SIGMA[j + 5]]);
      vTemp_[14] = ((vTemp_[14] ^ vTemp_[2]) << 16) | ((vTemp_[14] ^ vTemp_[2]) >>> 16);
      vTemp_[10] += vTemp_[14];
      vTemp_[6] = ((vTemp_[6] ^ vTemp_[10]) << 20) | ((vTemp_[6] ^ vTemp_[10]) >>> 12);
      vTemp_[2] += vTemp_[6] + (mTemp_[SIGMA[j + 5]] ^ CONSTANTS[SIGMA[j + 4]]);
      vTemp_[14] = ((vTemp_[14] ^ vTemp_[2]) << 24) | ((vTemp_[14] ^ vTemp_[2]) >>> 8);
      vTemp_[10] += vTemp_[14];
      vTemp_[6] = ((vTemp_[6] ^ vTemp_[10]) << 25) | ((vTemp_[6] ^ vTemp_[10]) >>> 7);
      vTemp_[3] += vTemp_[7] + (mTemp_[SIGMA[j + 6]] ^ CONSTANTS[SIGMA[j + 7]]);
      vTemp_[15] = ((vTemp_[15] ^ vTemp_[3]) << 16) | ((vTemp_[15] ^ vTemp_[3]) >>> 16);
      vTemp_[11] += vTemp_[15];
      vTemp_[7] = ((vTemp_[7] ^ vTemp_[11]) << 20) | ((vTemp_[7] ^ vTemp_[11]) >>> 12);
      vTemp_[3] += vTemp_[7] + (mTemp_[SIGMA[j + 7]] ^ CONSTANTS[SIGMA[j + 6]]);
      vTemp_[15] = ((vTemp_[15] ^ vTemp_[3]) << 24) | ((vTemp_[15] ^ vTemp_[3]) >>> 8);
      vTemp_[11] += vTemp_[15];
      vTemp_[7] = ((vTemp_[7] ^ vTemp_[11]) << 25) | ((vTemp_[7] ^ vTemp_[11]) >>> 7);

      vTemp_[3] += vTemp_[4] + (mTemp_[SIGMA[j + 14]] ^ CONSTANTS[SIGMA[j + 15]]);
      vTemp_[14] = ((vTemp_[14] ^ vTemp_[3]) << 16) | ((vTemp_[14] ^ vTemp_[3]) >>> 16);
      vTemp_[9] += vTemp_[14];
      vTemp_[4] = ((vTemp_[4] ^ vTemp_[9]) << 20) | ((vTemp_[4] ^ vTemp_[9]) >>> 12);
      vTemp_[3] += vTemp_[4] + (mTemp_[SIGMA[j + 15]] ^ CONSTANTS[SIGMA[j + 14]]);
      vTemp_[14] = ((vTemp_[14] ^ vTemp_[3]) << 24) | ((vTemp_[14] ^ vTemp_[3]) >>> 8);
      vTemp_[9] += vTemp_[14];
      vTemp_[4] = ((vTemp_[4] ^ vTemp_[9]) << 25) | ((vTemp_[4] ^ vTemp_[9]) >>> 7);
      vTemp_[2] += vTemp_[7] + (mTemp_[SIGMA[j + 12]] ^ CONSTANTS[SIGMA[j + 13]]);
      vTemp_[13] = ((vTemp_[13] ^ vTemp_[2]) << 16) | ((vTemp_[13] ^ vTemp_[2]) >>> 16);
      vTemp_[8] += vTemp_[13];
      vTemp_[7] = ((vTemp_[7] ^ vTemp_[8]) << 20) | ((vTemp_[7] ^ vTemp_[8]) >>> 12);
      vTemp_[2] += vTemp_[7] + (mTemp_[SIGMA[j + 13]] ^ CONSTANTS[SIGMA[j + 12]]);
      vTemp_[13] = ((vTemp_[13] ^ vTemp_[2]) << 24) | ((vTemp_[13] ^ vTemp_[2]) >>> 8);
      vTemp_[8] += vTemp_[13];
      vTemp_[7] = ((vTemp_[7] ^ vTemp_[8]) << 25) | ((vTemp_[7] ^ vTemp_[8]) >>> 7);
      vTemp_[0] += vTemp_[5] + (mTemp_[SIGMA[j + 8]] ^ CONSTANTS[SIGMA[j + 9]]);
      vTemp_[15] = ((vTemp_[15] ^ vTemp_[0]) << 16) | ((vTemp_[15] ^ vTemp_[0]) >>> 16);
      vTemp_[10] += vTemp_[15];
      vTemp_[5] = ((vTemp_[5] ^ vTemp_[10]) << 20) | ((vTemp_[5] ^ vTemp_[10]) >>> 12);
      vTemp_[0] += vTemp_[5] + (mTemp_[SIGMA[j + 9]] ^ CONSTANTS[SIGMA[j + 8]]);
      vTemp_[15] = ((vTemp_[15] ^ vTemp_[0]) << 24) | ((vTemp_[15] ^ vTemp_[0]) >>> 8);
      vTemp_[10] += vTemp_[15];
      vTemp_[5] = ((vTemp_[5] ^ vTemp_[10]) << 25) | ((vTemp_[5] ^ vTemp_[10]) >>> 7);
      vTemp_[1] += vTemp_[6] + (mTemp_[SIGMA[j + 10]] ^ CONSTANTS[SIGMA[j + 11]]);
      vTemp_[12] = ((vTemp_[12] ^ vTemp_[1]) << 16) | ((vTemp_[12] ^ vTemp_[1]) >>> 16);
      vTemp_[11] += vTemp_[12];
      vTemp_[6] = ((vTemp_[6] ^ vTemp_[11]) << 20) | ((vTemp_[6] ^ vTemp_[11]) >>> 12);
      vTemp_[1] += vTemp_[6] + (mTemp_[SIGMA[j + 11]] ^ CONSTANTS[SIGMA[j + 10]]);
      vTemp_[12] = ((vTemp_[12] ^ vTemp_[1]) << 24) | ((vTemp_[12] ^ vTemp_[1]) >>> 8);
      vTemp_[11] += vTemp_[12];
      vTemp_[6] = ((vTemp_[6] ^ vTemp_[11]) << 25) | ((vTemp_[6] ^ vTemp_[11]) >>> 7);
    }

    h_[0] ^= vTemp_[0] ^ vTemp_[8];
    h_[1] ^= vTemp_[1] ^ vTemp_[9];
    h_[2] ^= vTemp_[2] ^ vTemp_[10];
    h_[3] ^= vTemp_[3] ^ vTemp_[11];
    h_[4] ^= vTemp_[4] ^ vTemp_[12];
    h_[5] ^= vTemp_[5] ^ vTemp_[13];
    h_[6] ^= vTemp_[6] ^ vTemp_[14];
    h_[7] ^= vTemp_[7] ^ vTemp_[15];

    // if (salt_ != null) {
    // h_[0] ^= salt_[0];
    // h_[1] ^= salt_[1];
    // h_[2] ^= salt_[2];
    // h_[3] ^= salt_[3];
    // h_[4] ^= salt_[0];
    // h_[5] ^= salt_[1];
    // h_[6] ^= salt_[2];
    // h_[7] ^= salt_[3];
    // }
  }

  @Override
  void doPadding() {
    byte[] paddingTail;
    final int temp = (int) ((count_ % BLOCK_SIZE) + BLOCK_SIZE) % BLOCK_SIZE;

    // add remaining bits to length
    lengthLow_ += (temp << 3);

    final int lengthLow = lengthLow_;
    final int lengthHigh = lengthHigh_;
    final int paddingHeadLength = ((BLOCK_SIZE << 1) - temp - paddingTail_.length) % BLOCK_SIZE;

    // special case, where 0x80 and lengthEncodingMarker_ collapse
    if (paddingHeadLength == 0) {
      paddingTail = paddingTail_.clone();
      paddingTail[0] = (byte) (PADDING_MARKER | lengthEncodingMarker_);
    } else if (paddingHeadLength >= 55) {
      paddingTail = paddingTail_;
      // compensate increment in engineUpdate
      lengthLow_ -= BLOCK_BITSIZE;

      engineUpdate(padding_, 0, paddingHeadLength);
      // count_ will not be incorporated into second padding_ block
      incorporateLength_ = false;
    } else {
      paddingTail = paddingTail_;
      // compensate increment in engineUpdate
      lengthLow_ -= BLOCK_BITSIZE;

      engineUpdate(padding_, 0, paddingHeadLength);
    }

    // put the length data into the padding_
    Util.spreadIntsToBytes(new int[] { lengthHigh, lengthLow }, 0, paddingTail, 1, 2);

    // compensate increment in engineUpdate
    lengthLow_ = lengthLow - BLOCK_BITSIZE;
    engineUpdate(paddingTail, 0, paddingTail.length);
  }

  @Override
  void engineGetDigest(byte[] output, int offset) {
    Util.spreadIntsToBytes(h_, 0, output, offset, internalDigestLength_);
  }

  @Override
  protected void engineReset() {
    super.engineReset();

    System.arraycopy(iv_, 0, h_, 0, iv_.length);

    incorporateLength_ = true;
    lengthHigh_ = 0;
    lengthLow_ = 0;
    Util.zeroBlock(paddingTail_);
    Util.zeroBlock(vTemp_);
    Util.zeroBlock(mTemp_);
    paddingTail_[0] = lengthEncodingMarker_;
  }

}
