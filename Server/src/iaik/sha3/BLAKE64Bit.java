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
 * Super class for the 64-bit BLAKE message digest implementations.
 * 
 * @author Christian Hanser
 */
abstract class BLAKE64Bit extends BLAKE {

  // some constants
  private static final int BLOCK_SIZE = 128;
  private static final int BLOCK_BITSIZE = BLOCK_SIZE << 3;
  private static final int NB_ROUNDS64 = 16;
  private static final byte START_OF_PADDING_BYTE = (byte) 0x80;
  private static final long INCREASE_HIGH_COUNT_MASK = ~0x3FFL;

  // constants for BLAKE-64 and BLAKE-48
  private static final long[] CONSTANTS = { 0x243F6A8885A308D3L, 0x13198A2E03707344L,
      0xA4093822299F31D0L, 0x082EFA98EC4E6C89L, 0x452821E638D01377L, 0xBE5466CF34E90C6CL,
      0xC0AC29B7C97C50DDL, 0x3F84D5B5B5470917L, 0x9216D5D98979FB1BL, 0xD1310BA698DFB5ACL,
      0x2FFD72DBD01ADFB7L, 0xB8E1AFED6A267E96L, 0xBA7C9045F12C7F99L, 0x24A19947B3916CF7L,
      0x0801F2E2858EFC16L, 0x636920D871574E69L };

  // the chainings vars
  private final long[] h_ = new long[8];
  private final byte[] paddingTail_ = new byte[16 + 1];
  // private final long[] salt_;

  // the two counter values
  private long lengthLow_;
  private long lengthHigh_;

  private boolean incorporateLength_ = true;

  // the initialization vectors
  private final long[] iv_;
  private final long[] vTemp_ = new long[16];
  private final long[] mTemp_ = new long[16];

  /**
   * Constructs a new instance.
   * 
   * @param digestLength_
   *          the digest length in bytes
   * @param iv
   *          the initialization vectors
   * @param startOfLengthEncodingByte
   *          the value that marks the start of the length encoding
   */
  public BLAKE64Bit(int digestLength, long[] iv, byte lengthEncodingMarker) {
    super(digestLength, BLOCK_SIZE, lengthEncodingMarker, digestLength >> 3);
    iv_ = iv;
    // salt_ = null;
    // TODO: salt

    engineReset();
  }

  @Override
  void engineCompress(byte[] input, int offset) {
    Util.squashBytesToLongs(input, offset, mTemp_, 0, mTemp_.length);

    // initialization
    vTemp_[0] = h_[0];
    vTemp_[1] = h_[1];
    vTemp_[2] = h_[2];
    vTemp_[3] = h_[3];
    vTemp_[4] = h_[4];
    vTemp_[5] = h_[5];
    vTemp_[6] = h_[6];
    vTemp_[7] = h_[7];
    vTemp_[8] = 0x243F6A8885A308D3L;
    vTemp_[9] = 0x13198A2E03707344L;
    vTemp_[10] = 0xA4093822299F31D0L;
    vTemp_[11] = 0x082EFA98EC4E6C89L;
    vTemp_[12] = 0x452821E638D01377L;
    vTemp_[13] = 0xBE5466CF34E90C6CL;
    vTemp_[14] = 0xC0AC29B7C97C50DDL;
    vTemp_[15] = 0x3F84D5B5B5470917L;

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

    for (int j = 0; j < (NB_ROUNDS64 << 4); j += 16) {
      vTemp_[0] += vTemp_[4] + (mTemp_[SIGMA[j]] ^ CONSTANTS[SIGMA[j + 1]]);
      vTemp_[12] = ((vTemp_[12] ^ vTemp_[0]) << 32) | ((vTemp_[12] ^ vTemp_[0]) >>> 32);
      vTemp_[8] += vTemp_[12];
      vTemp_[4] = ((vTemp_[4] ^ vTemp_[8]) << 39) | ((vTemp_[4] ^ vTemp_[8]) >>> 25);
      vTemp_[0] += vTemp_[4] + (mTemp_[SIGMA[j + 1]] ^ CONSTANTS[SIGMA[j]]);
      vTemp_[12] = ((vTemp_[12] ^ vTemp_[0]) << 48) | ((vTemp_[12] ^ vTemp_[0]) >>> 16);
      vTemp_[8] += vTemp_[12];
      vTemp_[4] = ((vTemp_[4] ^ vTemp_[8]) << 53) | ((vTemp_[4] ^ vTemp_[8]) >>> 11);
      vTemp_[1] += vTemp_[5] + (mTemp_[SIGMA[j + 2]] ^ CONSTANTS[SIGMA[j + 3]]);
      vTemp_[13] = ((vTemp_[13] ^ vTemp_[1]) << 32) | ((vTemp_[13] ^ vTemp_[1]) >>> 32);
      vTemp_[9] += vTemp_[13];
      vTemp_[5] = ((vTemp_[5] ^ vTemp_[9]) << 39) | ((vTemp_[5] ^ vTemp_[9]) >>> 25);
      vTemp_[1] += vTemp_[5] + (mTemp_[SIGMA[j + 3]] ^ CONSTANTS[SIGMA[j + 2]]);
      vTemp_[13] = ((vTemp_[13] ^ vTemp_[1]) << 48) | ((vTemp_[13] ^ vTemp_[1]) >>> 16);
      vTemp_[9] += vTemp_[13];
      vTemp_[5] = ((vTemp_[5] ^ vTemp_[9]) << 53) | ((vTemp_[5] ^ vTemp_[9]) >>> 11);
      vTemp_[2] += vTemp_[6] + (mTemp_[SIGMA[j + 4]] ^ CONSTANTS[SIGMA[j + 5]]);
      vTemp_[14] = ((vTemp_[14] ^ vTemp_[2]) << 32) | ((vTemp_[14] ^ vTemp_[2]) >>> 32);
      vTemp_[10] += vTemp_[14];
      vTemp_[6] = ((vTemp_[6] ^ vTemp_[10]) << 39) | ((vTemp_[6] ^ vTemp_[10]) >>> 25);
      vTemp_[2] += vTemp_[6] + (mTemp_[SIGMA[j + 5]] ^ CONSTANTS[SIGMA[j + 4]]);
      vTemp_[14] = ((vTemp_[14] ^ vTemp_[2]) << 48) | ((vTemp_[14] ^ vTemp_[2]) >>> 16);
      vTemp_[10] += vTemp_[14];
      vTemp_[6] = ((vTemp_[6] ^ vTemp_[10]) << 53) | ((vTemp_[6] ^ vTemp_[10]) >>> 11);
      vTemp_[3] += vTemp_[7] + (mTemp_[SIGMA[j + 6]] ^ CONSTANTS[SIGMA[j + 7]]);
      vTemp_[15] = ((vTemp_[15] ^ vTemp_[3]) << 32) | ((vTemp_[15] ^ vTemp_[3]) >>> 32);
      vTemp_[11] += vTemp_[15];
      vTemp_[7] = ((vTemp_[7] ^ vTemp_[11]) << 39) | ((vTemp_[7] ^ vTemp_[11]) >>> 25);
      vTemp_[3] += vTemp_[7] + (mTemp_[SIGMA[j + 7]] ^ CONSTANTS[SIGMA[j + 6]]);
      vTemp_[15] = ((vTemp_[15] ^ vTemp_[3]) << 48) | ((vTemp_[15] ^ vTemp_[3]) >>> 16);
      vTemp_[11] += vTemp_[15];
      vTemp_[7] = ((vTemp_[7] ^ vTemp_[11]) << 53) | ((vTemp_[7] ^ vTemp_[11]) >>> 11);

      vTemp_[3] += vTemp_[4] + (mTemp_[SIGMA[j + 14]] ^ CONSTANTS[SIGMA[j + 15]]);
      vTemp_[14] = ((vTemp_[14] ^ vTemp_[3]) << 32) | ((vTemp_[14] ^ vTemp_[3]) >>> 32);
      vTemp_[9] += vTemp_[14];
      vTemp_[4] = ((vTemp_[4] ^ vTemp_[9]) << 39) | ((vTemp_[4] ^ vTemp_[9]) >>> 25);
      vTemp_[3] += vTemp_[4] + (mTemp_[SIGMA[j + 15]] ^ CONSTANTS[SIGMA[j + 14]]);
      vTemp_[14] = ((vTemp_[14] ^ vTemp_[3]) << 48) | ((vTemp_[14] ^ vTemp_[3]) >>> 16);
      vTemp_[9] += vTemp_[14];
      vTemp_[4] = ((vTemp_[4] ^ vTemp_[9]) << 53) | ((vTemp_[4] ^ vTemp_[9]) >>> 11);
      vTemp_[2] += vTemp_[7] + (mTemp_[SIGMA[j + 12]] ^ CONSTANTS[SIGMA[j + 13]]);
      vTemp_[13] = ((vTemp_[13] ^ vTemp_[2]) << 32) | ((vTemp_[13] ^ vTemp_[2]) >>> 32);
      vTemp_[8] += vTemp_[13];
      vTemp_[7] = ((vTemp_[7] ^ vTemp_[8]) << 39) | ((vTemp_[7] ^ vTemp_[8]) >>> 25);
      vTemp_[2] += vTemp_[7] + (mTemp_[SIGMA[j + 13]] ^ CONSTANTS[SIGMA[j + 12]]);
      vTemp_[13] = ((vTemp_[13] ^ vTemp_[2]) << 48) | ((vTemp_[13] ^ vTemp_[2]) >>> 16);
      vTemp_[8] += vTemp_[13];
      vTemp_[7] = ((vTemp_[7] ^ vTemp_[8]) << 53) | ((vTemp_[7] ^ vTemp_[8]) >>> 11);
      vTemp_[0] += vTemp_[5] + (mTemp_[SIGMA[j + 8]] ^ CONSTANTS[SIGMA[j + 9]]);
      vTemp_[15] = ((vTemp_[15] ^ vTemp_[0]) << 32) | ((vTemp_[15] ^ vTemp_[0]) >>> 32);
      vTemp_[10] += vTemp_[15];
      vTemp_[5] = ((vTemp_[5] ^ vTemp_[10]) << 39) | ((vTemp_[5] ^ vTemp_[10]) >>> 25);
      vTemp_[0] += vTemp_[5] + (mTemp_[SIGMA[j + 9]] ^ CONSTANTS[SIGMA[j + 8]]);
      vTemp_[15] = ((vTemp_[15] ^ vTemp_[0]) << 48) | ((vTemp_[15] ^ vTemp_[0]) >>> 16);
      vTemp_[10] += vTemp_[15];
      vTemp_[5] = ((vTemp_[5] ^ vTemp_[10]) << 53) | ((vTemp_[5] ^ vTemp_[10]) >>> 11);
      vTemp_[1] += vTemp_[6] + (mTemp_[SIGMA[j + 10]] ^ CONSTANTS[SIGMA[j + 11]]);
      vTemp_[12] = ((vTemp_[12] ^ vTemp_[1]) << 32) | ((vTemp_[12] ^ vTemp_[1]) >>> 32);
      vTemp_[11] += vTemp_[12];
      vTemp_[6] = ((vTemp_[6] ^ vTemp_[11]) << 39) | ((vTemp_[6] ^ vTemp_[11]) >>> 25);
      vTemp_[1] += vTemp_[6] + (mTemp_[SIGMA[j + 11]] ^ CONSTANTS[SIGMA[j + 10]]);
      vTemp_[12] = ((vTemp_[12] ^ vTemp_[1]) << 48) | ((vTemp_[12] ^ vTemp_[1]) >>> 16);
      vTemp_[11] += vTemp_[12];
      vTemp_[6] = ((vTemp_[6] ^ vTemp_[11]) << 53) | ((vTemp_[6] ^ vTemp_[11]) >>> 11);
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
    // emulate modulo
    final long temp = ((count_ % BLOCK_SIZE) + BLOCK_SIZE) % BLOCK_SIZE;

    // add remaining bits to length
    lengthLow_ += (temp << 3);

    final long lengthLow = lengthLow_;
    final long lengthHigh = lengthHigh_;
    final int paddingHeadLength = (int) ((BLOCK_SIZE << 1) - temp - paddingTail_.length)
        % BLOCK_SIZE;

    // special case, where 0x80 and startOfLengthEncodingByte_ collapse
    if (paddingHeadLength == 0) {
      paddingTail = paddingTail_.clone();
      paddingTail[0] = (byte) (START_OF_PADDING_BYTE | lengthEncodingMarker_);
    } else if (paddingHeadLength >= 111) {
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
    Util.spreadLongsToBytes(new long[] { lengthHigh, lengthLow }, 0, paddingTail, 1, 2);

    // compensate increment in engineUpdate
    lengthLow_ = lengthLow - BLOCK_BITSIZE;
    engineUpdate(paddingTail, 0, paddingTail.length);
  }

  @Override
  void engineGetDigest(byte[] output, int offset) {
    Util.spreadLongsToBytes(h_, 0, output, offset, internalDigestLength_);
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
