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
 * Skein implementation optimized for 64-bit platforms.
 * 
 * This implementation supports input data lengths up to 2^64 bytes.
 */
final class RawSkein64Bit extends AbstractMessageDigest {
  private static final int ROUNDS = 72;
  protected static final int BLOCK_SIZE = 64;
  private static final int BLOCK_WORD_SIZE = BLOCK_SIZE >>> 3;

  private static final int R00 = 46, R01 = 36, R02 = 19, R03 = 37;
  private static final int R10 = 33, R11 = 27, R12 = 14, R13 = 42;
  private static final int R20 = 17, R21 = 49, R22 = 36, R23 = 39;
  private static final int R30 = 44, R31 = 9, R32 = 54, R33 = 56;
  private static final int R40 = 39, R41 = 30, R42 = 34, R43 = 24;
  private static final int R50 = 13, R51 = 50, R52 = 10, R53 = 17;
  private static final int R60 = 25, R61 = 29, R62 = 39, R63 = 43;
  private static final int R70 = 8, R71 = 35, R72 = 56, R73 = 22;

  private static final long T1_FLAG_FIRST = 1L << 62;
  private static final long T1_FLAG_FINAL = 1L << 63;

  private static final long TYPE_OUT = 63L << 56;
  private static final long TYPE_MESSAGE = 48L << 56;

  private static final long PARITY_CONSTANT = 0x1BD11BDAA9FC1A22L;

  // byte counter
  private long tweak0_;
  // holds the tweak flags
  private long tweak1_;
  // chaining vars
  private final long[] x_ = new long[BLOCK_WORD_SIZE];
  // tweak schedule
  private final long[] ts_ = new long[5];
  // key schedule (chaining vars)
  private final long[] ks_ = new long[17];
  // initialization vectors
  private final long[] iv_;
  private boolean bufferFilled_;
  private int bytes_;

  // helper array
  private final byte[] outTemp_;

  /**
   * Constructs a new instance
   * 
   * @param digestLength_
   *          the desired digest length
   * @param iv
   *          the initialization vectors
   */
  RawSkein64Bit(int digestLength, long[] iv) {
    super("Skein" + (digestLength << 3), digestLength, BLOCK_SIZE);
    iv_ = iv;
    outTemp_ = new byte[((digestLength + 7) >>> 3) << 3];

    engineReset();
  }

  /**
   * Set up for starting with a new type.
   * 
   * @param type
   *          the type value
   */
  private void startNewType(long type) {
    tweak0_ = 0;
    tweak1_ = T1_FLAG_FIRST | type;
  }

  /**
   * Performs a rotational left shift plus an XOR operation.
   * 
   * @param x
   *          the value to be rotated
   * @param n
   *          the number of shift bits
   * @param xor
   *          the xor operand
   * @return the result
   */
  private static long XROTL(long x, int n, long y) {
    return ((x << n) | (x >>> (64 - n))) ^ y;
  }

  @Override
  void engineCompress(byte[] input, int offset) {
    long temp = 0;

    tweak0_ += bytes_;
    ts_[3] = ts_[0] = tweak0_;
    ts_[4] = ts_[1] = tweak1_;
    ts_[2] = tweak0_ ^ tweak1_;

    long temp1;
    // precompute the key schedule
    for (int i = 0; i < 8; i++) {
      ks_[i + 9] = ks_[i] = temp1 = x_[i];
      temp ^= temp1;
    }

    ks_[8] = PARITY_CONSTANT ^ temp;

    // key injection
    Util.squashBytesToLongsLE(input, offset, x_, 0, BLOCK_WORD_SIZE);

    long x0 = x_[0] + ks_[0];
    long x1 = x_[1] + ks_[1];
    long x2 = x_[2] + ks_[2];
    long x3 = x_[3] + ks_[3];
    long x4 = x_[4] + ks_[4];
    long x5 = x_[5] + ks_[5] + tweak0_;
    long x6 = x_[6] + ks_[6] + tweak1_;
    long x7 = x_[7] + ks_[7];

    // round iterations
    for (int r = 1; r <= (ROUNDS >>> 2); r += 2) {
      final int rMod9 = r % 9;
      final int rMod3 = r % 3;

      x0 += x1;
      x1 = XROTL(x1, R00, x0);
      x2 += x3;
      x3 = XROTL(x3, R01, x2);
      x4 += x5;
      x5 = XROTL(x5, R02, x4);
      x6 += x7;
      x7 = XROTL(x7, R03, x6);
      x2 += x1;
      x1 = XROTL(x1, R10, x2);
      x4 += x7;
      x7 = XROTL(x7, R11, x4);
      x6 += x5;
      x5 = XROTL(x5, R12, x6);
      x0 += x3;
      x3 = XROTL(x3, R13, x0);
      x4 += x1;
      x1 = XROTL(x1, R20, x4);
      x6 += x3;
      x3 = XROTL(x3, R21, x6);
      x0 += x5;
      x5 = XROTL(x5, R22, x0);
      x2 += x7;
      x7 = XROTL(x7, R23, x2);
      x6 += x1;
      x1 = XROTL(x1, R30, x6) + ks_[rMod9 + 1];
      x0 += x7;
      x7 = XROTL(x7, R31, x0) + ks_[rMod9 + 7] + r;
      x2 += x5;
      x5 = XROTL(x5, R32, x2) + ks_[rMod9 + 5] + ts_[rMod3];
      x4 += x3;
      x3 = XROTL(x3, R33, x4) + ks_[rMod9 + 3];
      x0 += x1 + ks_[rMod9];
      x1 = XROTL(x1, R40, x0);
      x2 += x3 + ks_[rMod9 + 2];
      x3 = XROTL(x3, R41, x2);
      x4 += x5 + ks_[rMod9 + 4];
      x5 = XROTL(x5, R42, x4);
      x6 += x7 + ks_[rMod9 + 6] + ts_[rMod3 + 1];
      x7 = XROTL(x7, R43, x6);
      x2 += x1;
      x1 = XROTL(x1, R50, x2);
      x4 += x7;
      x7 = XROTL(x7, R51, x4);
      x6 += x5;
      x5 = XROTL(x5, R52, x6);
      x0 += x3;
      x3 = XROTL(x3, R53, x0);
      x4 += x1;
      x1 = XROTL(x1, R60, x4);
      x6 += x3;
      x3 = XROTL(x3, R61, x6);
      x0 += x5;
      x5 = XROTL(x5, R62, x0);
      x2 += x7;
      x7 = XROTL(x7, R63, x2);
      x6 += x1;
      x1 = XROTL(x1, R70, x6) + ks_[rMod9 + 2];
      x0 += x7;
      x7 = XROTL(x7, R71, x0) + ks_[rMod9 + 8] + r + 1;
      x2 += x5;
      x5 = XROTL(x5, R72, x2) + ks_[rMod9 + 6] + ts_[rMod3 + 1];
      x4 += x3;
      x3 = XROTL(x3, R73, x4) + ks_[rMod9 + 4];

      x0 += ks_[rMod9 + 1];
      x2 += ks_[rMod9 + 3];
      x4 += ks_[rMod9 + 5];
      x6 += ks_[rMod9 + 7] + ts_[rMod3 + 2];
    }

    // feed forward
    x_[0] ^= x0;
    x_[1] ^= x1;
    x_[2] ^= x2;
    x_[3] ^= x3;
    x_[4] ^= x4;
    x_[5] ^= x5;
    x_[6] ^= x6;
    x_[7] ^= x7;

    // clear the start bit
    tweak1_ &= ~T1_FLAG_FIRST;
  }

  @Override
  void doPadding() {
    // get the number of overhanging bytes
    bytes_ = (int) ((count_ % BLOCK_SIZE) + BLOCK_SIZE) % BLOCK_SIZE;

    // add padding_ if input length == 0
    if (bytes_ != 0) {
      engineUpdate(padding_, 1, BLOCK_SIZE - bytes_);
    } else if (count_ == 0) {
      // or not a multiple of the block size
      engineUpdate(padding_, 1, BLOCK_SIZE);
    } else if (bufferFilled_) {
      // if the buffer_ is full bytes_ must be equal to BLOCK_SIZE as there
      // is still one call to the compression function left
      bytes_ = BLOCK_SIZE;
    }

    // perform the last call to the compression function
    tweak1_ |= T1_FLAG_FINAL;
    engineCompress(buffer_, 0);

    // build the counter block and ...
    startNewType(TYPE_OUT | T1_FLAG_FINAL);
    // ... run counter mode
    bytes_ = 8;
    engineCompress(padding_, 1);
  }

  @Override
  void engineGetDigest(byte[] output, int offset) {
    Util.spreadLongsToBytesLE(x_, 0, outTemp_, 0, outTemp_.length >>> 3);

    // truncate
    System.arraycopy(outTemp_, 0, output, offset, digestLength_);
  }

  @Override
  protected void engineReset() {
    count_ = 0;
    Util.zeroBlock(buffer_);

    System.arraycopy(iv_, 0, x_, 0, iv_.length);
    Util.zeroBlock(ks_);
    Util.zeroBlock(ts_);
    Util.zeroBlock(outTemp_);

    bytes_ = BLOCK_SIZE;
    bufferFilled_ = false;

    startNewType(TYPE_MESSAGE);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    if (bufferFilled_) {
      engineCompress(buffer_, 0);
    }

    final int index = (int) (count_ & mask_);
    count_ += len;

    if (index != 0) {
      final int n = BLOCK_SIZE - index;
      if (n <= len) {
        System.arraycopy(input, offset, buffer_, index, n);
        len -= n;

        if (len == 0) {
          bufferFilled_ = ((index + n) == BLOCK_SIZE);

          return;
        }

        offset += n;
      } else {
        System.arraycopy(input, offset, buffer_, index, len);
        bufferFilled_ = ((index + len) == BLOCK_SIZE);

        return;
      }
    }

    while (len > BLOCK_SIZE) {
      engineCompress(input, offset);
      offset += BLOCK_SIZE;
      len -= BLOCK_SIZE;
    }

    if (len > 0) {
      System.arraycopy(input, offset, buffer_, 0, len);
      bufferFilled_ = (len == BLOCK_SIZE);
    }
  }

}
