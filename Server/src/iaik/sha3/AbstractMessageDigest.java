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

import java.security.MessageDigest;

/**
 * This is the base class of all message digest implementations in this package.
 * 
 * @author Andreas Sterbenz
 * @author Christian Hanser
 */
abstract class AbstractMessageDigest extends MessageDigest {

  /**
   * The padding_ buffer_. The length is calculated as (max_block_size +
   * max_bit_counter_length), i.e. (128 + 8).
   */
  final static byte[] padding_ = new byte[136];

  static {
    padding_[0] = (byte) 0x80;
  }

  byte buffer_[];
  final int digestLength_;
  final int blockSize_;
  final int mask_;
  long count_;

  private transient final byte[] byteArray_ = new byte[1];

  /**
   * Construct a new abstract message digest.
   * 
   * @param algorithm
   *          The (JCA) name of the algorithm.
   * @param digestLength_
   *          The length of a hash value in bytes.
   * @param blockSize_
   *          The input block size of the compression function in bytes.
   */
  AbstractMessageDigest(String algorithm, int digestLength, int blockSize) {
    super(algorithm);
    digestLength_ = digestLength;
    blockSize_ = blockSize;
    mask_ = blockSize - 1;
    buffer_ = new byte[blockSize];
  }

  /**
   * <b>SPI</b>: Updates the data to be hashed with the specified byte.
   * 
   * @param input
   *          the byte to be used for updating.
   */
  @Override
  protected final void engineUpdate(byte input) {
    byteArray_[0] = input;
    engineUpdate(byteArray_, 0, 1);
  }

  /**
   * <b>SPI</b>: Updates the data to be hashed with the specified number of
   * bytes, beginning at the specified offset within the given byte array.
   * 
   * @param input
   *          the byte array holding the data to be used for this update
   *          operation.
   * @param offset
   *          the offset, indicating the start position within the given byte
   *          array.
   * @param len
   *          the number of bytes to be obtained from the given byte array,
   *          starting at the given position.
   */
  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    final int index = (int) (count_ & mask_);
    count_ += len;

    if (index != 0) {
      final int n = blockSize_ - index;

      if (n <= len) {
        System.arraycopy(input, offset, buffer_, index, n);
        engineCompress(buffer_, 0);
        len -= n;

        if (len == 0) {
          return;
        }

        offset += n;
      } else {
        System.arraycopy(input, offset, buffer_, index, len);
        return;
      }
    }

    while (len >= blockSize_) {
      engineCompress(input, offset);
      offset += blockSize_;
      len -= blockSize_;
    }

    if (len > 0) {
      System.arraycopy(input, offset, buffer_, 0, len);
    }
  }

  /**
   * <b>SPI</b>: Completes the hash computation by performing final operations
   * such as padding_. Once <code>engineDigest</code> has been called, the
   * engine should be reset. Resetting is the responsibility of the engine
   * implementor.
   * 
   * @return The computed hash value.
   * @see #engineReset
   */
  @Override
  protected byte[] engineDigest() {
    final byte[] digest = new byte[digestLength_];
    doPadding();
    engineGetDigest(digest, 0);
    engineReset();

    return digest;
  }

  /**
   * <b>SPI</b>: Returns the length of the digest in bytes.
   * <p>
   * May not be available for applications before JDK versions >= 1.2.x.
   * 
   * @return the length of the digest in bytes.
   */
  @Override
  public int engineGetDigestLength() {
    return digestLength_;
  }

  /**
   * Apply the compression function of this hash to the given input block. The
   * input block has the block-length of the hash.
   * <code>offset + blocksize &lt; input.length</code>.
   * 
   * @param input
   *          The buffer_ that contains the input block.
   * @param offset
   *          The offset where in the input buffer_ the block starts.
   */
  abstract void engineCompress(byte[] input, int offset);

  /**
   * Do the final padding_ and perform last compression.
   */
  abstract void doPadding();

  /**
   * Get digest value of the hash, but do not reset the hash automatically.
   * <code>offset + digestlength &lt; output</code>.
   * 
   * @param output
   *          The buffer_ where to put the hash value.
   * @param offset
   *          The offset in the buffer_ where to start writing the hash.
   */
  abstract void engineGetDigest(byte[] output, int offset);

  /**
   * <b>SPI</b>: Resets this message digest for further use.
   */
  @Override
  protected abstract void engineReset();

}
