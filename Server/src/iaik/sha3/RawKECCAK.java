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
 * Super class for all KECCAK implementations.
 * 
 * @author Christian Hanser
 */
abstract class RawKECCAK extends AbstractMessageDigest {

  // some constants
  static final byte ONE_BYTE_PADDING = (byte) 0x81;
  static final byte[] TWO_BYTE_PADDING = new byte[] { 0x01, (byte) 0x80 };

  /**
   * Constructs a new instance.
   * 
   * @param digestLength
   *          the digest length in bytes
   * @param rate
   *          the rate in bits
   */
  RawKECCAK(int digestLength, int rate) {
    super("KECCAK" + (digestLength << 3), digestLength, rate >>> 3);
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
    final int index = (int) count_ % blockSize_;
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

  @Override
  protected void engineReset() {
    count_ = 0;
    Util.zeroBlock(buffer_);
  }
}
