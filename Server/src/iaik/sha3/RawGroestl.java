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
 * Base class for 32 and 64 Bit Groestl variants.
 * 
 * @author Christian Hanser
 */
abstract class RawGroestl extends AbstractMessageDigest {

  final int blockBitLength_;
  byte[] bits_ = new byte[8];

  /**
   * Constructs a new instance.
   * 
   * @param digestLength_
   *          the hash length in bytes
   * @param blockSize_
   *          the block size in bytes
   */
  RawGroestl(int digestLength, int blockSize) {
    super("Groestl" + (digestLength << 3), digestLength, blockSize);

    blockBitLength_ = blockSize << 3;
  }

  @Override
  protected void doPadding() {
    final long bitcount = count_ << 3;
    // emulate the modulo operator, as % calculates only the remainder
    final int w = (((int) (-bitcount - 65) % blockBitLength_) + blockBitLength_) % blockBitLength_;
    final long length = (bitcount + w + 65) / blockBitLength_;

    for (int i = 0; i < bits_.length; i++) {
      bits_[7 - i] = (byte) (length >>> (i << 3));
    }

    // w + 1, due to the leading 1 is contained in padding_
    engineUpdate(padding_, 0, (w + 1) >>> 3);
    engineUpdate(bits_, 0, bits_.length);
  }

  @Override
  protected void engineReset() {
    count_ = 0;
    Util.zeroBlock(bits_);
    Util.zeroBlock(buffer_);
  }

}
