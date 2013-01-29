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
 * This class wraps an internal implementation of a message digest. It is
 * intended to be used as super class for either 32-bit or 64-bit optimized
 * implementations. It provides information about the underlying JVM data model,
 * so that sub-classes can choose the optimized implementation.
 * 
 * @author Christian Hanser
 */
abstract class AbstractMessageDigestWrapper extends MessageDigest {

  final static int JVM_DATA_MODEL = Util.getJVMDataMode();

  private final AbstractMessageDigest delegate_;
  private final int digestLength_;

  /**
   * Constructs a new instance.
   * 
   * @param delegate
   *          an object of the actual digest implementation
   */
  AbstractMessageDigestWrapper(AbstractMessageDigest delegate) {
    super(delegate.getAlgorithm());
    delegate_ = delegate;
    digestLength_ = delegate.getDigestLength();
  }

  @Override
  protected int engineGetDigestLength() {
    return digestLength_;
  }

  protected void engineCompress(byte[] input, int offset) {
    delegate_.engineCompress(input, offset);
  }

  protected void doPadding() {
    delegate_.doPadding();
  }

  protected void engineDigest(byte[] output, int offset) {
    delegate_.engineGetDigest(output, offset);
  }

  @Override
  protected byte[] engineDigest() {
    return delegate_.engineDigest();
  }

  @Override
  protected void engineUpdate(byte input) {
    delegate_.engineUpdate(input);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    delegate_.engineUpdate(input, offset, len);
  }

  @Override
  protected void engineReset() {
    delegate_.engineReset();
  }
}
