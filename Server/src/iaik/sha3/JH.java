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
 * Super class for JH implementations.
 * 
 * @author Christian Hanser
 */
abstract class JH extends AbstractMessageDigestWrapper {

  /**
   * Create a new instance.
   * 
   * @param digestLength
   *          the desired digest length
   * @param blockSize
   *          the corresponding block size
   * @param iv
   *          the initialization vector
   */
  public JH(int digestLength, int blockSize, byte[] iv) {
    super(getDigest(digestLength, blockSize, iv));
  }

  /**
   * Returns the appropriate hash implementation (either for 32bit or 64bit
   * VMs).
   * 
   * @return the according raw hash
   */
  protected static RawJH getDigest(int digestLength, int blockSize, byte[] iv) {
    return (JVM_DATA_MODEL == 32) ? new RawJH32Bit(digestLength, blockSize, iv) : new RawJH64Bit(
        digestLength, blockSize, iv);
  }

}
