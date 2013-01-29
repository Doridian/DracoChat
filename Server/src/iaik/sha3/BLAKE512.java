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
 * This class implements the BLAKE message digest algorithm.
 * <p>
 * A message digest algorithm represents the functionality of an one-way hash
 * function for computing a fixed sized data value (message digest, hash) from
 * input data of arbitrary size. The length of the resulting hash value usually
 * is shorter than the length of the input data. Using a one-way hash function
 * will make it easy to compute the hash from the given data, but hard to go the
 * reverse way for calculating the input data when only the hash is known.
 * Furthermore, a proper hash function should avoid any collision, meaning that
 * it has to be hard to find two different messages producing the same hash
 * value.
 * <p>
 * The <i>BLAKE-512</i> message digest algorithm produces a 512-bit hash-value
 * of the given input data.
 * <p>
 * This class extends the <code>java.security.MessageDigest</code> class and
 * applications should use one of the <code>getInstance</code> methods presented
 * there to create a MessageDigest-BLAKE object. Generally, an application
 * wishing to compute the message digest of some data has to perform three
 * steps:
 * <ul>
 * <li>First an instance of the desired message digest algorithm has to be
 * created using a proper <code>getInstance</code> method, e.g.:
 * <p>
 * <blockquote>
 * 
 * <pre>
 * MessageDigest BLAKE = MessageDigest.getInstance(&quot;BLAKE512&quot;);
 * </pre>
 * 
 * </blockquote>
 * <p>
 * <li>Second, the data to be hashed is supplied to the MessageDigest object
 * just created by one or more calls to one of the <code>update</code> methods,
 * e.g: <br>
 * <blockquote>
 * 
 * <PRE>
 *     BLAKE.update(m1);
 *     BLAKE.update(m2);
 *     ...
 * </PRE>
 * 
 * </blockquote>
 * <p>
 * <li>Finally, the hash value can be computed using one of the
 * <code>digest</code> methods: <br>
 * <blockquote>
 * 
 * <pre>
 * byte[] hash_value = BLAKE.digest();
 * </pre>
 * 
 * </blockquote>
 * </ul>
 * <p>
 * There are several ways for combining <code>update</code> and
 * <code>digest</code> methods for computing a message digest. Since this class
 * implements the <code>Cloneable</code> interface, BLAKE MessageDigest objects
 * may be used for compute intermediate hashes through cloning (see <a href =
 * http://java.sun.com/products/JDK/1.2/docs/guide/security/CryptoSpec.html>
 * http
 * ://java.sun.com/products/JDK/1.2/docs/guide/security/CryptoSpec.html</a>).
 * <p>
 * When the hash value successfully has been computed, the BLAKE MessageDigest
 * object automatically resets for being able to be supplied with new data to be
 * hashed..
 * 
 * @see java.security.MessageDigest
 * 
 * @author Christian Hanser
 */
public final class BLAKE512 extends BLAKE64Bit {

  // some constants
  private static final int DIGEST_LENGTH = 64;
  private static final long[] IV = { 0x6A09E667F3BCC908L, 0xBB67AE8584CAA73BL, 0x3C6EF372FE94F82BL,
      0xA54FF53A5F1D36F1L, 0x510E527FADE682D1L, 0x9B05688C2B3E6C1FL, 0x1F83D9ABFB41BD6BL,
      0x5BE0CD19137E2179L };

  private static final byte END_OF_PADDING_BYTE = 1;

  /**
   * Default constructor.
   */
  public BLAKE512() {
    super(DIGEST_LENGTH, IV, END_OF_PADDING_BYTE);
  }

}
