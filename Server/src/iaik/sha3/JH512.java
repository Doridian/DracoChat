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
 * This class implements the JH message digest algorithm.
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
 * The <i>JH-512</i> message digest algorithm produces a 512-bit hash-value of
 * the given input data.
 * <p>
 * This class extends the <code>java.security.MessageDigest</code> class and
 * applications should use one of the <code>getInstance</code> methods presented
 * there to create a MessageDigest-JH object. Generally, an application wishing
 * to compute the message digest of some data has to perform three steps:
 * <ul>
 * <li>First an instance of the desired message digest algorithm has to be
 * created using a proper <code>getInstance</code> method, e.g.:
 * <p>
 * <blockquote>
 * 
 * <pre>
 * MessageDigest JH = MessageDigest.getInstance(&quot;JH512&quot;);
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
 *     JH.update(m1);
 *     JH.update(m2);
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
 * byte[] hash_value = JH.digest();
 * </pre>
 * 
 * </blockquote>
 * </ul>
 * <p>
 * There are several ways for combining <code>update</code> and
 * <code>digest</code> methods for computing a message digest. Since this class
 * implements the <code>Cloneable</code> interface, JH MessageDigest objects may
 * be used for compute intermediate hashes through cloning (see <a href =
 * http://java.sun.com/products/JDK/1.2/docs/guide/security/CryptoSpec.html>
 * http
 * ://java.sun.com/products/JDK/1.2/docs/guide/security/CryptoSpec.html</a>).
 * <p>
 * When the hash value successfully has been computed, the JH MessageDigest
 * object automatically resets for being able to be supplied with new data to be
 * hashed..
 * 
 * @see java.security.MessageDigest
 * 
 * @author Christian Hanser
 */
public final class JH512 extends JH {

  // some constants
  private static final int BLOCK_SIZE = 64;
  private static final int DIGEST_LENGTH = 64;

  private final static byte[] IV = { 0x6f, (byte) 0xd1, 0x4b, (byte) 0x96, 0x3e, 0x0, (byte) 0xaa,
      0x17, 0x63, 0x6a, 0x2e, 0x5, 0x7a, 0x15, (byte) 0xd5, 0x43, (byte) 0x8a, 0x22, 0x5e,
      (byte) 0x8d, 0xc, (byte) 0x97, (byte) 0xef, 0xb, (byte) 0xe9, 0x34, 0x12, 0x59, (byte) 0xf2,
      (byte) 0xb3, (byte) 0xc3, 0x61, (byte) 0x89, 0x1d, (byte) 0xa0, (byte) 0xc1, 0x53, 0x6f,
      (byte) 0x80, 0x1e, 0x2a, (byte) 0xa9, 0x5, 0x6b, (byte) 0xea, 0x2b, 0x6d, (byte) 0x80, 0x58,
      (byte) 0x8e, (byte) 0xcc, (byte) 0xdb, 0x20, 0x75, (byte) 0xba, (byte) 0xa6, (byte) 0xa9,
      0xf, 0x3a, 0x76, (byte) 0xba, (byte) 0xf8, 0x3b, (byte) 0xf7, 0x1, 0x69, (byte) 0xe6, 0x5,
      0x41, (byte) 0xe3, 0x4a, 0x69, 0x46, (byte) 0xb5, (byte) 0x8a, (byte) 0x8e, 0x2e, 0x6f,
      (byte) 0xe6, 0x5a, 0x10, 0x47, (byte) 0xa7, (byte) 0xd0, (byte) 0xc1, (byte) 0x84, 0x3c,
      0x24, 0x3b, 0x6e, 0x71, (byte) 0xb1, 0x2d, 0x5a, (byte) 0xc1, (byte) 0x99, (byte) 0xcf, 0x57,
      (byte) 0xf6, (byte) 0xec, (byte) 0x9d, (byte) 0xb1, (byte) 0xf8, 0x56, (byte) 0xa7, 0x6,
      (byte) 0x88, 0x7c, 0x57, 0x16, (byte) 0xb1, 0x56, (byte) 0xe3, (byte) 0xc2, (byte) 0xfc,
      (byte) 0xdf, (byte) 0xe6, (byte) 0x85, 0x17, (byte) 0xfb, 0x54, 0x5a, 0x46, 0x78,
      (byte) 0xcc, (byte) 0x8c, (byte) 0xdd, 0x4b };

  /**
   * Default constructor.
   */
  public JH512() {
    super(DIGEST_LENGTH, BLOCK_SIZE, IV);
  }

}
