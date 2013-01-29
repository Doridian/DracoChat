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
 * The <i>JH-384</i> message digest algorithm produces a 384-bit hash-value of
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
 * MessageDigest JH = MessageDigest.getInstance(&quot;JH384&quot;);
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
public final class JH384 extends JH {

  // some constants
  private static final int BLOCK_SIZE = 64;
  private static final int DIGEST_LENGTH = 48;

  private final static byte[] IV = { 0x48, 0x1e, 0x3b, (byte) 0xc6, (byte) 0xd8, 0x13, 0x39,
      (byte) 0x8a, 0x6d, 0x3b, 0x5e, (byte) 0x89, 0x4a, (byte) 0xde, (byte) 0x87, (byte) 0x9b,
      0x63, (byte) 0xfa, (byte) 0xea, 0x68, (byte) 0xd4, (byte) 0x80, (byte) 0xad, 0x2e, 0x33,
      0x2c, (byte) 0xcb, 0x21, 0x48, 0xf, (byte) 0x82, 0x67, (byte) 0x98, (byte) 0xae, (byte) 0xc8,
      0x4d, (byte) 0x90, (byte) 0x82, (byte) 0xb9, 0x28, (byte) 0xd4, 0x55, (byte) 0xea, 0x30,
      0x41, 0x11, 0x42, 0x49, (byte) 0x36, (byte) 0xf5, 0x55, (byte) 0xb2, (byte) 0x92, 0x48, 0x47,
      (byte) 0xec, (byte) 0xc7, 0x25, 0xa, (byte) 0x93, (byte) 0xba, (byte) 0xf4, 0x3c,
      (byte) 0xe1, 0x56, (byte) 0x9b, 0x7f, (byte) 0x8a, 0x27, (byte) 0xdb, 0x45, 0x4c,
      (byte) 0x9e, (byte) 0xfc, (byte) 0xbd, 0x49, 0x63, (byte) 0x97, (byte) 0xaf, 0xe, 0x58,
      (byte) 0x9f, (byte) 0xc2, 0x7d, 0x26, (byte) 0xaa, (byte) 0x80, (byte) 0xcd, (byte) 0x80,
      (byte) 0xc0, (byte) 0x8b, (byte) 0x8c, (byte) 0x9d, (byte) 0xeb, 0x2e, (byte) 0xda,
      (byte) 0x8a, 0x79, (byte) 0x81, (byte) 0xe8, (byte) 0xf8, (byte) 0xd5, 0x37, 0x3a,
      (byte) 0xf4, 0x39, 0x67, (byte) 0xad, (byte) 0xdd, (byte) 0xd1, 0x7a, 0x71, (byte) 0xa9,
      (byte) 0xb4, (byte) 0xd3, (byte) 0xbd, (byte) 0xa4, 0x75, (byte) 0xd3, (byte) 0x94,
      (byte) 0x97, 0x6c, 0x3f, (byte) 0xba, (byte) 0x98, 0x42, 0x73, 0x7f };

  /**
   * Default constructor.
   */
  public JH384() {
    super(DIGEST_LENGTH, BLOCK_SIZE, IV);
  }

}
