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
 * The <i>JH-256</i> message digest algorithm produces a 256-bit hash-value of
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
 * MessageDigest JH = MessageDigest.getInstance(&quot;JH256&quot;);
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
public final class JH256 extends JH {

  // some constants
  private static final int BLOCK_SIZE = 64;
  private static final int DIGEST_LENGTH = 32;

  private final static byte[] IV = { (byte) 0xeb, (byte) 0x98, (byte) 0xa3, 0x41, 0x2c, 0x20,
      (byte) 0xd3, (byte) 0xeb, (byte) 0x92, (byte) 0xcd, (byte) 0xbe, 0x7b, (byte) 0x9c,
      (byte) 0xb2, 0x45, (byte) 0xc1, 0x1c, (byte) 0x93, 0x51, (byte) 0x91, 0x60, (byte) 0xd4,
      (byte) 0xc7, (byte) 0xfa, 0x26, 0x0, (byte) 0x82, (byte) 0xd6, 0x7e, 0x50, (byte) 0x8a,
      (byte) 0x3, (byte) 0xa4, 0x23, (byte) 0x9e, 0x26, 0x77, 0x26, (byte) 0xb9, 0x45, (byte) 0xe0,
      (byte) 0xfb, 0x1a, 0x48, (byte) 0xd4, 0x1a, (byte) 0x94, 0x77, (byte) 0xcd, (byte) 0xb5,
      (byte) 0xab, 0x26, 0x2, 0x6b, 0x17, 0x7a, 0x56, (byte) 0xf0, 0x24, 0x42, 0xf, (byte) 0xff,
      0x2f, (byte) 0xa8, 0x71, (byte) 0xa3, (byte) 0x96, (byte) 0x89, 0x7f, 0x2e, 0x4d, 0x75, 0x1d,
      0x14, 0x49, 0x8, (byte) 0xf7, 0x7d, (byte) 0xe2, 0x62, 0x27, 0x76, (byte) 0x95, (byte) 0xf7,
      0x76, 0x24, (byte) 0x8f, (byte) 0x94, (byte) 0x87, (byte) 0xd5, (byte) 0xb6, 0x57, 0x47,
      (byte) 0x80, 0x29, 0x6c, 0x5c, 0x5e, 0x27, 0x2d, (byte) 0xac, (byte) 0x8e, 0xd, 0x6c, 0x51,
      (byte) 0x84, 0x50, (byte) 0xc6, 0x57, 0x5, 0x7a, 0xf, 0x7b, (byte) 0xe4, (byte) 0xd3, 0x67,
      0x70, 0x24, 0x12, (byte) 0xea, (byte) 0x89, (byte) 0xe3, (byte) 0xab, 0x13, (byte) 0xd3,
      0x1c, (byte) 0xd7, 0x69 };

  /**
   * Default constructor.
   */
  public JH256() {
    super(DIGEST_LENGTH, BLOCK_SIZE, IV);
  }
}
