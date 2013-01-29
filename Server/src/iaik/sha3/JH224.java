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
 * The <i>JH-224</i> message digest algorithm produces a 224-bit hash-value of
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
 * MessageDigest JH = MessageDigest.getInstance(&quot;JH224&quot;);
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
public final class JH224 extends JH {

  // some constants
  static final int BLOCK_SIZE = 64;
  static final int DIGEST_LENGTH = 28;

  final static byte[] IV = { 0x2d, (byte) 0xfe, (byte) 0xdd, 0x62, (byte) 0xf9, (byte) 0x9a,
      (byte) 0x98, (byte) 0xac, (byte) 0xae, 0x7c, (byte) 0xac, (byte) 0xd6, 0x19, (byte) 0xd6,
      0x34, (byte) 0xe7, (byte) 0xa4, (byte) 0x83, 0x10, 0x5, (byte) 0xbc, 0x30, 0x12, 0x16,
      (byte) 0xb8, 0x60, 0x38, (byte) 0xc6, (byte) 0xc9, 0x66, 0x14, (byte) 0x94, 0x66,
      (byte) 0xd9, (byte) 0x89, (byte) 0x9f, 0x25, (byte) 0x80, 0x70, 0x6f, (byte) 0xce,
      (byte) 0x9e, (byte) 0xa3, 0x1b, 0x1d, (byte) 0x9b, 0x1a, (byte) 0xdc, 0x11, (byte) 0xe8,
      0x32, 0x5f, 0x7b, 0x36, 0x6e, 0x10, (byte) 0xf9, (byte) 0x94, (byte) 0x85, 0x7f, 0x2,
      (byte) 0xfa, 0x6, (byte) 0xc1, 0x1b, 0x4f, 0x1b, 0x5c, (byte) 0xd8, (byte) 0xc8, 0x40,
      (byte) 0xb3, (byte) 0x97, (byte) 0xf6, (byte) 0xa1, 0x7f, 0x6e, 0x73, (byte) 0x80,
      (byte) 0x99, (byte) 0xdc, (byte) 0xdf, (byte) 0x93, (byte) 0xa5, (byte) 0xad, (byte) 0xea,
      (byte) 0xa3, (byte) 0xd3, (byte) 0xa4, 0x31, (byte) 0xe8, (byte) 0xde, (byte) 0xc9, 0x53,
      (byte) 0x9a, 0x68, 0x22, (byte) 0xb4, (byte) 0xa9, (byte) 0x8a, (byte) 0xec, (byte) 0x86,
      (byte) 0xa1, (byte) 0xe4, (byte) 0xd5, 0x74, (byte) 0xac, (byte) 0x95, (byte) 0x9c,
      (byte) 0xe5, 0x6c, (byte) 0xf0, 0x15, (byte) 0x96, 0xd, (byte) 0xea, (byte) 0xb5,
      (byte) 0xab, 0x2b, (byte) 0xbf, (byte) 0x96, 0x11, (byte) 0xdc, (byte) 0xf0, (byte) 0xdd,
      0x64, (byte) 0xea, 0x6e };

  /**
   * Default constructor.
   */
  public JH224() {
    super(BLOCK_SIZE, DIGEST_LENGTH, IV);
  }

}
