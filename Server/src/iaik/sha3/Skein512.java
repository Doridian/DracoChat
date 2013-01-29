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
 * This class implements the Skein message digest algorithm.
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
 * The <i>Skein-512</i> message digest algorithm produces a 512-bit hash-value
 * of the given input data.
 * <p>
 * This class extends the <code>java.security.MessageDigest</code> class and
 * applications should use one of the <code>getInstance</code> methods presented
 * there to create a MessageDigest-Skein object. Generally, an application
 * wishing to compute the message digest of some data has to perform three
 * steps:
 * <ul>
 * <li>First an instance of the desired message digest algorithm has to be
 * created using a proper <code>getInstance</code> method, e.g.:
 * <p>
 * <blockquote>
 * 
 * <pre>
 * MessageDigest Skein = MessageDigest.getInstance(&quot;Skein512&quot;);
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
 *     Skein.update(m1);
 *     Skein.update(m2);
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
 * byte[] hash_value = Skein.digest();
 * </pre>
 * 
 * </blockquote>
 * </ul>
 * <p>
 * There are several ways for combining <code>update</code> and
 * <code>digest</code> methods for computing a message digest. Since this class
 * implements the <code>Cloneable</code> interface, Skein MessageDigest objects
 * may be used for compute intermediate hashes through cloning (see <a href =
 * http://java.sun.com/products/JDK/1.2/docs/guide/security/CryptoSpec.html>
 * http
 * ://java.sun.com/products/JDK/1.2/docs/guide/security/CryptoSpec.html</a>).
 * <p>
 * When the hash value successfully has been computed, the Skein MessageDigest
 * object automatically resets for being able to be supplied with new data to be
 * hashed..
 * 
 * @see java.security.MessageDigest
 * 
 * @author Christian Hanser
 */
public final class Skein512 extends AbstractMessageDigestWrapper {

  // some constants
  private static final int DIGEST_LENGTH = 64;

  private final static long[] IV = { 0x4903ADFF749C51CEL, 0x0D95DE399746DF03L, 0x8FD1934127C79BCEL,
      0x9A255629FF352CB1L, 0x5DB62599DF6CA7B0L, 0xEABE394CA9D5C3F4L, 0x991112C71A75B523L,
      0xAE18A40B660FCC33L };

  /**
   * Default constructor.
   */
  public Skein512() {
    super(new RawSkein64Bit(DIGEST_LENGTH, IV));
  }

}
