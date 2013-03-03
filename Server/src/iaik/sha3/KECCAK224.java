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
 * This class implements the KECCAK message digest algorithm.
 * <p/>
 * A message digest algorithm represents the functionality of an one-way hash
 * function for computing a fixed sized data value (message digest, hash) from
 * input data of arbitrary size. The length of the resulting hash value usually
 * is shorter than the length of the input data. Using a one-way hash function
 * will make it easy to compute the hash from the given data, but hard to go the
 * reverse way for calculating the input data when only the hash is known.
 * Furthermore, a proper hash function should avoid any collision, meaning that
 * it has to be hard to find two different messages producing the same hash
 * value.
 * <p/>
 * The <i>KECCAK-224</i> message digest algorithm produces a 224-bit hash-value
 * of the given input data.
 * <p/>
 * This class extends the <code>java.security.MessageDigest</code> class and
 * applications should use one of the <code>getInstance</code> methods presented
 * there to create a MessageDigest-KECCAK object. Generally, an application
 * wishing to compute the message digest of some data has to perform three
 * steps:
 * <ul>
 * <li>First an instance of the desired message digest algorithm has to be
 * created using a proper <code>getInstance</code> method, e.g.:
 * <p/>
 * <blockquote>
 * <p/>
 * <pre>
 * MessageDigest KECCAK = MessageDigest.getInstance(&quot;KECCAK224&quot;);
 * </pre>
 * <p/>
 * </blockquote>
 * <p/>
 * <li>Second, the data to be hashed is supplied to the MessageDigest object
 * just created by one or more calls to one of the <code>update</code> methods,
 * e.g: <br>
 * <blockquote>
 * <p/>
 * <PRE>
 * KECCAK.update(m1);
 * KECCAK.update(m2);
 * ...
 * </PRE>
 * <p/>
 * </blockquote>
 * <p/>
 * <li>Finally, the hash value can be computed using one of the
 * <code>digest</code> methods: <br>
 * <blockquote>
 * <p/>
 * <pre>
 * byte[] hash_value = KECCAK.digest();
 * </pre>
 * <p/>
 * </blockquote>
 * </ul>
 * <p/>
 * There are several ways for combining <code>update</code> and
 * <code>digest</code> methods for computing a message digest. Since this class
 * implements the <code>Cloneable</code> interface, KECCAK MessageDigest objects
 * may be used for compute intermediate hashes through cloning (see <a href =
 * http://java.sun.com/products/JDK/1.2/docs/guide/security/CryptoSpec.html>
 * http
 * ://java.sun.com/products/JDK/1.2/docs/guide/security/CryptoSpec.html</a>).
 * <p/>
 * When the hash value successfully has been computed, the KECCAK MessageDigest
 * object automatically resets for being able to be supplied with new data to be
 * hashed..
 *
 * @author Christian Hanser
 * @see java.security.MessageDigest
 */
public final class KECCAK224 extends KECCAK {

	private final static int DIGEST_LENGTH = 28;
	private final static int RATE = 1152;

	/**
	 * Default constructor.
	 */
	public KECCAK224() {
		super(DIGEST_LENGTH, RATE);
	}

}
