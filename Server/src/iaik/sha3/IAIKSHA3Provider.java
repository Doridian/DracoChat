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

import java.security.AccessController;
import java.security.Provider;
import java.util.ArrayList;

public final class IAIKSHA3Provider extends Provider {

  private static final long serialVersionUID = 6209466469704580315L;

  private final static String NAME = "IAIK_SHA3";
  private final static double VERSION = 1.0;
  private final static String INFO = "IAIK SHA3 MessageDigest Provider";

  private static volatile IAIKSHA3Provider instance_;

  // @formatter:off
  private final static String[][] ALGORITHMS = {
    { "MessageDigest", "BLAKE224", "iaik.sha3.BLAKE224" },
    { "MessageDigest", "BLAKE256", "iaik.sha3.BLAKE256" },
    { "MessageDigest", "BLAKE384", "iaik.sha3.BLAKE384" },
    { "MessageDigest", "BLAKE512", "iaik.sha3.BLAKE512" },
    { "MessageDigest", "Groestl224", "iaik.sha3.Groestl224" },
    { "MessageDigest", "Groestl256", "iaik.sha3.Groestl256" },
    { "MessageDigest", "Groestl384", "iaik.sha3.Groestl384" },
    { "MessageDigest", "Groestl512", "iaik.sha3.Groestl512" },
    { "MessageDigest", "JH224", "iaik.sha3.JH224" },
    { "MessageDigest", "JH256", "iaik.sha3.JH256" },
    { "MessageDigest", "JH384", "iaik.sha3.JH384" },
    { "MessageDigest", "JH512", "iaik.sha3.JH512" },
    { "MessageDigest", "KECCAK224", "iaik.sha3.KECCAK224" },
    { "MessageDigest", "KECCAK256", "iaik.sha3.KECCAK256" },
    { "MessageDigest", "KECCAK384", "iaik.sha3.KECCAK384" },
    { "MessageDigest", "KECCAK512", "iaik.sha3.KECCAK512" },
    { "MessageDigest", "Skein224", "iaik.sha3.Skein224" },
    { "MessageDigest", "Skein256", "iaik.sha3.Skein256" },
    { "MessageDigest", "Skein384", "iaik.sha3.Skein384" },
    { "MessageDigest", "Skein512", "iaik.sha3.Skein512" },
  };
  // @formatter:on

  /**
   * Create a new instance of the IAIK SHA3 provider.
   */
  public IAIKSHA3Provider() {
    super(NAME, VERSION, INFO);

    AccessController.<Object> doPrivileged(new java.security.PrivilegedAction<Object>() {
      @Override
      public Object run() {
        addProtocols();
        return null;
      }
    });
  }

  /**
   * Adds the supported protocols.
   */
  void addProtocols() {
    for (final String[] element : ALGORITHMS) {
      ArrayList<String> aliases = null;
      final int size = element.length - 3;

      // compile the aliases, if there are any
      if (size > 0) {
        aliases = new ArrayList<String>(size);

        for (int j = 0; j < size; j++) {
          aliases.add(element[j + 3]);
        }
      }

      putService(new Service(this, element[0], element[1], element[2], aliases, null));
    }
  }

  /**
   * Returns a singleton of this provider.
   * 
   * @return a unique instance of this provider
   */
  public static IAIKSHA3Provider getInstance() {
    IAIKSHA3Provider instance = instance_;

    // single-check idiom
    if (instance == null) {
      instance = new IAIKSHA3Provider();
      instance_ = instance;
    }

    return instance;
  }

  /**
   * You can use this static method to register this provider.
   */
  public static void addAsProvider() {
    java.security.Security.addProvider(getInstance());
  }

  /**
   * You can use this static method to register this provider.
   * 
   * @param position
   *          the position for this provider
   */
  public static void insertProviderAt(int position) {
    java.security.Security.insertProviderAt(getInstance(), position);
  }

}
