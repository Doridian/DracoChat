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
 * KECCAK implementations optimized for 32-bit platforms.
 * 
 * @author Christian Hanser
 */
class RawKECCAK32Bit extends RawKECCAK {

  // some constants
  private static final int TABLE_SIZE = 65536;
  private static final int BYTE_MASK = 0xFF;
  private static final int UPPER_BYTE_MASK = 0xFF00;
  private static final int ALL_ONE_INT = ~0;

  private final static int[] ROUND_CONSTANTS_0 = { 0x00000001, 0x00000000, 0x00000000, 0x00000000,
      0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000000, 0x00000000, 0x00000001,
      0x00000000, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000001, 0x00000000 };

  private final static int[] ROUND_CONSTANTS_1 = { 0x00000000, 0x00000089, 0x8000008b, 0x80008080,
      0x0000008b, 0x00008000, 0x80008088, 0x80000082, 0x0000000b, 0x0000000a, 0x00008082,
      0x00008003, 0x0000808b, 0x8000000b, 0x8000008a, 0x80000081, 0x80000081, 0x80000008,
      0x00000083, 0x80008003, 0x80008088, 0x80000088, 0x00008000, 0x80008082 };

  private final int[] interleaveTable_ = new int[TABLE_SIZE];
  private final int[] deinterleaveTable_ = new int[TABLE_SIZE];

  private final int lanes_;

  // the state
  private final int[] state_ = new int[50];

  // helper vars
  private final byte[] inTemp_;
  private final byte[] outTemp_;

  /**
   * Constructs a new instance.
   * 
   * @param digestLength
   *          the digest length in bytes
   */
  RawKECCAK32Bit(int digestLength, int rate) {
    super(digestLength, rate);

    inTemp_ = new byte[blockSize_];
    lanes_ = rate >>> 6;
    outTemp_ = new byte[lanes_ << 4];

    // build interleave tables
    int x;

    for (int i = 0; i < TABLE_SIZE; i++) {
      x = 0;

      for (int j = 0; j < 16; j++) {
        if ((i & (1 << j)) != 0) {
          x |= (1 << ((j >>> 1) + ((j & 0x01) << 3)));
        }
      }

      interleaveTable_[i] = x;
      deinterleaveTable_[x] = i;
    }

    engineReset();
  }

  /**
   * Performs the interleaving.
   * 
   * @param i
   *          the current index
   * @param source
   *          the source (input) values
   */
  private void interleaveBytesIntoWords(int i, byte[] source) {
    state_[i] ^= ((interleaveTable_[((source[(i << 2) + 7] & BYTE_MASK) << 8)
        | (source[(i << 2) + 6] & BYTE_MASK)] & BYTE_MASK) << 24)
        ^ ((interleaveTable_[((source[(i << 2) + 5] & BYTE_MASK) << 8)
            | (source[(i << 2) + 4] & BYTE_MASK)] & BYTE_MASK) << 16)
        ^ ((interleaveTable_[((source[(i << 2) + 3] & BYTE_MASK) << 8)
            | (source[(i << 2) + 2] & BYTE_MASK)] & BYTE_MASK) << 8)
        ^ (interleaveTable_[((source[(i << 2) + 1] & BYTE_MASK) << 8)
            | (source[i << 2] & BYTE_MASK)] & BYTE_MASK);
    state_[i + 1] ^= ((interleaveTable_[((source[(i << 2) + 7] & BYTE_MASK) << 8)
        | (source[(i << 2) + 6] & BYTE_MASK)] & UPPER_BYTE_MASK) << 16)
        ^ ((interleaveTable_[((source[(i << 2) + 5] & BYTE_MASK) << 8)
            | (source[(i << 2) + 4] & BYTE_MASK)] & UPPER_BYTE_MASK) << 8)
        ^ (interleaveTable_[((source[(i << 2) + 3] & BYTE_MASK) << 8)
            | (source[(i << 2) + 2] & BYTE_MASK)] & UPPER_BYTE_MASK)
        ^ ((interleaveTable_[((source[(i << 2) + 1] & BYTE_MASK) << 8)
            | (source[i << 2] & BYTE_MASK)] >>> 8) & BYTE_MASK);
  }

  /**
   * Performs the deinterleaving.
   * 
   * @param i
   *          the current index
   * @param dest
   *          the destination array
   * @param even
   *          a state value of even index
   * @param odd
   *          a state value of odd index
   */
  private void deinterleaveWordsIntoBytes(int i, byte[] dest, int even, int odd) {
    final int d0 = deinterleaveTable_[((even & BYTE_MASK) | ((odd & BYTE_MASK) << 8))];
    final int d1 = deinterleaveTable_[((even >>> 8) & BYTE_MASK) | ((odd & UPPER_BYTE_MASK))];
    final int d2 = deinterleaveTable_[(((even >>> 16) & BYTE_MASK) | ((odd >>> 8) & UPPER_BYTE_MASK))];
    final int d3 = deinterleaveTable_[(((even >>> 24) & BYTE_MASK) | ((odd >>> 16) & UPPER_BYTE_MASK))];

    final int j = i << 2;
    dest[j] = (byte) d0;
    dest[j + 1] = (byte) (d0 >>> 8);
    dest[j + 2] = (byte) d1;
    dest[j + 3] = (byte) (d1 >>> 8);
    dest[j + 4] = (byte) d2;
    dest[j + 5] = (byte) (d2 >>> 8);
    dest[j + 6] = (byte) d3;
    dest[j + 7] = (byte) (d3 >>> 8);
  }

  @Override
  void engineCompress(byte[] input, int offset) {
    int Aba0, Abe0, Abi0, Abo0, Abu0;
    int Aba1, Abe1, Abi1, Abo1, Abu1;
    int Aga0, Age0, Agi0, Ago0, Agu0;
    int Aga1, Age1, Agi1, Ago1, Agu1;
    int Aka0, Ake0, Aki0, Ako0, Aku0;
    int Aka1, Ake1, Aki1, Ako1, Aku1;
    int Ama0, Ame0, Ami0, Amo0, Amu0;
    int Ama1, Ame1, Ami1, Amo1, Amu1;
    int Asa0, Ase0, Asi0, Aso0, Asu0;
    int Asa1, Ase1, Asi1, Aso1, Asu1;
    int Bba0, Bbe0, Bbi0, Bbo0, Bbu0;
    int Bba1, Bbe1, Bbi1, Bbo1, Bbu1;
    int Bga0, Bge0, Bgi0, Bgo0, Bgu0;
    int Bga1, Bge1, Bgi1, Bgo1, Bgu1;
    int Bka0, Bke0, Bki0, Bko0, Bku0;
    int Bka1, Bke1, Bki1, Bko1, Bku1;
    int Bma0, Bme0, Bmi0, Bmo0, Bmu0;
    int Bma1, Bme1, Bmi1, Bmo1, Bmu1;
    int Bsa0, Bse0, Bsi0, Bso0, Bsu0;
    int Bsa1, Bse1, Bsi1, Bso1, Bsu1;
    int Ca0, Ce0, Ci0, Co0, Cu0;
    int Ca1, Ce1, Ci1, Co1, Cu1;
    int Da0, De0, Di0, Do0, Du0;
    int Da1, De1, Di1, Do1, Du1;
    int Eba0, Ebe0, Ebi0, Ebo0, Ebu0;
    int Eba1, Ebe1, Ebi1, Ebo1, Ebu1;
    int Ega0, Ege0, Egi0, Ego0, Egu0;
    int Ega1, Ege1, Egi1, Ego1, Egu1;
    int Eka0, Eke0, Eki0, Eko0, Eku0;
    int Eka1, Eke1, Eki1, Eko1, Eku1;
    int Ema0, Eme0, Emi0, Emo0, Emu0;
    int Ema1, Eme1, Emi1, Emo1, Emu1;
    int Esa0, Ese0, Esi0, Eso0, Esu0;
    int Esa1, Ese1, Esi1, Eso1, Esu1;

    if (offset == 0) {
      for (int i = 0; i < (lanes_ << 1); i += 2) {
        interleaveBytesIntoWords(i, input);
      }
    } else {
      System.arraycopy(input, offset, inTemp_, 0, blockSize_);

      for (int i = 0; i < (lanes_ << 1); i += 2) {
        interleaveBytesIntoWords(i, inTemp_);
      }
    }

    Aba0 = state_[0];
    Aba1 = state_[1];
    Abe0 = state_[2];
    Abe1 = state_[3];
    Abi0 = state_[4];
    Abi1 = state_[5];
    Abo0 = state_[6];
    Abo1 = state_[7];
    Abu0 = state_[8];
    Abu1 = state_[9];
    Aga0 = state_[10];
    Aga1 = state_[11];
    Age0 = state_[12];
    Age1 = state_[13];
    Agi0 = state_[14];
    Agi1 = state_[15];
    Ago0 = state_[16];
    Ago1 = state_[17];
    Agu0 = state_[18];
    Agu1 = state_[19];
    Aka0 = state_[20];
    Aka1 = state_[21];
    Ake0 = state_[22];
    Ake1 = state_[23];
    Aki0 = state_[24];
    Aki1 = state_[25];
    Ako0 = state_[26];
    Ako1 = state_[27];
    Aku0 = state_[28];
    Aku1 = state_[29];
    Ama0 = state_[30];
    Ama1 = state_[31];
    Ame0 = state_[32];
    Ame1 = state_[33];
    Ami0 = state_[34];
    Ami1 = state_[35];
    Amo0 = state_[36];
    Amo1 = state_[37];
    Amu0 = state_[38];
    Amu1 = state_[39];
    Asa0 = state_[40];
    Asa1 = state_[41];
    Ase0 = state_[42];
    Ase1 = state_[43];
    Asi0 = state_[44];
    Asi1 = state_[45];
    Aso0 = state_[46];
    Aso1 = state_[47];
    Asu0 = state_[48];
    Asu1 = state_[49];

    Ca0 = Aba0 ^ Aga0 ^ Aka0 ^ Ama0 ^ Asa0;
    Ca1 = Aba1 ^ Aga1 ^ Aka1 ^ Ama1 ^ Asa1;
    Ce0 = Abe0 ^ Age0 ^ Ake0 ^ Ame0 ^ Ase0;
    Ce1 = Abe1 ^ Age1 ^ Ake1 ^ Ame1 ^ Ase1;
    Ci0 = Abi0 ^ Agi0 ^ Aki0 ^ Ami0 ^ Asi0;
    Ci1 = Abi1 ^ Agi1 ^ Aki1 ^ Ami1 ^ Asi1;
    Co0 = Abo0 ^ Ago0 ^ Ako0 ^ Amo0 ^ Aso0;
    Co1 = Abo1 ^ Ago1 ^ Ako1 ^ Amo1 ^ Aso1;
    Cu0 = Abu0 ^ Agu0 ^ Aku0 ^ Amu0 ^ Asu0;
    Cu1 = Abu1 ^ Agu1 ^ Aku1 ^ Amu1 ^ Asu1;

    for (int i = 0; i < 24; i += 2) {
      Da0 = Cu0 ^ ROTL(Ce1, 1);
      Da1 = Cu1 ^ Ce0;
      De0 = Ca0 ^ ROTL(Ci1, 1);
      De1 = Ca1 ^ Ci0;
      Di0 = Ce0 ^ ROTL(Co1, 1);
      Di1 = Ce1 ^ Co0;
      Do0 = Ci0 ^ ROTL(Cu1, 1);
      Do1 = Ci1 ^ Cu0;
      Du0 = Co0 ^ ROTL(Ca1, 1);
      Du1 = Co1 ^ Ca0;
      Aba0 ^= Da0;
      Bba0 = Aba0;
      Age0 ^= De0;
      Bbe0 = ROTL(Age0, 22);
      Aki1 ^= Di1;
      Bbi0 = ROTL(Aki1, 22);
      Amo1 ^= Do1;
      Bbo0 = ROTL(Amo1, 11);
      Asu0 ^= Du0;
      Bbu0 = ROTL(Asu0, 7);
      Eba0 = Bba0 ^ (Bbe0 | Bbi0);
      Eba0 ^= ROUND_CONSTANTS_0[i];
      Ca0 = Eba0;
      Ebe0 = Bbe0 ^ ((~Bbi0) | Bbo0);
      Ce0 = Ebe0;
      Ebi0 = Bbi0 ^ (Bbo0 & Bbu0);
      Ci0 = Ebi0;
      Ebo0 = Bbo0 ^ (Bbu0 | Bba0);
      Co0 = Ebo0;
      Ebu0 = Bbu0 ^ (Bba0 & Bbe0);
      Cu0 = Ebu0;
      Aba1 ^= Da1;
      Bba1 = Aba1;
      Age1 ^= De1;
      Bbe1 = ROTL(Age1, 22);
      Aki0 ^= Di0;
      Bbi1 = ROTL(Aki0, 21);
      Amo0 ^= Do0;
      Bbo1 = ROTL(Amo0, 10);
      Asu1 ^= Du1;
      Bbu1 = ROTL(Asu1, 7);
      Eba1 = Bba1 ^ (Bbe1 | Bbi1);
      Eba1 ^= ROUND_CONSTANTS_1[i];
      Ca1 = Eba1;
      Ebe1 = Bbe1 ^ ((~Bbi1) | Bbo1);
      Ce1 = Ebe1;
      Ebi1 = Bbi1 ^ (Bbo1 & Bbu1);
      Ci1 = Ebi1;
      Ebo1 = Bbo1 ^ (Bbu1 | Bba1);
      Co1 = Ebo1;
      Ebu1 = Bbu1 ^ (Bba1 & Bbe1);
      Cu1 = Ebu1;
      Abo0 ^= Do0;
      Bga0 = ROTL(Abo0, 14);
      Agu0 ^= Du0;
      Bge0 = ROTL(Agu0, 10);
      Aka1 ^= Da1;
      Bgi0 = ROTL(Aka1, 2);
      Ame1 ^= De1;
      Bgo0 = ROTL(Ame1, 23);
      Asi1 ^= Di1;
      Bgu0 = ROTL(Asi1, 31);
      Ega0 = Bga0 ^ (Bge0 | Bgi0);
      Ca0 ^= Ega0;
      Ege0 = Bge0 ^ (Bgi0 & Bgo0);
      Ce0 ^= Ege0;
      Egi0 = Bgi0 ^ (Bgo0 | (~Bgu0));
      Ci0 ^= Egi0;
      Ego0 = Bgo0 ^ (Bgu0 | Bga0);
      Co0 ^= Ego0;
      Egu0 = Bgu0 ^ (Bga0 & Bge0);
      Cu0 ^= Egu0;
      Abo1 ^= Do1;
      Bga1 = ROTL(Abo1, 14);
      Agu1 ^= Du1;
      Bge1 = ROTL(Agu1, 10);
      Aka0 ^= Da0;
      Bgi1 = ROTL(Aka0, 1);
      Ame0 ^= De0;
      Bgo1 = ROTL(Ame0, 22);
      Asi0 ^= Di0;
      Bgu1 = ROTL(Asi0, 30);
      Ega1 = Bga1 ^ (Bge1 | Bgi1);
      Ca1 ^= Ega1;
      Ege1 = Bge1 ^ (Bgi1 & Bgo1);
      Ce1 ^= Ege1;
      Egi1 = Bgi1 ^ (Bgo1 | (~Bgu1));
      Ci1 ^= Egi1;
      Ego1 = Bgo1 ^ (Bgu1 | Bga1);
      Co1 ^= Ego1;
      Egu1 = Bgu1 ^ (Bga1 & Bge1);
      Cu1 ^= Egu1;
      Abe1 ^= De1;
      Bka0 = ROTL(Abe1, 1);
      Agi0 ^= Di0;
      Bke0 = ROTL(Agi0, 3);
      Ako1 ^= Do1;
      Bki0 = ROTL(Ako1, 13);
      Amu0 ^= Du0;
      Bko0 = ROTL(Amu0, 4);
      Asa0 ^= Da0;
      Bku0 = ROTL(Asa0, 9);
      Eka0 = Bka0 ^ (Bke0 | Bki0);
      Ca0 ^= Eka0;
      Eke0 = Bke0 ^ (Bki0 & Bko0);
      Ce0 ^= Eke0;
      Eki0 = Bki0 ^ ((~Bko0) & Bku0);
      Ci0 ^= Eki0;
      Eko0 = (~Bko0) ^ (Bku0 | Bka0);
      Co0 ^= Eko0;
      Eku0 = Bku0 ^ (Bka0 & Bke0);
      Cu0 ^= Eku0;
      Abe0 ^= De0;
      Bka1 = Abe0;
      Agi1 ^= Di1;
      Bke1 = ROTL(Agi1, 3);
      Ako0 ^= Do0;
      Bki1 = ROTL(Ako0, 12);
      Amu1 ^= Du1;
      Bko1 = ROTL(Amu1, 4);
      Asa1 ^= Da1;
      Bku1 = ROTL(Asa1, 9);
      Eka1 = Bka1 ^ (Bke1 | Bki1);
      Ca1 ^= Eka1;
      Eke1 = Bke1 ^ (Bki1 & Bko1);
      Ce1 ^= Eke1;
      Eki1 = Bki1 ^ ((~Bko1) & Bku1);
      Ci1 ^= Eki1;
      Eko1 = (~Bko1) ^ (Bku1 | Bka1);
      Co1 ^= Eko1;
      Eku1 = Bku1 ^ (Bka1 & Bke1);
      Cu1 ^= Eku1;
      Abu1 ^= Du1;
      Bma0 = ROTL(Abu1, 14);
      Aga0 ^= Da0;
      Bme0 = ROTL(Aga0, 18);
      Ake0 ^= De0;
      Bmi0 = ROTL(Ake0, 5);
      Ami1 ^= Di1;
      Bmo0 = ROTL(Ami1, 8);
      Aso0 ^= Do0;
      Bmu0 = ROTL(Aso0, 28);
      Ema0 = Bma0 ^ (Bme0 & Bmi0);
      Ca0 ^= Ema0;
      Eme0 = Bme0 ^ (Bmi0 | Bmo0);
      Ce0 ^= Eme0;
      Emi0 = Bmi0 ^ ((~Bmo0) | Bmu0);
      Ci0 ^= Emi0;
      Emo0 = (~Bmo0) ^ (Bmu0 & Bma0);
      Co0 ^= Emo0;
      Emu0 = Bmu0 ^ (Bma0 | Bme0);
      Cu0 ^= Emu0;
      Abu0 ^= Du0;
      Bma1 = ROTL(Abu0, 13);
      Aga1 ^= Da1;
      Bme1 = ROTL(Aga1, 18);
      Ake1 ^= De1;
      Bmi1 = ROTL(Ake1, 5);
      Ami0 ^= Di0;
      Bmo1 = ROTL(Ami0, 7);
      Aso1 ^= Do1;
      Bmu1 = ROTL(Aso1, 28);
      Ema1 = Bma1 ^ (Bme1 & Bmi1);
      Ca1 ^= Ema1;
      Eme1 = Bme1 ^ (Bmi1 | Bmo1);
      Ce1 ^= Eme1;
      Emi1 = Bmi1 ^ ((~Bmo1) | Bmu1);
      Ci1 ^= Emi1;
      Emo1 = (~Bmo1) ^ (Bmu1 & Bma1);
      Co1 ^= Emo1;
      Emu1 = Bmu1 ^ (Bma1 | Bme1);
      Cu1 ^= Emu1;
      Abi0 ^= Di0;
      Bsa0 = ROTL(Abi0, 31);
      Ago1 ^= Do1;
      Bse0 = ROTL(Ago1, 28);
      Aku1 ^= Du1;
      Bsi0 = ROTL(Aku1, 20);
      Ama1 ^= Da1;
      Bso0 = ROTL(Ama1, 21);
      Ase0 ^= De0;
      Bsu0 = ROTL(Ase0, 1);
      Esa0 = Bsa0 ^ ((~Bse0) & Bsi0);
      Ca0 ^= Esa0;
      Ese0 = (~Bse0) ^ (Bsi0 | Bso0);
      Ce0 ^= Ese0;
      Esi0 = Bsi0 ^ (Bso0 & Bsu0);
      Ci0 ^= Esi0;
      Eso0 = Bso0 ^ (Bsu0 | Bsa0);
      Co0 ^= Eso0;
      Esu0 = Bsu0 ^ (Bsa0 & Bse0);
      Cu0 ^= Esu0;
      Abi1 ^= Di1;
      Bsa1 = ROTL(Abi1, 31);
      Ago0 ^= Do0;
      Bse1 = ROTL(Ago0, 27);
      Aku0 ^= Du0;
      Bsi1 = ROTL(Aku0, 19);
      Ama0 ^= Da0;
      Bso1 = ROTL(Ama0, 20);
      Ase1 ^= De1;
      Bsu1 = ROTL(Ase1, 1);
      Esa1 = Bsa1 ^ ((~Bse1) & Bsi1);
      Ca1 ^= Esa1;
      Ese1 = (~Bse1) ^ (Bsi1 | Bso1);
      Ce1 ^= Ese1;
      Esi1 = Bsi1 ^ (Bso1 & Bsu1);
      Ci1 ^= Esi1;
      Eso1 = Bso1 ^ (Bsu1 | Bsa1);
      Co1 ^= Eso1;
      Esu1 = Bsu1 ^ (Bsa1 & Bse1);
      Cu1 ^= Esu1;
      Da0 = Cu0 ^ ROTL(Ce1, 1);
      Da1 = Cu1 ^ Ce0;
      De0 = Ca0 ^ ROTL(Ci1, 1);
      De1 = Ca1 ^ Ci0;
      Di0 = Ce0 ^ ROTL(Co1, 1);
      Di1 = Ce1 ^ Co0;
      Do0 = Ci0 ^ ROTL(Cu1, 1);
      Do1 = Ci1 ^ Cu0;
      Du0 = Co0 ^ ROTL(Ca1, 1);
      Du1 = Co1 ^ Ca0;
      Eba0 ^= Da0;
      Bba0 = Eba0;
      Ege0 ^= De0;
      Bbe0 = ROTL(Ege0, 22);
      Eki1 ^= Di1;
      Bbi0 = ROTL(Eki1, 22);
      Emo1 ^= Do1;
      Bbo0 = ROTL(Emo1, 11);
      Esu0 ^= Du0;
      Bbu0 = ROTL(Esu0, 7);
      Aba0 = Bba0 ^ (Bbe0 | Bbi0);
      Aba0 ^= ROUND_CONSTANTS_0[i + 1];
      Ca0 = Aba0;
      Abe0 = Bbe0 ^ ((~Bbi0) | Bbo0);
      Ce0 = Abe0;
      Abi0 = Bbi0 ^ (Bbo0 & Bbu0);
      Ci0 = Abi0;
      Abo0 = Bbo0 ^ (Bbu0 | Bba0);
      Co0 = Abo0;
      Abu0 = Bbu0 ^ (Bba0 & Bbe0);
      Cu0 = Abu0;
      Eba1 ^= Da1;
      Bba1 = Eba1;
      Ege1 ^= De1;
      Bbe1 = ROTL(Ege1, 22);
      Eki0 ^= Di0;
      Bbi1 = ROTL(Eki0, 21);
      Emo0 ^= Do0;
      Bbo1 = ROTL(Emo0, 10);
      Esu1 ^= Du1;
      Bbu1 = ROTL(Esu1, 7);
      Aba1 = Bba1 ^ (Bbe1 | Bbi1);
      Aba1 ^= ROUND_CONSTANTS_1[i + 1];
      Ca1 = Aba1;
      Abe1 = Bbe1 ^ ((~Bbi1) | Bbo1);
      Ce1 = Abe1;
      Abi1 = Bbi1 ^ (Bbo1 & Bbu1);
      Ci1 = Abi1;
      Abo1 = Bbo1 ^ (Bbu1 | Bba1);
      Co1 = Abo1;
      Abu1 = Bbu1 ^ (Bba1 & Bbe1);
      Cu1 = Abu1;
      Ebo0 ^= Do0;
      Bga0 = ROTL(Ebo0, 14);
      Egu0 ^= Du0;
      Bge0 = ROTL(Egu0, 10);
      Eka1 ^= Da1;
      Bgi0 = ROTL(Eka1, 2);
      Eme1 ^= De1;
      Bgo0 = ROTL(Eme1, 23);
      Esi1 ^= Di1;
      Bgu0 = ROTL(Esi1, 31);
      Aga0 = Bga0 ^ (Bge0 | Bgi0);
      Ca0 ^= Aga0;
      Age0 = Bge0 ^ (Bgi0 & Bgo0);
      Ce0 ^= Age0;
      Agi0 = Bgi0 ^ (Bgo0 | (~Bgu0));
      Ci0 ^= Agi0;
      Ago0 = Bgo0 ^ (Bgu0 | Bga0);
      Co0 ^= Ago0;
      Agu0 = Bgu0 ^ (Bga0 & Bge0);
      Cu0 ^= Agu0;
      Ebo1 ^= Do1;
      Bga1 = ROTL(Ebo1, 14);
      Egu1 ^= Du1;
      Bge1 = ROTL(Egu1, 10);
      Eka0 ^= Da0;
      Bgi1 = ROTL(Eka0, 1);
      Eme0 ^= De0;
      Bgo1 = ROTL(Eme0, 22);
      Esi0 ^= Di0;
      Bgu1 = ROTL(Esi0, 30);
      Aga1 = Bga1 ^ (Bge1 | Bgi1);
      Ca1 ^= Aga1;
      Age1 = Bge1 ^ (Bgi1 & Bgo1);
      Ce1 ^= Age1;
      Agi1 = Bgi1 ^ (Bgo1 | (~Bgu1));
      Ci1 ^= Agi1;
      Ago1 = Bgo1 ^ (Bgu1 | Bga1);
      Co1 ^= Ago1;
      Agu1 = Bgu1 ^ (Bga1 & Bge1);
      Cu1 ^= Agu1;
      Ebe1 ^= De1;
      Bka0 = ROTL(Ebe1, 1);
      Egi0 ^= Di0;
      Bke0 = ROTL(Egi0, 3);
      Eko1 ^= Do1;
      Bki0 = ROTL(Eko1, 13);
      Emu0 ^= Du0;
      Bko0 = ROTL(Emu0, 4);
      Esa0 ^= Da0;
      Bku0 = ROTL(Esa0, 9);
      Aka0 = Bka0 ^ (Bke0 | Bki0);
      Ca0 ^= Aka0;
      Ake0 = Bke0 ^ (Bki0 & Bko0);
      Ce0 ^= Ake0;
      Aki0 = Bki0 ^ ((~Bko0) & Bku0);
      Ci0 ^= Aki0;
      Ako0 = (~Bko0) ^ (Bku0 | Bka0);
      Co0 ^= Ako0;
      Aku0 = Bku0 ^ (Bka0 & Bke0);
      Cu0 ^= Aku0;
      Ebe0 ^= De0;
      Bka1 = Ebe0;
      Egi1 ^= Di1;
      Bke1 = ROTL(Egi1, 3);
      Eko0 ^= Do0;
      Bki1 = ROTL(Eko0, 12);
      Emu1 ^= Du1;
      Bko1 = ROTL(Emu1, 4);
      Esa1 ^= Da1;
      Bku1 = ROTL(Esa1, 9);
      Aka1 = Bka1 ^ (Bke1 | Bki1);
      Ca1 ^= Aka1;
      Ake1 = Bke1 ^ (Bki1 & Bko1);
      Ce1 ^= Ake1;
      Aki1 = Bki1 ^ ((~Bko1) & Bku1);
      Ci1 ^= Aki1;
      Ako1 = (~Bko1) ^ (Bku1 | Bka1);
      Co1 ^= Ako1;
      Aku1 = Bku1 ^ (Bka1 & Bke1);
      Cu1 ^= Aku1;
      Ebu1 ^= Du1;
      Bma0 = ROTL(Ebu1, 14);
      Ega0 ^= Da0;
      Bme0 = ROTL(Ega0, 18);
      Eke0 ^= De0;
      Bmi0 = ROTL(Eke0, 5);
      Emi1 ^= Di1;
      Bmo0 = ROTL(Emi1, 8);
      Eso0 ^= Do0;
      Bmu0 = ROTL(Eso0, 28);
      Ama0 = Bma0 ^ (Bme0 & Bmi0);
      Ca0 ^= Ama0;
      Ame0 = Bme0 ^ (Bmi0 | Bmo0);
      Ce0 ^= Ame0;
      Ami0 = Bmi0 ^ ((~Bmo0) | Bmu0);
      Ci0 ^= Ami0;
      Amo0 = (~Bmo0) ^ (Bmu0 & Bma0);
      Co0 ^= Amo0;
      Amu0 = Bmu0 ^ (Bma0 | Bme0);
      Cu0 ^= Amu0;
      Ebu0 ^= Du0;
      Bma1 = ROTL(Ebu0, 13);
      Ega1 ^= Da1;
      Bme1 = ROTL(Ega1, 18);
      Eke1 ^= De1;
      Bmi1 = ROTL(Eke1, 5);
      Emi0 ^= Di0;
      Bmo1 = ROTL(Emi0, 7);
      Eso1 ^= Do1;
      Bmu1 = ROTL(Eso1, 28);
      Ama1 = Bma1 ^ (Bme1 & Bmi1);
      Ca1 ^= Ama1;
      Ame1 = Bme1 ^ (Bmi1 | Bmo1);
      Ce1 ^= Ame1;
      Ami1 = Bmi1 ^ ((~Bmo1) | Bmu1);
      Ci1 ^= Ami1;
      Amo1 = (~Bmo1) ^ (Bmu1 & Bma1);
      Co1 ^= Amo1;
      Amu1 = Bmu1 ^ (Bma1 | Bme1);
      Cu1 ^= Amu1;
      Ebi0 ^= Di0;
      Bsa0 = ROTL(Ebi0, 31);
      Ego1 ^= Do1;
      Bse0 = ROTL(Ego1, 28);
      Eku1 ^= Du1;
      Bsi0 = ROTL(Eku1, 20);
      Ema1 ^= Da1;
      Bso0 = ROTL(Ema1, 21);
      Ese0 ^= De0;
      Bsu0 = ROTL(Ese0, 1);
      Asa0 = Bsa0 ^ ((~Bse0) & Bsi0);
      Ca0 ^= Asa0;
      Ase0 = (~Bse0) ^ (Bsi0 | Bso0);
      Ce0 ^= Ase0;
      Asi0 = Bsi0 ^ (Bso0 & Bsu0);
      Ci0 ^= Asi0;
      Aso0 = Bso0 ^ (Bsu0 | Bsa0);
      Co0 ^= Aso0;
      Asu0 = Bsu0 ^ (Bsa0 & Bse0);
      Cu0 ^= Asu0;
      Ebi1 ^= Di1;
      Bsa1 = ROTL(Ebi1, 31);
      Ego0 ^= Do0;
      Bse1 = ROTL(Ego0, 27);
      Eku0 ^= Du0;
      Bsi1 = ROTL(Eku0, 19);
      Ema0 ^= Da0;
      Bso1 = ROTL(Ema0, 20);
      Ese1 ^= De1;
      Bsu1 = ROTL(Ese1, 1);
      Asa1 = Bsa1 ^ ((~Bse1) & Bsi1);
      Ca1 ^= Asa1;
      Ase1 = (~Bse1) ^ (Bsi1 | Bso1);
      Ce1 ^= Ase1;
      Asi1 = Bsi1 ^ (Bso1 & Bsu1);
      Ci1 ^= Asi1;
      Aso1 = Bso1 ^ (Bsu1 | Bsa1);
      Co1 ^= Aso1;
      Asu1 = Bsu1 ^ (Bsa1 & Bse1);
      Cu1 ^= Asu1;
    }

    state_[0] = Aba0;
    state_[1] = Aba1;
    state_[2] = Abe0;
    state_[3] = Abe1;
    state_[4] = Abi0;
    state_[5] = Abi1;
    state_[6] = Abo0;
    state_[7] = Abo1;
    state_[8] = Abu0;
    state_[9] = Abu1;
    state_[10] = Aga0;
    state_[11] = Aga1;
    state_[12] = Age0;
    state_[13] = Age1;
    state_[14] = Agi0;
    state_[15] = Agi1;
    state_[16] = Ago0;
    state_[17] = Ago1;
    state_[18] = Agu0;
    state_[19] = Agu1;
    state_[20] = Aka0;
    state_[21] = Aka1;
    state_[22] = Ake0;
    state_[23] = Ake1;
    state_[24] = Aki0;
    state_[25] = Aki1;
    state_[26] = Ako0;
    state_[27] = Ako1;
    state_[28] = Aku0;
    state_[29] = Aku1;
    state_[30] = Ama0;
    state_[31] = Ama1;
    state_[32] = Ame0;
    state_[33] = Ame1;
    state_[34] = Ami0;
    state_[35] = Ami1;
    state_[36] = Amo0;
    state_[37] = Amo1;
    state_[38] = Amu0;
    state_[39] = Amu1;
    state_[40] = Asa0;
    state_[41] = Asa1;
    state_[42] = Ase0;
    state_[43] = Ase1;
    state_[44] = Asi0;
    state_[45] = Asi1;
    state_[46] = Aso0;
    state_[47] = Aso1;
    state_[48] = Asu0;
    state_[49] = Asu1;
  }

  /**
   * Performs a circular left rotation on an <code>int</code>.
   * 
   * @param a
   *          the integer
   * @param n
   *          the number of shift bits
   * @return the rotated long
   */
  private static int ROTL(int value, int n) {
    return (value << n) | (value >>> (32 - n));
  }

  @Override
  void doPadding() {
    final int paddingBytes = (int) (((blockSize_ - count_) % blockSize_) + blockSize_) % blockSize_;

    if (paddingBytes > 2) {
      engineUpdate(TWO_BYTE_PADDING[0]);
      engineUpdate(padding_, 1, paddingBytes - 2);
      engineUpdate(TWO_BYTE_PADDING[1]);
    } else if (paddingBytes == 0) {
      engineUpdate(TWO_BYTE_PADDING[0]);
      engineUpdate(padding_, 1, blockSize_ - 2);
      engineUpdate(TWO_BYTE_PADDING[1]);
    } else if (paddingBytes == 1) {
      engineUpdate(ONE_BYTE_PADDING);
    } else {
      engineUpdate(TWO_BYTE_PADDING, 0, 2);
    }
  }

  @Override
  void engineGetDigest(byte[] output, int offset) {
    for (int i = 0; i < (lanes_ << 1); i += 2) {
      deinterleaveWordsIntoBytes(i, outTemp_, state_[i], state_[i + 1]);
    }

    outTemp_[8] = (byte) ~outTemp_[8];
    outTemp_[9] = (byte) ~outTemp_[9];
    outTemp_[10] = (byte) ~outTemp_[10];
    outTemp_[11] = (byte) ~outTemp_[11];

    outTemp_[12] = (byte) ~outTemp_[12];
    outTemp_[13] = (byte) ~outTemp_[13];
    outTemp_[14] = (byte) ~outTemp_[14];
    outTemp_[15] = (byte) ~outTemp_[15];

    outTemp_[16] = (byte) ~outTemp_[16];
    outTemp_[17] = (byte) ~outTemp_[17];
    outTemp_[18] = (byte) ~outTemp_[18];
    outTemp_[19] = (byte) ~outTemp_[19];

    outTemp_[20] = (byte) ~outTemp_[20];
    outTemp_[21] = (byte) ~outTemp_[21];
    outTemp_[22] = (byte) ~outTemp_[22];
    outTemp_[23] = (byte) ~outTemp_[23];

    if (lanes_ > 8) {
      outTemp_[64] = (byte) ~outTemp_[64];
      outTemp_[65] = (byte) ~outTemp_[65];
      outTemp_[66] = (byte) ~outTemp_[66];
      outTemp_[67] = (byte) ~outTemp_[67];

      outTemp_[68] = (byte) ~outTemp_[68];
      outTemp_[69] = (byte) ~outTemp_[69];
      outTemp_[70] = (byte) ~outTemp_[70];
      outTemp_[71] = (byte) ~outTemp_[71];

      if (lanes_ > 12) {
        outTemp_[96] = (byte) ~outTemp_[96];
        outTemp_[97] = (byte) ~outTemp_[97];
        outTemp_[98] = (byte) ~outTemp_[98];
        outTemp_[99] = (byte) ~outTemp_[99];

        outTemp_[100] = (byte) ~outTemp_[100];
        outTemp_[101] = (byte) ~outTemp_[101];
        outTemp_[102] = (byte) ~outTemp_[102];
        outTemp_[103] = (byte) ~outTemp_[103];

        if (lanes_ > 17) {
          outTemp_[136] = (byte) ~outTemp_[136];
          outTemp_[137] = (byte) ~outTemp_[137];
          outTemp_[138] = (byte) ~outTemp_[138];
          outTemp_[139] = (byte) ~outTemp_[139];

          outTemp_[140] = (byte) ~outTemp_[140];
          outTemp_[141] = (byte) ~outTemp_[141];
          outTemp_[142] = (byte) ~outTemp_[142];
          outTemp_[143] = (byte) ~outTemp_[143];
        }
      }
    }

    System.arraycopy(outTemp_, 0, output, offset, digestLength_);
  }

  @Override
  protected void engineReset() {
    super.engineReset();
    Util.zeroBlock(state_);
    Util.zeroBlock(inTemp_);
    Util.zeroBlock(outTemp_);

    state_[2] = state_[3] = state_[4] = state_[5] = state_[16] = state_[17] = state_[24] = state_[25] = state_[34] = state_[35] = state_[40] = state_[41] = ALL_ONE_INT;
  }
}
