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
 * KECCAK implementations optimized for 64-bit platforms.
 * 
 * @author Christian Hanser
 */
final class RawKECCAK64Bit extends RawKECCAK {

  // some constants
  private final static long ALL_ONE_LONG = ~0L;

  private static final long[] ROUND_CONSTANTS = { 0x0000000000000001L, 0x0000000000008082L,
      0x800000000000808AL, 0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L,
      0x8000000080008081L, 0x8000000000008009L, 0x000000000000008AL, 0x0000000000000088L,
      0x0000000080008009L, 0x000000008000000AL, 0x000000008000808BL, 0x800000000000008BL,
      0x8000000000008089L, 0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
      0x000000000000800AL, 0x800000008000000AL, 0x8000000080008081L, 0x8000000000008080L,
      0x0000000080000001L, 0x8000000080008008L };

  // the state
  private final long[] state_ = new long[25];
  private final int digestLongLength_;

  // helver vars
  private final long[] dataWordsTemp_ = new long[16];
  private final byte[] outTemp_ = new byte[32];

  /**
   * Constructs a new instance.
   * 
   * @param digestLength_
   *          the digest length in bytes
   */
  RawKECCAK64Bit(int digestLength, int rate) {
    super(digestLength, rate);

    digestLongLength_ = digestLength >>> 3;
    engineReset();
  }

  /**
   * Performs a circular left rotation on a <code>long</code>.
   * 
   * @param a
   *          the long
   * @param n
   *          the number of shift bits
   * 
   * @return the rotated long
   */
  private static long ROTL(long a, int n) {
    return (a << n) | (a >>> (64 - n));
  }

  @Override
  void engineCompress(byte[] input, int offset) {
    Util.squashBytesToLongsLE(input, offset, dataWordsTemp_, 0, dataWordsTemp_.length);

    long Aba, Abe, Abi, Abo, Abu;
    long Aga, Age, Agi, Ago, Agu;
    long Aka, Ake, Aki, Ako, Aku;
    long Ama, Ame, Ami, Amo, Amu;
    long Asa, Ase, Asi, Aso, Asu;
    long Bba, Bbe, Bbi, Bbo, Bbu;
    long Bga, Bge, Bgi, Bgo, Bgu;
    long Bka, Bke, Bki, Bko, Bku;
    long Bma, Bme, Bmi, Bmo, Bmu;
    long Bsa, Bse, Bsi, Bso, Bsu;
    long Ca, Ce, Ci, Co, Cu;
    long Da, De, Di, Do, Du;
    long Eba, Ebe, Ebi, Ebo, Ebu;
    long Ega, Ege, Egi, Ego, Egu;
    long Eka, Eke, Eki, Eko, Eku;
    long Ema, Eme, Emi, Emo, Emu;
    long Esa, Ese, Esi, Eso, Esu;

    Aba = state_[0] ^ dataWordsTemp_[0];
    Abe = state_[1] ^ dataWordsTemp_[1];
    Abi = state_[2] ^ dataWordsTemp_[2];
    Abo = state_[3] ^ dataWordsTemp_[3];
    Abu = state_[4] ^ dataWordsTemp_[4];
    Aga = state_[5] ^ dataWordsTemp_[5];
    Age = state_[6] ^ dataWordsTemp_[6];
    Agi = state_[7] ^ dataWordsTemp_[7];
    Ago = state_[8] ^ dataWordsTemp_[8];
    Agu = state_[9] ^ dataWordsTemp_[9];
    Aka = state_[10] ^ dataWordsTemp_[10];
    Ake = state_[11] ^ dataWordsTemp_[11];
    Aki = state_[12] ^ dataWordsTemp_[12];
    Ako = state_[13] ^ dataWordsTemp_[13];
    Aku = state_[14] ^ dataWordsTemp_[14];
    Ama = state_[15] ^ dataWordsTemp_[15];
    Ame = state_[16];
    Ami = state_[17];
    Amo = state_[18];
    Amu = state_[19];
    Asa = state_[20];
    Ase = state_[21];
    Asi = state_[22];
    Aso = state_[23];
    Asu = state_[24];

    Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    for (int i = 0; i < 24; i += 2) {
      Da = Cu ^ ROTL(Ce, 1);
      De = Ca ^ ROTL(Ci, 1);
      Di = Ce ^ ROTL(Co, 1);
      Do = Ci ^ ROTL(Cu, 1);
      Du = Co ^ ROTL(Ca, 1);

      Aba ^= Da;
      Bba = Aba;
      Age ^= De;
      Bbe = ROTL(Age, 44);
      Aki ^= Di;
      Bbi = ROTL(Aki, 43);
      Amo ^= Do;
      Bbo = ROTL(Amo, 21);
      Asu ^= Du;
      Bbu = ROTL(Asu, 14);
      Eba = Bba ^ (Bbe | Bbi);
      Eba ^= ROUND_CONSTANTS[i];
      Ca = Eba;
      Ebe = Bbe ^ ((~Bbi) | Bbo);
      Ce = Ebe;
      Ebi = Bbi ^ (Bbo & Bbu);
      Ci = Ebi;
      Ebo = Bbo ^ (Bbu | Bba);
      Co = Ebo;
      Ebu = Bbu ^ (Bba & Bbe);
      Cu = Ebu;

      Abo ^= Do;
      Bga = ROTL(Abo, 28);
      Agu ^= Du;
      Bge = ROTL(Agu, 20);
      Aka ^= Da;
      Bgi = ROTL(Aka, 3);
      Ame ^= De;
      Bgo = ROTL(Ame, 45);
      Asi ^= Di;
      Bgu = ROTL(Asi, 61);
      Ega = Bga ^ (Bge | Bgi);
      Ca ^= Ega;
      Ege = Bge ^ (Bgi & Bgo);
      Ce ^= Ege;
      Egi = Bgi ^ (Bgo | (~Bgu));
      Ci ^= Egi;
      Ego = Bgo ^ (Bgu | Bga);
      Co ^= Ego;
      Egu = Bgu ^ (Bga & Bge);
      Cu ^= Egu;

      Abe ^= De;
      Bka = ROTL(Abe, 1);
      Agi ^= Di;
      Bke = ROTL(Agi, 6);
      Ako ^= Do;
      Bki = ROTL(Ako, 25);
      Amu ^= Du;
      Bko = ROTL(Amu, 8);
      Asa ^= Da;
      Bku = ROTL(Asa, 18);
      Eka = Bka ^ (Bke | Bki);
      Ca ^= Eka;
      Eke = Bke ^ (Bki & Bko);
      Ce ^= Eke;
      Eki = Bki ^ ((~Bko) & Bku);
      Ci ^= Eki;
      Eko = (~Bko) ^ (Bku | Bka);
      Co ^= Eko;
      Eku = Bku ^ (Bka & Bke);
      Cu ^= Eku;

      Abu ^= Du;
      Bma = ROTL(Abu, 27);
      Aga ^= Da;
      Bme = ROTL(Aga, 36);
      Ake ^= De;
      Bmi = ROTL(Ake, 10);
      Ami ^= Di;
      Bmo = ROTL(Ami, 15);
      Aso ^= Do;
      Bmu = ROTL(Aso, 56);
      Ema = Bma ^ (Bme & Bmi);
      Ca ^= Ema;
      Eme = Bme ^ (Bmi | Bmo);
      Ce ^= Eme;
      Emi = Bmi ^ ((~Bmo) | Bmu);
      Ci ^= Emi;
      Emo = (~Bmo) ^ (Bmu & Bma);
      Co ^= Emo;
      Emu = Bmu ^ (Bma | Bme);
      Cu ^= Emu;

      Abi ^= Di;
      Bsa = ROTL(Abi, 62);
      Ago ^= Do;
      Bse = ROTL(Ago, 55);
      Aku ^= Du;
      Bsi = ROTL(Aku, 39);
      Ama ^= Da;
      Bso = ROTL(Ama, 41);
      Ase ^= De;
      Bsu = ROTL(Ase, 2);
      Esa = Bsa ^ ((~Bse) & Bsi);
      Ca ^= Esa;
      Ese = (~Bse) ^ (Bsi | Bso);
      Ce ^= Ese;
      Esi = Bsi ^ (Bso & Bsu);
      Ci ^= Esi;
      Eso = Bso ^ (Bsu | Bsa);
      Co ^= Eso;
      Esu = Bsu ^ (Bsa & Bse);
      Cu ^= Esu;

      Da = Cu ^ ROTL(Ce, 1);
      De = Ca ^ ROTL(Ci, 1);
      Di = Ce ^ ROTL(Co, 1);
      Do = Ci ^ ROTL(Cu, 1);
      Du = Co ^ ROTL(Ca, 1);

      Eba ^= Da;
      Bba = Eba;
      Ege ^= De;
      Bbe = ROTL(Ege, 44);
      Eki ^= Di;
      Bbi = ROTL(Eki, 43);
      Emo ^= Do;
      Bbo = ROTL(Emo, 21);
      Esu ^= Du;
      Bbu = ROTL(Esu, 14);
      Aba = Bba ^ (Bbe | Bbi);
      Aba ^= ROUND_CONSTANTS[i + 1];
      Ca = Aba;
      Abe = Bbe ^ ((~Bbi) | Bbo);
      Ce = Abe;
      Abi = Bbi ^ (Bbo & Bbu);
      Ci = Abi;
      Abo = Bbo ^ (Bbu | Bba);
      Co = Abo;
      Abu = Bbu ^ (Bba & Bbe);
      Cu = Abu;

      Ebo ^= Do;
      Bga = ROTL(Ebo, 28);
      Egu ^= Du;
      Bge = ROTL(Egu, 20);
      Eka ^= Da;
      Bgi = ROTL(Eka, 3);
      Eme ^= De;
      Bgo = ROTL(Eme, 45);
      Esi ^= Di;
      Bgu = ROTL(Esi, 61);
      Aga = Bga ^ (Bge | Bgi);
      Ca ^= Aga;
      Age = Bge ^ (Bgi & Bgo);
      Ce ^= Age;
      Agi = Bgi ^ (Bgo | (~Bgu));
      Ci ^= Agi;
      Ago = Bgo ^ (Bgu | Bga);
      Co ^= Ago;
      Agu = Bgu ^ (Bga & Bge);
      Cu ^= Agu;

      Ebe ^= De;
      Bka = ROTL(Ebe, 1);
      Egi ^= Di;
      Bke = ROTL(Egi, 6);
      Eko ^= Do;
      Bki = ROTL(Eko, 25);
      Emu ^= Du;
      Bko = ROTL(Emu, 8);
      Esa ^= Da;
      Bku = ROTL(Esa, 18);
      Aka = Bka ^ (Bke | Bki);
      Ca ^= Aka;
      Ake = Bke ^ (Bki & Bko);
      Ce ^= Ake;
      Aki = Bki ^ ((~Bko) & Bku);
      Ci ^= Aki;
      Ako = (~Bko) ^ (Bku | Bka);
      Co ^= Ako;
      Aku = Bku ^ (Bka & Bke);
      Cu ^= Aku;

      Ebu ^= Du;
      Bma = ROTL(Ebu, 27);
      Ega ^= Da;
      Bme = ROTL(Ega, 36);
      Eke ^= De;
      Bmi = ROTL(Eke, 10);
      Emi ^= Di;
      Bmo = ROTL(Emi, 15);
      Eso ^= Do;
      Bmu = ROTL(Eso, 56);
      Ama = Bma ^ (Bme & Bmi);
      Ca ^= Ama;
      Ame = Bme ^ (Bmi | Bmo);
      Ce ^= Ame;
      Ami = Bmi ^ ((~Bmo) | Bmu);
      Ci ^= Ami;
      Amo = (~Bmo) ^ (Bmu & Bma);
      Co ^= Amo;
      Amu = Bmu ^ (Bma | Bme);
      Cu ^= Amu;

      Ebi ^= Di;
      Bsa = ROTL(Ebi, 62);
      Ego ^= Do;
      Bse = ROTL(Ego, 55);
      Eku ^= Du;
      Bsi = ROTL(Eku, 39);
      Ema ^= Da;
      Bso = ROTL(Ema, 41);
      Ese ^= De;
      Bsu = ROTL(Ese, 2);
      Asa = Bsa ^ ((~Bse) & Bsi);
      Ca ^= Asa;
      Ase = (~Bse) ^ (Bsi | Bso);
      Ce ^= Ase;
      Asi = Bsi ^ (Bso & Bsu);
      Ci ^= Asi;
      Aso = Bso ^ (Bsu | Bsa);
      Co ^= Aso;
      Asu = Bsu ^ (Bsa & Bse);
      Cu ^= Asu;
    }

    state_[0] = Aba;
    state_[1] = Abe;
    state_[2] = Abi;
    state_[3] = Abo;
    state_[4] = Abu;
    state_[5] = Aga;
    state_[6] = Age;
    state_[7] = Agi;
    state_[8] = Ago;
    state_[9] = Agu;
    state_[10] = Aka;
    state_[11] = Ake;
    state_[12] = Aki;
    state_[13] = Ako;
    state_[14] = Aku;
    state_[15] = Ama;
    state_[16] = Ame;
    state_[17] = Ami;
    state_[18] = Amo;
    state_[19] = Amu;
    state_[20] = Asa;
    state_[21] = Ase;
    state_[22] = Asi;
    state_[23] = Aso;
    state_[24] = Asu;
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
    state_[1] = ~state_[1];
    state_[2] = ~state_[2];
    state_[8] = ~state_[8];
    state_[12] = ~state_[12];

    if (digestLength_ == 28) {
      Util.spreadLongsToBytesLE(state_, 0, outTemp_, 0, digestLongLength_ + 1);

      System.arraycopy(outTemp_, 0, output, offset, digestLength_);
    } else {
      Util.spreadLongsToBytesLE(state_, 0, output, offset, digestLongLength_);
    }
  }

  @Override
  protected void engineReset() {
    super.engineReset();
    Util.zeroBlock(state_);

    state_[1] = state_[2] = state_[8] = state_[12] = state_[17] = state_[20] = ALL_ONE_LONG;
  }

}
