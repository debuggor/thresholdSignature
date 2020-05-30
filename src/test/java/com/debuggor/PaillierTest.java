package com.debuggor;

import com.debuggor.crypto.paillier.KeyPairBuilder;
import com.debuggor.crypto.paillier.Paillier;
import com.debuggor.crypto.paillier.PrivateKey;
import com.debuggor.crypto.paillier.PublicKey;
import org.junit.Test;

import java.math.BigInteger;

/**
 * @Author:yong.huang
 * @Date:2020-05-30 00:16
 */
public class PaillierTest {

    @Test
    public void testPaillier() {
        Paillier paillier = KeyPairBuilder.generateKeyPair(1);

        PublicKey publicKey = paillier.getPublicKey();
        PrivateKey privateKey = paillier.getPrivateKey();

        BigInteger m = BigInteger.valueOf(123456789);
        BigInteger c = publicKey.encrypt(m);
        BigInteger m1 = privateKey.decrypt(c);

        System.out.println(m);
        System.out.println(c);
        System.out.println(m1);
    }


    @Test
    public void testHomoMul() {
        Paillier paillier = KeyPairBuilder.generateKeyPair(1);
        PublicKey publicKey = paillier.getPublicKey();
        PrivateKey privateKey = paillier.getPrivateKey();

        BigInteger three = BigInteger.valueOf(3);
        BigInteger six = BigInteger.valueOf(6);

        BigInteger c3 = publicKey.encrypt(three);
        BigInteger cm = publicKey.homoMult(six, c3);
        BigInteger dm = privateKey.decrypt(cm);

        System.out.println(dm);
    }

    @Test
    public void testHomoAdd(){
        Paillier paillier = KeyPairBuilder.generateKeyPair(1);
        PublicKey publicKey = paillier.getPublicKey();
        PrivateKey privateKey = paillier.getPrivateKey();

        BigInteger three = BigInteger.valueOf(300);
        BigInteger six = BigInteger.valueOf(654);

        BigInteger c3 = publicKey.encrypt(three);
        BigInteger c6 = publicKey.encrypt(six);
        BigInteger ca = publicKey.homoAdd(c3, c6);
        BigInteger dm = privateKey.decrypt(ca);

        System.out.println(dm);
    }

}
