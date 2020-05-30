package com.debuggor.crypto.paillier;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @Author:yong.huang
 * @Date:2020-05-29 22:58
 */
public class KeyPairBuilder {

    private static int bits = 2048;

    public static Paillier generateKeyPair(int certainty) {
        SecureRandom rng = new SecureRandom();

        BigInteger p, q;
        int length = bits / 2;
        if (certainty > 0) {
            p = new BigInteger(length, certainty, rng);
            q = new BigInteger(length, certainty, rng);
        } else {
            p = BigInteger.probablePrime(length, rng);
            q = BigInteger.probablePrime(length, rng);
        }

        BigInteger n = p.multiply(q);
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger qMinusOne = q.subtract(BigInteger.ONE);
        BigInteger phiN = pMinusOne.multiply(qMinusOne);
        BigInteger gcd = pMinusOne.gcd(qMinusOne);
        BigInteger lambdaN = phiN.divide(gcd);

        PublicKey publicKey = new PublicKey(n);
        PrivateKey privateKey = new PrivateKey(publicKey, lambdaN, phiN);
        return new Paillier(privateKey, publicKey);
    }


}
