package com.debuggor.crypto.vss;

import org.bitcoinj.core.ECKey;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @Author:yong.huang
 * @Date:2020-05-30 11:45
 */
public class FeldmanVss {

    Share[] shares;

    ECPoint[] vs;

    public FeldmanVss(Share[] shares, ECPoint[] vs) {
        this.shares = shares;
        this.vs = vs;
    }

    public Share[] getShares() {
        return shares;
    }

    public ECPoint[] getVs() {
        return vs;
    }

    /**
     * @param threshold
     * @param secret    第i个参与者的密钥
     * @param indexes   所有参与者的id列表
     * @return
     */
    public static FeldmanVss create(int threshold, BigInteger secret, BigInteger[] indexes) {
        if (secret == null || indexes.length == 0) {
            throw new IllegalArgumentException("secret or indexes is error argument");
        }
        if (threshold < 1) {
            throw new IllegalArgumentException("vss threshold < 1");
        }
        int num = indexes.length;
        if (num < threshold) {
            throw new IllegalArgumentException("threshold is big than n");
        }
        BigInteger[] poly = samplePolynomial(threshold, secret);
        poly[0] = secret;
        // becomes sigma*G in v
        ECPoint[] v = new ECPoint[poly.length];
        for (int i = 0; i < poly.length; i++) {
            BigInteger ai = poly[i];
            ECPoint ecPoint = ECKey.publicPointFromPrivate(ai);
            v[i] = ecPoint;
        }

        Share[] shares = new Share[num];
        for (int i = 0; i < num; i++) {
            if (indexes[i].compareTo(BigInteger.ZERO) == 0) {
                throw new IllegalArgumentException("party index should not be 0");
            }
            BigInteger share = evaluatePolynomial(threshold, poly, indexes[i]);
            shares[i] = new Share(threshold, indexes[i], share);
        }
        return new FeldmanVss(shares, v);
    }


    public static BigInteger evaluatePolynomial(int threshold, BigInteger[] v, BigInteger id) {
        BigInteger q = ECKey.CURVE.getN();
        BigInteger result = BigInteger.ZERO;
        BigInteger X = BigInteger.ONE;
        for (int i = 1; i <= threshold; i++) {
            BigInteger ai = v[i];
            X = X.multiply(id).mod(q);
            BigInteger aiXi = ai.multiply(X);
            result = result.add(aiXi);
        }
        return result;
    }


    /**
     * @param threshold
     * @param secret
     * @return
     */
    public static BigInteger[] samplePolynomial(int threshold, BigInteger secret) {
        BigInteger q = ECKey.CURVE.getN();
        BigInteger[] v = new BigInteger[threshold + 1];
        v[0] = secret;
        for (int i = 1; i <= threshold; i++) {
            SecureRandom random = new SecureRandom();
            BigInteger ai = BigInteger.probablePrime(q.bitLength(), random);
            v[i] = ai;
        }
        return v;
    }

}
