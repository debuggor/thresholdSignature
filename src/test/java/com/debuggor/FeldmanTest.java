package com.debuggor;

import com.debuggor.crypto.vss.FeldmanVss;
import com.debuggor.crypto.vss.Share;
import org.bitcoinj.core.ECKey;
import org.junit.Test;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @Author:yong.huang
 * @Date:2020-05-30 14:19
 */
public class FeldmanTest {

    @Test
    public void verifyTest() {
        int num = 5;
        int threshold = 3;

        SecureRandom random = new SecureRandom();
        BigInteger secret = BigInteger.probablePrime(ECKey.CURVE.getN().bitLength(), random);

        BigInteger[] ids = new BigInteger[num];
        for (int i = 0; i < num; i++) {
            random = new SecureRandom();
            ids[i] = BigInteger.probablePrime(ECKey.CURVE.getN().bitLength(), random);
        }

        FeldmanVss feldmanVss = FeldmanVss.create(threshold, secret, ids);
        Share[] shares = feldmanVss.getShares();
        ECPoint[] vs = feldmanVss.getVs();

        for (int i = 0; i < num; i++) {
            boolean verify = shares[i].verify(threshold, vs);
            System.out.println(verify);
        }
    }

    /**
     * 恢复secret
     */
    @Test
    public void reconstructTest() {
        int num = 5;
        int threshold = 3;

        SecureRandom random = new SecureRandom();
        BigInteger secret = BigInteger.probablePrime(ECKey.CURVE.getN().bitLength(), random);

        BigInteger[] ids = new BigInteger[num];
        for (int i = 0; i < num; i++) {
            random = new SecureRandom();
            ids[i] = BigInteger.probablePrime(ECKey.CURVE.getN().bitLength(), random);
        }

        FeldmanVss feldmanVss = FeldmanVss.create(threshold, secret, ids);
        Share[] shares = feldmanVss.getShares();

        Share[] ss = new Share[threshold + 1];
        System.arraycopy(shares, 0, ss, 0, threshold + 1);
        BigInteger secret1 = FeldmanVss.reConstruct(ss);

        System.out.println(secret.equals(secret1));
    }

}
