package com.debuggor;

import com.debuggor.crypto.vss.FeldmanVss;
import com.debuggor.crypto.vss.Share;
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
        // BigInteger secret = BigInteger.probablePrime(ECKey.CURVE.getN().bitLength(), random);
        BigInteger secret = BigInteger.valueOf(10);

        BigInteger[] ids = new BigInteger[num];
        for (int i = 0; i < num; i++) {
            random = new SecureRandom();
            //  ids[i] = BigInteger.probablePrime(ECKey.CURVE.getN().bitLength(), random);
            ids[i] = BigInteger.valueOf(i + 1);
        }

        FeldmanVss feldmanVss = FeldmanVss.create(threshold, secret, ids);
        Share[] shares = feldmanVss.getShares();
        ECPoint[] vs = feldmanVss.getVs();

        for (int i = 0; i < num; i++) {
            boolean verify = shares[i].verify(threshold, vs);
            System.out.println(verify);
        }
    }




}
