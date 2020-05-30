package com.debuggor;

import org.bitcoinj.core.ECKey;
import org.junit.Test;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @Author:yong.huang
 * @Date:2020-05-30 12:53
 */
public class CommonTest {

    /**
     * 将私钥拆分成两个数 对每个数分别乘G的和
     * =私钥乘以G
     */
    @Test
    public void numberAddTest() {
        BigInteger num1 = BigInteger.valueOf(100);
        BigInteger num2 = BigInteger.valueOf(300);
        ECPoint ecPoint1 = ECKey.publicPointFromPrivate(num1);
        ECPoint ecPoint2 = ECKey.publicPointFromPrivate(num2);

        ECPoint add = ecPoint1.add(ecPoint2);
        System.out.println(add.getX());

        ECPoint sum = ECKey.publicPointFromPrivate(num1.add(num2));
        System.out.println(sum.getX());
    }

    @Test
    public void ecPointTest() {
        SecureRandom random = new SecureRandom();
        BigInteger secret = BigInteger.probablePrime(ECKey.CURVE.getN().bitLength(), random);
        ECPoint ecPoint = ECKey.publicPointFromPrivate(secret);

        BigInteger a = BigInteger.valueOf(1000);
        BigInteger b = secret.subtract(a);
        ECPoint point = ECKey.publicPointFromPrivate(BigInteger.ONE);
        ECPoint pointA = point.multiply(a);
        ECPoint pointB = point.multiply(b);
        ECPoint sum = pointA.add(pointB);

        System.out.println(ecPoint.equals(sum));
    }
}
