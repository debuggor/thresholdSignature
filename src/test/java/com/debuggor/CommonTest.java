package com.debuggor;

import org.bitcoinj.core.ECKey;
import org.junit.Test;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.custom.sec.SecP256K1FieldElement;
import org.spongycastle.math.ec.custom.sec.SecP256K1Point;

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

    @Test
    public void pointAddTest() {

        ECFieldElement x1 = new SecP256K1FieldElement(new BigInteger("45021377925733711715810236953605074273429545304805836921735933979352728890565",10));
        ECFieldElement y1 = new SecP256K1FieldElement(new BigInteger("26390808010398651568117294922753116165078485443867391015295665571631182394833",10));
        ECPoint ecPoint1 = new SecP256K1Point(ECKey.CURVE.getCurve(), x1, y1);

        ECFieldElement x2 = new SecP256K1FieldElement(new BigInteger("2117975946696719197142529799042979861807655407080430736665907517902342141956",10));
        ECFieldElement y2 = new SecP256K1FieldElement(new BigInteger("26561369122643691082149321013703254044756646805600032068804440801178307729365",10));
        ECPoint ecPoint2 = new SecP256K1Point(ECKey.CURVE.getCurve(), x2, y2);

        ECFieldElement x3 = new SecP256K1FieldElement(new BigInteger("6985233019778852573243885539040107226022388083061975759794812563952305925348",10));
        ECFieldElement y3 = new SecP256K1FieldElement(new BigInteger("75286012031132234634193493299719769525924812077767499284219746819157652051120",10));
        ECPoint ecPoint3 = new SecP256K1Point(ECKey.CURVE.getCurve(), x3, y3);

        ECFieldElement x4 = new SecP256K1FieldElement(new BigInteger("91325595183031692290959462012925898775099936859466119698659999383219306256034",10));
        ECFieldElement y4 = new SecP256K1FieldElement(new BigInteger("53679320682095686944554215751517239319788756690292341778506922043809481509106",10));
        ECPoint ecPoint4 = new SecP256K1Point(ECKey.CURVE.getCurve(), x4, y4);

        ECPoint sum = ecPoint1.add(ecPoint2).add(ecPoint3).add(ecPoint4);
        System.out.println(sum.getXCoord().toBigInteger());


    }
}
