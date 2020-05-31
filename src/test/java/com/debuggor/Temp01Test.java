package com.debuggor;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.junit.Test;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.custom.sec.SecP256K1FieldElement;
import org.spongycastle.math.ec.custom.sec.SecP256K1Point;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;

/**
 * @Author:yong.huang
 * @Date:2020-05-30 11:55
 */
public class Temp01Test {

    /**
     * 30963515218297574829581293481859109883103069123989182152796719936132055988859
     * <p>
     * <p>
     * 22941885473264038441196179400607627819084347264272828288334555450118652308047,
     * 50521704546093776115179469078506483082914287302267975579243071943278197852929
     */
    @Test
    public void test01() {
        BigInteger pri = new BigInteger("30963515218297574829581293481859109883103069123989182152796719936132055988859", 10);

        ECPoint ecPoint = ECKey.publicPointFromPrivate(pri);

        System.out.println(ecPoint.getXCoord().toBigInteger());
        System.out.println(ecPoint.getYCoord().toBigInteger());
        String pub = Hex.toHexString(ecPoint.getEncoded(true));
        System.out.println(pub);

        BigInteger bigInteger = new BigInteger("22941885473264038441196179400607627819084347264272828288334555450118652308047", 10);
        System.out.println(bigInteger.toString(16));
    }

    /**
     * sk:02918cf076c2aa43919bf5c1cfd32bd5c0c4eba71169d8aa8192115d35f7c06503
     * pk:9c0f254fe17c4144ad3ab5b4a3e23dc3474057161dc354b81e69e4d010cf79e2
     * <p>
     * <p>
     * 70587564603158231455708687489440188327857144316529305416380210506769374345698,
     * 42704705153112392692344644222385386484191154034555108804513709978826700387587
     */
    @Test
    public void test02() {
        BigInteger pri = new BigInteger("02918cf076c2aa43919bf5c1cfd32bd5c0c4eba71169d8aa8192115d35f7c06503", 16);
        ECPoint ecPoint = ECKey.publicPointFromPrivate(pri);
        System.out.println(ecPoint.getXCoord().toBigInteger());
        System.out.println(ecPoint.getYCoord().toBigInteger());
        String pub = Hex.toHexString(ecPoint.getEncoded(true));
        System.out.println(pub);

        BigInteger pp = new BigInteger("70587564603158231455708687489440188327857144316529305416380210506769374345698", 10);
        System.out.println(pp.toString(16));

    }


    /**
     * 0 796c2d465b9e1fe8d913a6818df4c136d3e81d57bec511456e80f7f7231b62a9
     * 1 4b5b21e9dc1a12506f818990a7cdfed18431a005a02d3ca72fc928cbf4841e2d
     * 2 33641f3a5c4b85b52342afac24c38b015b1d844f15e6dca26901671a69c295b4
     * 3 6a671a329b725fbef378636bc5168374493e5409b1e06f4ed8b71c1f381e106a
     * <p>
     * <p>
     * sk:016292889d2f7617ad5f50432a1f9cce7dfc7595b626b999dde002a3fcb98026f4
     * pk:2af3a550a94d962ecb0258dea0eda697d1e151c61ac8819b1f3569d94305b177
     */
    @Test
    public void test03() {
        BigInteger pri1 = new BigInteger("796c2d465b9e1fe8d913a6818df4c136d3e81d57bec511456e80f7f7231b62a9", 16);
        BigInteger pri2 = new BigInteger("4b5b21e9dc1a12506f818990a7cdfed18431a005a02d3ca72fc928cbf4841e2d", 16);
        BigInteger pri3 = new BigInteger("33641f3a5c4b85b52342afac24c38b015b1d844f15e6dca26901671a69c295b4", 16);
        BigInteger pri4 = new BigInteger("6a671a329b725fbef378636bc5168374493e5409b1e06f4ed8b71c1f381e106a", 16);

        BigInteger add = pri1.add(pri2).add(pri3).add(pri4);//.mod(ECKey.CURVE.getN());
        System.out.println(add.toString(16));
    }


    /**
     * 问题：将私钥拆分 子私钥*G的和 ！=  私钥*G
     * 没问题 相等 ✅
     * <p>
     * X Y 坐标的值不一样，但最后得到的压缩公钥一样
     */
    @Test
    public void test04() {
        BigInteger pri1 = new BigInteger("796c2d465b9e1fe8d913a6818df4c136d3e81d57bec511456e80f7f7231b62a9", 16);
        BigInteger pri2 = new BigInteger("4b5b21e9dc1a12506f818990a7cdfed18431a005a02d3ca72fc928cbf4841e2d", 16);
        BigInteger pri3 = new BigInteger("33641f3a5c4b85b52342afac24c38b015b1d844f15e6dca26901671a69c295b4", 16);
        BigInteger pri4 = new BigInteger("6a671a329b725fbef378636bc5168374493e5409b1e06f4ed8b71c1f381e106a", 16);

        ECPoint ecPoint1 = ECKey.publicPointFromPrivate(pri1);
        ECPoint ecPoint2 = ECKey.publicPointFromPrivate(pri2);
        ECPoint ecPoint3 = ECKey.publicPointFromPrivate(pri3);
        ECPoint ecPoint4 = ECKey.publicPointFromPrivate(pri4);

        ECPoint add = ecPoint1.add(ecPoint2).add(ecPoint3).add(ecPoint4);
        // add = ECKey.compressPoint(add);
        System.out.println(add.getXCoord().toBigInteger());
        System.out.println(add.getYCoord().toBigInteger());
        String pub1 = Hex.toHexString(add.getEncoded(true));
        System.out.println(pub1);

        System.out.println("===================");
        BigInteger pri = pri1.add(pri2).add(pri3).add(pri4);//.mod(ECKey.CURVE.getN());
        ECPoint ecPoint = ECKey.publicPointFromPrivate(pri);
        System.out.println(ecPoint.getXCoord().toBigInteger());
        System.out.println(ecPoint.getYCoord().toBigInteger());
        String pub = Hex.toHexString(ecPoint.getEncoded(true));
        System.out.println(pub);

        System.out.println("====================");
        ECPoint point = ECKey.compressPoint(ecPoint);
        System.out.println(point.getXCoord().toBigInteger());

    }

    /**
     * 由点得到压缩公钥
     * <p>
     * 63464842321549028104593741931401395291219779908808861285873486625278935908818
     * 90616146736488935619747544460719722648245133709271273181142341137830619944065
     * 032af3a550a94d962ecb0258dea0eda697d1e151c61ac8819b1f3569d94305b177
     */
    @Test
    public void test05() {
        BigInteger pri = new BigInteger("16292889d2f7617ad5f50432a1f9cce7dfc7595b626b999dde002a3fcb98026f4", 16);
        ECKey ecKey = ECKey.fromPrivate(pri.mod(ECKey.CURVE.getN()));
        System.out.println(ecKey.getPublicKeyAsHex());

        Sha256Hash sha256Hash = Sha256Hash.twiceOf("Hello world!".getBytes());
        ECKey.ECDSASignature sign = ecKey.sign(sha256Hash);

        ECKey ecKey1 = ECKey.fromPublicOnly(Hex.decode(ecKey.getPublicKeyAsHex()));
        boolean verify = ecKey1.verify(sha256Hash, sign);
        System.out.println(verify);

        ECPoint point = ecKey.getPubKeyPoint();
        System.out.println(point.getXCoord().toBigInteger());
        System.out.println(point.getYCoord().toBigInteger());
        String pub = Hex.toHexString(point.getEncoded(true));
        System.out.println(pub);

        System.out.println(point.getXCoord().toBigInteger().toString(16));
    }

    /**
     * 由点得到压缩公钥
     * <p>
     * <p>
     * X Y 公钥 私钥
     * 19427624440010984107990153102091150856699532277856516076262623001629270847863,
     * 43603320305579634220861617348616252096469809901139100494252573102937765173787
     * 032af3a550a94d962ecb0258dea0eda697d1e151c61ac8819b1f3569d94305b177
     * 6292889d2f7617ad5f50432a1f9cce7f41c6b8cf7770f9a22030456fe949e5b3
     */
    @Test
    public void test06() {
        BigInteger x = new BigInteger("19427624440010984107990153102091150856699532277856516076262623001629270847863", 10);
        BigInteger y = new BigInteger("43603320305579634220861617348616252096469809901139100494252573102937765173787", 10);
        ECFieldElement X = new SecP256K1FieldElement(x);
        ECFieldElement Y = new SecP256K1FieldElement(y);
        ECPoint point = new SecP256K1Point(ECKey.CURVE.getCurve(), X, Y);
        System.out.println(Hex.toHexString(point.getEncoded(true)));

        BigInteger pri = new BigInteger("6292889d2f7617ad5f50432a1f9cce7f41c6b8cf7770f9a22030456fe949e5b3", 16);
        ECKey ecKey = ECKey.fromPrivate(pri);
        System.out.println(ecKey.getPublicKeyAsHex());

    }
}
