package com.debuggor;


import java.math.BigInteger;
import java.util.Random;

/**
 * @Author:yong.huang
 * @Date:2020-05-18 13:21
 */
public class Paillier {

    //选取两个较大的质数p与q，lambda是p-1与q-1的最小公倍数
    private BigInteger p, q, lambda;

    //n是p与q的乘积
    public BigInteger n;

    //n_square = n*n
    public BigInteger n_square;
    private BigInteger g;
    private int bitLength;

    public Paillier(int bitLengthVal, int certainty) {
        Key(bitLengthVal, certainty);
    }

    public Paillier() {
        Key(32, 64);
    }

    public void Key(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        //随机构造两个大素数，详情参见API，BigInteger的构造方法
        p = new BigInteger(bitLength / 2, certainty, new Random());
        q = new BigInteger(bitLength / 2, certainty, new Random());

        //n=p*q;
        n = p.multiply(q);

        //nsquare=n*n;
        n_square = n.multiply(n);
        g = new BigInteger("2");

        //求p-1与q-1的乘积除于p-1于q-1的最大公约数
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))
                .divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));

        //检测g是某满足要求
        if (g.modPow(lambda, n_square).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {
            System.out.println("g的选取不合适!");
            System.exit(1);
        }
    }

    //给定r的加密
    public BigInteger En(BigInteger m, BigInteger r) {
        return g.modPow(m, n_square).multiply(r.modPow(n, n_square)).mod(n_square);
    }

    //随机生成r的加密
    public BigInteger En(BigInteger m) {
        BigInteger r = new BigInteger(bitLength, new Random());
        return g.modPow(m, n_square).multiply(r.modPow(n, n_square)).mod(n_square);
    }

    //解密
    public BigInteger De(BigInteger c) {
        BigInteger u = g.modPow(lambda, n_square).subtract(BigInteger.ONE).divide(n).modInverse(n);
        return c.modPow(lambda, n_square).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
    }

    public static void main(String[] args) {
        Paillier paillier = new Paillier();
        //创建两个大整数m1,m2:
        BigInteger m1 = new BigInteger("20");
        BigInteger m2 = new BigInteger("60");
        System.out.println("原文是:");
        System.out.println(m1 + "和" + m2);

        //将m1,m2加密得到em1,em2:
        BigInteger em1 = paillier.En(m1);
        BigInteger em2 = paillier.En(m2);

        //加密后的结果
        System.out.println("m1加密结果:" + em1);
        System.out.println("m2加密结果:" + em2);

        //解密后的结果
        System.out.println("m1解密结果:" + paillier.De(em1));
        System.out.println("m2解密结果:" + paillier.De(em2).toString());

        /**
         * paillier性质
         * */
        //加法同态
        // m1+m2,求明文数值的和
        System.out.println("**************************求和********************");
        BigInteger sum_m1m2 = m1.add(m2).mod(paillier.n);
        System.out.println("明文数值的和 : " + sum_m1m2.toString());
        System.out.println("测试:" + m1.add(m2));

        // em1+em2，求密文数值的和
        BigInteger product_em1em2 = em1.multiply(em2).mod(paillier.n_square);
        System.out.println("密文和: " + product_em1em2.toString());
        System.out.println("密文和解密: " + paillier.De(product_em1em2).toString());


        // 数乘同态
        System.out.println("***************************数乘*********************");
        //做乘法，先将两个数相乘，然后对n求模
        BigInteger multiply_m1m2 = m1.multiply(m2).mod(paillier.n);
        System.out.println("两个大整数相乘: " + multiply_m1m2.toString());
        System.out.println("测试:" + m1.multiply(m2));

        //数乘，密文数，乘上某个明文数C的密文值等于=密文数的C次方对n平方求模
        BigInteger multiply_em1em2 = em1.modPow(m2, paillier.n_square);
        System.out.println("数乘密文值: " + multiply_em1em2.toString());
        System.out.println("数乘密文值解密: " + paillier.De(multiply_em1em2).toString());
    }

}
