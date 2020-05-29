package com.debuggor.crypto.share;

import com.debuggor.crypto.paillier.KeyPairBuilder;
import com.debuggor.crypto.paillier.Paillier;
import com.debuggor.crypto.paillier.PrivateKey;
import com.debuggor.crypto.paillier.PublicKey;

import java.math.BigInteger;

/**
 * 解决问题：ab = a1 + b1
 * alice知道a，bob知道b，
 * 在不暴露a和b的情况下，求a1和b1，
 * 且alice只得到a1，bob只得到b1
 *
 * @Author:yong.huang
 * @Date:2020-05-30 01:24
 */
public class ShareProtocol {

    /**
     * alice [Ea(a),pka] ------> bob
     * alice <------------- bob  [Ea(ab-b1)]
     * alice: a1=Da(Ea(ab+b1))
     */

    /**
     * 第一步 alice加密a，将加密后的结果发送给bob
     *
     * @param publicKeyA
     * @param a
     * @return ca
     */
    public static BigInteger aliceInit(PublicKey publicKeyA, BigInteger a) {
        return publicKeyA.encrypt(a);
    }

    /**
     * 第二步 bob生成一个随机数b11，b1=-b11
     * b*Ea(a) + Ea(b11) = Ea(ab + b11)
     * 将结果发送给alice
     *
     * @param publicKeyA alice的公钥 会提前发送给bob
     * @param ca         alice加密的结果
     * @param b          bob的b
     * @param b1         bob的结果b1，bob随机生成的
     * @return cb
     */
    public static BigInteger bobAction(PublicKey publicKeyA, BigInteger ca, BigInteger b, BigInteger b1) {
        BigInteger bca = publicKeyA.homoMult(b, ca);

        BigInteger b11 = BigInteger.ZERO.subtract(b1);
        BigInteger cb11 = publicKeyA.encrypt(b11);

        BigInteger cha = publicKeyA.homoAdd(bca, cb11);
        return cha;
    }

    /**
     * alice解压bob发送的结果，即a1
     *
     * @param privateKeyA
     * @param cb          bob加上b的信息加密后，发送给alice的结果
     * @return a1
     */
    public static BigInteger aliceEnd(PrivateKey privateKeyA, BigInteger cb) {
        BigInteger a1 = privateKeyA.decrypt(cb);
        return a1;
    }


    public static void main(String[] args) {
        Paillier paillier = KeyPairBuilder.generateKeyPair(1);
        PublicKey publicKeyA = paillier.getPublicKey();
        PrivateKey privateKeyA = paillier.getPrivateKey();

        BigInteger a = BigInteger.valueOf(10);
        BigInteger b = BigInteger.valueOf(9);
        // 第一步
        BigInteger ca = aliceInit(publicKeyA, a);

        // 第二步 bob生成自己的b1
        BigInteger b1 = BigInteger.valueOf(-40);
        BigInteger cb = bobAction(publicKeyA, ca, b, b1);

        // 第三步 alice解密bob的结果
        BigInteger a1 = aliceEnd(privateKeyA, cb);
        // 10*9 = -40 + 130
        System.out.println(a1);

    }
}
