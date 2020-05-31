package com.debuggor;

import org.bitcoinj.core.ECKey;
import org.junit.Test;

import java.math.BigInteger;

/**
 * @Author:yong.huang
 * @Date:2020-05-31 16:51
 */
public class SignTest {

    /**
     * 私钥：d8ec31b7ef753ae680d76665eec9c8195ff0c43ec7ccf74a41f81681c0043554
     * 公钥：02a286ec06aec5463a83316ae7b8f76bf4175fd65b2210ef0ee5cb2254684edbd3
     * <p>
     * 由私钥片段恢复私钥
     */
    @Test
    public void test01() {
        BigInteger pri1 = new BigInteger("788571a21cd780dc3e7500882dfce2d042fe3ead5637850a906459b916145297", 16);
        BigInteger pri2 = new BigInteger("b4a9d59bd54f3646197c206d98559becb8bb61c637d43c6bd1b087984e37897a", 16);
        BigInteger pri3 = new BigInteger("abbcea79fd4e83c428e645702877495b1ee600b1e909d60f9fb593bd2bee9a84", 16);

        BigInteger add = pri1.add(pri2).add(pri3);
        System.out.println(add.mod(ECKey.CURVE.getN()).toString(16));
    }
}
