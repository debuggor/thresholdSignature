package com.debuggor.ecdsa.signing;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.debuggor.common.ReadWriteJson;
import org.bitcoinj.core.ECKey;

import java.math.BigInteger;

/**
 * @Author:yong.huang
 * @Date:2020-05-31 15:32
 */
public class Signing {
    /**
     * 1、求得参与签名的参与者的ui
     * 2、求r，交换信息较多
     */
    public static void signing(int threshold, byte[] message) {
        BigInteger q = ECKey.CURVE.getN();
     //   BigInteger m = calculateE(q, message);

        JSONArray jsonArray = readParams(threshold);
        BigInteger[] Xi = new BigInteger[threshold + 1];
        BigInteger[] ks = new BigInteger[threshold + 1];
        // BigInteger[] Xi = new BigInteger[threshold+1];
        for (int i = 0; i < threshold + 1; i++) {
            JSONObject param = (JSONObject) jsonArray.get(i);
            Xi[i] = param.getBigInteger("Xi");
            ks[i] = param.getBigInteger("ShareID");

        }

        BigInteger tmp = BigInteger.ZERO;
        BigInteger[] Wi = new BigInteger[threshold + 1];
        for (int i = 0; i < threshold + 1; i++) {
            Wi[i] = calculateWi(i, Xi[i], ks);
            tmp = tmp.add(Wi[i]);
            System.out.println(Wi[i].toString(16));
        }
        System.out.println("===========================");
        System.out.println(tmp.toString(16));
        ECKey ecKey = ECKey.fromPrivate(tmp.mod(q));
        System.out.println(ecKey.getPrivateKeyAsHex());
        System.out.println(ecKey.getPublicKeyAsHex());

    }


    public static BigInteger calculateWi(int i, BigInteger xi, BigInteger[] ks) {
        BigInteger q = ECKey.CURVE.getN();
        BigInteger wi = xi;
        for (int j = 0; j < ks.length; j++) {
            if (i == j) {
                continue;
            }
            BigInteger modInverse = ks[j].subtract(ks[i]).modInverse(q);
            BigInteger coef = ks[j].multiply(modInverse).mod(q);
            wi = wi.multiply(coef).mod(q);
        }
        return wi;
    }

    /**
     * 读取前面threshold+1的配置
     *
     * @param threshold
     * @return
     */
    private static JSONArray readParams(int threshold) {
        JSONArray result = new JSONArray();
        for (int i = 0; i < threshold + 1; i++) {
            String filePath = "test/test01/ecdsa_data_" + i + ".json";
            String param = ReadWriteJson.readJsonFile(filePath);
            result.add(i, JSONObject.parseObject(param));
        }
        return result;
    }

    /**
     * 将messgae转为BigInteger
     *
     * @param n
     * @param message
     * @return
     */
    private static BigInteger calculateE(BigInteger n, byte[] message) {
        int log2n = n.bitLength();
        int messageBitLength = message.length * 8;
        BigInteger e = new BigInteger(1, message);
        if (log2n < messageBitLength) {
            e = e.shiftRight(messageBitLength - log2n);
        }
        return e;
    }

    public static void main(String[] args) {
        signing(2, null);

        ECKey ecKey = new ECKey();
        //  ecKey.sign()
    }
}
