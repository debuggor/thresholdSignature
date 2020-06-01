package com.debuggor.ecdsa.resharing;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.debuggor.common.ECPointUtils;
import com.debuggor.common.ReadWriteJson;
import com.debuggor.crypto.paillier.KeyPairBuilder;
import com.debuggor.crypto.paillier.Paillier;
import com.debuggor.crypto.vss.FeldmanVss;
import com.debuggor.crypto.vss.Share;
import com.debuggor.ecdsa.signing.Signing;
import org.bitcoinj.core.ECKey;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;


/**
 * @Author:yong.huang
 * @Date:2020-06-01 22:00
 */
public class Resharing {

    /**
     * 1、恢复每个参与者的私钥片段
     * 2、拆分每个人的私钥片段
     */
    public static void resharing(int newThreshold, int n) {
        BigInteger q = ECKey.CURVE.getN();

        JSONArray params = readParams(n);
        BigInteger[] Xi = new BigInteger[n];
        BigInteger[] ks = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            JSONObject param = (JSONObject) params.get(i);
            Xi[i] = param.getBigInteger("Xi");
            ks[i] = param.getBigInteger("ShareID");
        }

        BigInteger tmp = BigInteger.ZERO;
        BigInteger[] Wi = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            Wi[i] = Signing.calculateWi(i, Xi[i], ks);
            tmp = tmp.add(Wi[i]);
        }

        System.out.println("私钥：" + tmp.toString(16));


        // 重新为每个参与者生成新的编号 和 同态加密的信息
        Paillier[] pailliers = new Paillier[n];
        BigInteger[] newIds = new BigInteger[n];
        BigInteger id = BigInteger.probablePrime(q.bitLength(), new SecureRandom());
        for (int i = 0; i < n; i++) {
            newIds[i] = id;
            id = id.add(BigInteger.ONE);
            pailliers[i] = KeyPairBuilder.generateKeyPair(1);
        }

        // 每个参与者生成自己的
        ECPoint[][] vs = new ECPoint[n][newThreshold+1];
        Share[][] shares = new Share[n][n];
        for (int i = 0; i < n; i++) {
            FeldmanVss vss = FeldmanVss.create(newThreshold, Wi[i], newIds);
            ECPoint[] vsi = vss.getVs();
            Share[] sharesi = vss.getShares();
            vs[i] = vsi;
            shares[i] = sharesi;
        }

        // 各条直线*G的参数 相加的结果
        ECPoint[] Vc = new ECPoint[newThreshold + 1];
        for (int j = 0; j <= newThreshold; j++) {
            ECPoint[] vci = vs[0];
            ECPoint vcij = vci[j];
            for (int i = 1; i < n; i++) {
                vci = vs[i];
                vcij = vcij.add(vci[j]);
            }
            Vc[j] = vcij;
        }

        // 参与者的公钥 （X，Y）
        ECPoint[] bigXj = new ECPoint[n];
        for (int i = 0; i < n; i++) {
            BigInteger idi = newIds[i];
            ECPoint BigXj = Vc[0];
            BigInteger z = BigInteger.ONE;
            for (int j = 1; j <= newThreshold; j++) {
                z = z.multiply(idi).mod(q);
                BigXj = BigXj.add(Vc[j].multiply(z));
            }
            bigXj[i] = ECKey.compressPoint(BigXj);
        }
        // 公钥
        ECPoint ecdsaPubKey = ECKey.compressPoint(Vc[0]);

        // 计算xi  (i,xi)曲线上的一点
        BigInteger[] Xis = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            Xis[i] = BigInteger.ZERO;
        }
        for (int i = 0; i < n; i++) {
            Share[] sharei = shares[i];
            for (int j = 0; j < n; j++) {
                Share sharej = sharei[j];
                Xis[j] = Xis[j].add(sharej.getShare());
            }
        }


        // =============================保存数据=============================
        JSONArray Ks = new JSONArray();
        JSONArray PaillierPKs = new JSONArray();
        for (int i = 0; i < n; i++) {
            Ks.add(i, newIds[i]);
            PaillierPKs.add(i, pailliers[i].getPublicKey().toJson());
        }
        // 各个参与者保存信息
        for (int i = 0; i < n; i++) {
            String filePath = "test/test05/ecdsa_data_" + i + ".json";
            JSONObject object = new JSONObject();
            object.put("PaillierSK", pailliers[i].getPrivateKey().toJson());
            object.put("ShareID", newIds[i]);
            object.put("Xi", Xis[i]);
            object.put("Ks", Ks);
            object.put("BigXj", ECPointUtils.ecPointsToJson(bigXj));
            object.put("PaillierPKs", PaillierPKs);
            object.put("ECDSAPub", ECPointUtils.ecPointToJson(ecdsaPubKey));

            ReadWriteJson.writeJsonFile(filePath, object.toString());
        }

        BigInteger pri = BigInteger.ZERO;
        for (int i = 0; i < n; i++) {
            pri = pri.add(Wi[i]).mod(q);
        }
        System.out.println("私钥：" + pri.toString(16));
        System.out.println("公钥：" + Hex.toHexString(ecdsaPubKey.getEncoded(true)));

    }

    private static JSONArray readParams(int n) {
        JSONArray result = new JSONArray();
        for (int i = 0; i < n; i++) {
            String filePath = "test/test04/ecdsa_data_" + i + ".json";
            String param = ReadWriteJson.readJsonFile(filePath);
            result.add(i, JSONObject.parseObject(param));
        }
        return result;
    }

    public static void main(String[] args) {
        resharing(1, 3);
    }

}
