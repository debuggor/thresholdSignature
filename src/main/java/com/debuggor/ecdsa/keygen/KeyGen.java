package com.debuggor.ecdsa.keygen;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.debuggor.common.ECPointUtils;
import com.debuggor.common.ReadWriteJson;
import com.debuggor.crypto.paillier.KeyPairBuilder;
import com.debuggor.crypto.paillier.Paillier;
import com.debuggor.crypto.vss.FeldmanVss;
import com.debuggor.crypto.vss.Share;
import org.bitcoinj.core.ECKey;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;


/**
 * @Author:yong.huang
 * @Date:2020-05-30 16:34
 */
public class KeyGen {

    /**
     * 生成t-n门限签名的参数，并且聚合得到总的私钥
     *
     * @param threshold
     * @param n
     */
    public static void keygen(int threshold, int n) {
        BigInteger q = ECKey.CURVE.getN();

        // 每个参与者生成自己的密钥ui和编号id,paillier
        Paillier[] pailliers = new Paillier[n];
        BigInteger[] uis = new BigInteger[n];
        BigInteger[] ids = new BigInteger[n];
        BigInteger id = BigInteger.probablePrime(q.bitLength(), new SecureRandom());
        for (int i = 0; i < n; i++) {
            BigInteger ui = BigInteger.probablePrime(q.bitLength(), new SecureRandom());
            uis[i] = ui;
            ids[i] = id;
            id = id.add(BigInteger.ONE);
            pailliers[i] = KeyPairBuilder.generateKeyPair(1);
        }

        // 每个参与者生成自己的
        ECPoint[][] vs = new ECPoint[n][threshold + 1];
        Share[][] shares = new Share[n][threshold + 1];
        for (int i = 0; i < n; i++) {
            FeldmanVss vss = FeldmanVss.create(threshold, uis[i], ids);
            ECPoint[] vsi = vss.getVs();
            Share[] sharesi = vss.getShares();
            vs[i] = vsi;
            shares[i] = sharesi;
        }

        // 各条直线*G的参数 相加的结果
        ECPoint[] Vc = new ECPoint[threshold + 1];
        for (int j = 0; j <= threshold; j++) {
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
            BigInteger idi = ids[i];
            ECPoint BigXj = Vc[0];
            BigInteger z = BigInteger.ONE;
            for (int j = 1; j <= threshold; j++) {
                z = z.multiply(idi).mod(q);
                BigXj = BigXj.add(Vc[j].multiply(z));
            }
            bigXj[i] = BigXj;
        }
        // 公钥
        ECPoint ecdsaPubKey = Vc[0];

        // 计算xi  (i,xi)曲线上的一点
        BigInteger[] Xis = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            Share[] sharei = shares[i];
            BigInteger xi = sharei[i].getShare();
            for (int j = 0; j < n; j++) {
                if (i == j) {
                    continue;
                }
                Share sharej = sharei[j];
                xi = xi.add(sharej.getShare());
            }
            Xis[i] = xi.mod(q);
        }


        // =============================保存数据=============================
        JSONArray Ks = new JSONArray();
        JSONArray PaillierPKs = new JSONArray();
        for (int i = 0; i < n; i++) {
            Ks.add(i, ids[i]);
            PaillierPKs.add(i, pailliers[i].getPublicKey().toJson());
        }
        // 各个参与者保存信息
        for (int i = 0; i < n; i++) {
            String filePath = "test/test02/ecdsa_data_" + i + ".json";
            JSONObject object = new JSONObject();
            object.put("PaillierSK", pailliers[i].getPrivateKey().toJson());
            object.put("ShareID", ids[i]);
            object.put("Xi", Xis[i]);
            object.put("Ks", Ks);
            object.put("BigXj", ECPointUtils.ecPointsToJson(bigXj));
            object.put("PaillierPKs", PaillierPKs);
            object.put("ECDSAPub", ECPointUtils.ecPointToJson(ecdsaPubKey));

            ReadWriteJson.writeJsonFile(filePath, object.toString());
        }
    }

    public static void main(String[] args) {
        keygen(2, 4);
    }

}
