package com.debuggor.ecdsa.signing;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.debuggor.common.ReadWriteJson;
import com.debuggor.crypto.paillier.PrivateKey;
import com.debuggor.crypto.paillier.PublicKey;
import com.debuggor.crypto.share.ShareProtocol;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

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
        BigInteger m = calculateE(q, message);

        JSONArray jsonArray = readParams(threshold);
        BigInteger[] Xi = new BigInteger[threshold + 1];
        BigInteger[] ks = new BigInteger[threshold + 1];
        JSONObject[] PaillierSKs = new JSONObject[threshold + 1];
        for (int i = 0; i < threshold + 1; i++) {
            JSONObject param = (JSONObject) jsonArray.get(i);
            Xi[i] = param.getBigInteger("Xi");
            ks[i] = param.getBigInteger("ShareID");
            PaillierSKs[i] = param.getJSONObject("PaillierSK");
        }

        BigInteger tmp = BigInteger.ZERO;
        BigInteger[] Wi = new BigInteger[threshold + 1];
        for (int i = 0; i < threshold + 1; i++) {
            Wi[i] = calculateWi(i, Xi[i], ks);
            tmp = tmp.add(Wi[i]);
        }

        // 每个参与者生成两个随机数 k和gamma
        BigInteger[] Ki = new BigInteger[threshold + 1];
        BigInteger[] Gamma = new BigInteger[threshold + 1];
        ECPoint[] PointGamma = new ECPoint[threshold + 1];
        for (int i = 0; i < threshold + 1; i++) {
            BigInteger ki = BigInteger.probablePrime(q.bitLength(), new SecureRandom());
            BigInteger gammai = BigInteger.probablePrime(q.bitLength(), new SecureRandom());
            Ki[i] = ki;
            Gamma[i] = gammai;
            PointGamma[i] = ECKey.publicPointFromPrivate(gammai);
        }

        //=========== alice和bob交换数据 ===============
        // step1 alice将自己的数据加密发送给bob
        BigInteger[] Ca = new BigInteger[threshold + 1];
        for (int i = 0; i < threshold + 1; i++) {
            JSONObject alice = PaillierSKs[i];
            BigInteger N = alice.getBigInteger("N");
            PublicKey publicKeyA = new PublicKey(N);
            BigInteger k = Ki[i];
            BigInteger ca = ShareProtocol.aliceInit(publicKeyA, k);
            Ca[i] = ca;
        }

        // step2 bob将alice发送给的数据，加上自己的数据加密后给alice
        BigInteger[][] Betas = new BigInteger[threshold + 1][threshold + 1];
        BigInteger[][] V1 = new BigInteger[threshold + 1][threshold + 1];
        BigInteger[][] Cbwi = new BigInteger[threshold + 1][threshold + 1];
        BigInteger[][] Cbgamma = new BigInteger[threshold + 1][threshold + 1];
        for (int i = 0; i < threshold + 1; i++) {
            BigInteger gammaBob = Gamma[i];
            BigInteger wiBob = Wi[i];
            for (int j = 0; j < threshold + 1; j++) {
                if (i == j) {
                    continue;
                }
                JSONObject alice = PaillierSKs[j];
                BigInteger N = alice.getBigInteger("N");
                PublicKey publicKeyA = new PublicKey(N);
                BigInteger ca = Ca[j];

                BigInteger v1 = BigInteger.ZERO.subtract(BigInteger.probablePrime(q.bitLength(), new SecureRandom()));
                BigInteger cbwi = ShareProtocol.bobAction(publicKeyA, ca, wiBob, v1);
                V1[i][j] = v1;
                Cbwi[i][j] = cbwi;

                BigInteger beta = BigInteger.ZERO.subtract(BigInteger.probablePrime(q.bitLength(), new SecureRandom()));
                BigInteger cbgamma = ShareProtocol.bobAction(publicKeyA, ca, gammaBob, beta);
                Betas[i][j] = beta;
                Cbgamma[i][j] = cbgamma;
            }
        }

        // step3 alice加密bob加密的信息 得到自己需要的信息
        BigInteger[][] V2 = new BigInteger[threshold + 1][threshold + 1];
        BigInteger[][] Alphas = new BigInteger[threshold + 1][threshold + 1];
        for (int i = 0; i < threshold + 1; i++) {
            JSONObject alice = PaillierSKs[i];
            BigInteger phiN = alice.getBigInteger("PhiN");
            BigInteger lambdaN = alice.getBigInteger("LambdaN");
            BigInteger N = alice.getBigInteger("N");
            PublicKey publicKey = new PublicKey(N);
            PrivateKey privateKeyA = new PrivateKey(publicKey, lambdaN, phiN);

            for (int j = 0; j < threshold + 1; j++) {
                if (i == j) {
                    continue;
                }
                BigInteger v2 = ShareProtocol.aliceEnd(privateKeyA, Cbwi[j][i]);
                BigInteger alphaIj = ShareProtocol.aliceEnd(privateKeyA, Cbgamma[j][i]);
                V2[i][j] = v2;
                Alphas[i][j] = alphaIj;
            }
        }

        // 每个参与者从其他参与者那获取数据后 计算自己的
        BigInteger[] Theltas = new BigInteger[threshold + 1];
        BigInteger[] Sigmas = new BigInteger[threshold + 1];
        for (int i = 0; i < threshold + 1; i++) {
            Theltas[i] = Ki[i].multiply(Gamma[i]).mod(q);
            Sigmas[i] = Ki[i].multiply(Wi[i]).mod(q);
            for (int j = 0; j < threshold + 1; j++) {
                if (i == j) {
                    continue;
                }
                Theltas[i] = Theltas[i].add(Alphas[i][j].add(Betas[j][i])).mod(q);
                Sigmas[i] = Sigmas[i].add(V2[i][j].add(V1[j][i])).mod(q);
            }
        }

        // theta的负1次方
        BigInteger thetaInverse = BigInteger.ZERO;
        for (int i = 0; i < threshold + 1; i++) {
            thetaInverse = thetaInverse.add(Theltas[i]).mod(q);
        }
        thetaInverse = thetaInverse.modInverse(q);

        // 求得签名中的r
        ECPoint R = PointGamma[0];
        for (int i = 1; i < threshold + 1; i++) {
            R = R.add(PointGamma[i]);
        }
        R = R.multiply(thetaInverse);
        R = ECKey.compressPoint(R);
        BigInteger rx = R.getAffineXCoord().toBigInteger().mod(q);

        // 每个参与者签名
        BigInteger[] Signaturei = new BigInteger[threshold + 1];
        for (int i = 0; i < threshold + 1; i++) {
            BigInteger ki = Ki[i];
            BigInteger sigma = Sigmas[i];
            BigInteger si = ki.multiply(m).add(rx.multiply(sigma)).mod(q);
            Signaturei[i] = si;
        }

        // 签名已经完成， 把每个签名者的签名结果相加
        BigInteger s = BigInteger.ZERO;
        for (int i = 0; i < threshold + 1; i++) {
            s = s.add(Signaturei[i]).mod(q);
        }
        System.out.println("签名结果s: " + s.toString(16));
        System.out.println("签名结果r: " + rx.toString(16));

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
        Sha256Hash sha256Hash = Sha256Hash.twiceOf("Hello world!".getBytes());
        signing(2, sha256Hash.getBytes());

        /**
         * 私钥：a449b5df71dd21b07370a848b66b85137b31b46c43645dd8ad3a5b48b4a3fac0
         * 公钥：02b7844b6be8d0c0d86a1c0dbcaa7dec428ba9ae83aca993b3f37c13f02a80e128
         *
         * 签名结果s: 17c2fc0735d2c3addae0a3d74c909e8e1cd64d981462a474e0e1c7aa62fc23b9
         * 签名结果r: c1091c52da4baa91c90e71d18231c15e57ec8bd9d06edb59db3fa5910c3d9fc3
         */
        BigInteger pri = new BigInteger("a449b5df71dd21b07370a848b66b85137b31b46c43645dd8ad3a5b48b4a3fac0", 16);
        ECKey ecKey = ECKey.fromPrivate(pri);

        BigInteger s = new BigInteger("17c2fc0735d2c3addae0a3d74c909e8e1cd64d981462a474e0e1c7aa62fc23b9", 16);
        BigInteger r = new BigInteger("c1091c52da4baa91c90e71d18231c15e57ec8bd9d06edb59db3fa5910c3d9fc3", 16);
        ECKey.ECDSASignature sign = new ECKey.ECDSASignature(r, s);
        boolean verify = ecKey.verify(sha256Hash, sign);
        System.out.println(verify);
    }
}
