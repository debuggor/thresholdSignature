package com.debuggor.crypto.vss;

import org.bitcoinj.core.ECKey;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * @Author:yong.huang
 * @Date:2020-05-30 11:46
 */
public class Share {
    /**
     * 阀值
     */
    private int threshold;
    /**
     * 参与者编号 id
     */
    private BigInteger id;
    /**
     * Sigma i
     * 要共享的内容
     */
    private BigInteger share;

    public Share(int threshold, BigInteger id, BigInteger share) {
        this.threshold = threshold;
        this.id = id;
        this.share = share;
    }

    public int getThreshold() {
        return threshold;
    }

    public BigInteger getId() {
        return id;
    }

    public BigInteger getShare() {
        return share;
    }


    public boolean verify(int threshold, ECPoint[] vs) {
        if (this.threshold != threshold || vs.length == 0) {
            return false;
        }
        BigInteger q = ECKey.CURVE.getN();
        ECPoint v = vs[0];
        BigInteger t = BigInteger.ONE;

        for (int j = 1; j <= threshold; j++) {
            t = t.multiply(this.id).mod(q);
            ECPoint vjt = vs[j].multiply(t);
            v = v.add(vjt);
        }

        ECPoint sigmaGi = ECKey.publicPointFromPrivate(share);
        return sigmaGi.equals(v);
    }
}
