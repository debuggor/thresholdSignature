package com.debuggor.crypto.paillier;

import com.alibaba.fastjson.JSONObject;

import java.math.BigInteger;

/**
 * @Author:yong.huang
 * @Date:2020-05-29 22:43
 */
public class PrivateKey {

    private PublicKey publicKey;
    //  lcm(p-1, q-1)
    private BigInteger lambdaN;
    // (p-1) * (q-1)
    private BigInteger phiN;

    public PrivateKey(PublicKey publicKey, BigInteger lambdaN, BigInteger phiN) {
        this.publicKey = publicKey;
        this.lambdaN = lambdaN;
        this.phiN = phiN;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public BigInteger getLambdaN() {
        return lambdaN;
    }

    public BigInteger getPhiN() {
        return phiN;
    }

    public JSONObject toJson() {
        JSONObject object = new JSONObject();
        object.put("N", publicKey.getN());
        object.put("LambdaN", lambdaN);
        object.put("PhiN", phiN);
        return object;
    }

    /**
     * func (privateKey *PrivateKey) Decrypt(c *big.Int) (m *big.Int, err error) {
     * N2 := privateKey.NSquare()
     * if c.Cmp(zero) == -1 || c.Cmp(N2) != -1 { // c < 0 || c >= N2 ?
     * return nil, ErrMessageTooLong
     * }
     * // 1. L(u) = (c^LambdaN-1 mod N2) / N
     * Lc := L(new(big.Int).Exp(c, privateKey.LambdaN, N2), privateKey.N)
     * // 2. L(u) = (Gamma^LambdaN-1 mod N2) / N
     * Lg := L(new(big.Int).Exp(privateKey.Gamma(), privateKey.LambdaN, N2), privateKey.N)
     * // 3. (1) * modInv(2) mod N
     * inv := new(big.Int).ModInverse(Lg, privateKey.N)
     * m = common.ModInt(privateKey.N).Mul(Lc, inv)
     * return
     * }
     */
    public BigInteger decrypt(BigInteger c) {
        BigInteger n = publicKey.getN();
        BigInteger n2 = n.multiply(n);
        // c < 0 || c >= N2 ?
        if (c.compareTo(BigInteger.ZERO) < 0 || c.compareTo(n2) >= 0) {
            throw new IllegalArgumentException("c is error argument");
        }
        BigInteger lc = L(c.modPow(lambdaN, n2), n);

        BigInteger gamma = publicKey.gamma();
        BigInteger lg = L(gamma.modPow(lambdaN, n2), n);

        BigInteger inv = lg.modInverse(n);
        BigInteger m = lc.multiply(inv).mod(n);
        return m;
    }


    /**
     * func L(u, N *big.Int) *big.Int {
     * t := new(big.Int).Sub(u, one)
     * return new(big.Int).Div(t, N)
     * }
     */
    public BigInteger L(BigInteger u, BigInteger N) {
        BigInteger t = u.subtract(BigInteger.ONE);
        return t.divide(N);
    }

}
