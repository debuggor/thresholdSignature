package com.debuggor.crypto.paillier;

import com.alibaba.fastjson.JSONObject;

import java.math.BigInteger;
import java.util.Random;

/**
 * @Author:yong.huang
 * @Date:2020-05-29 22:41
 */
public class PublicKey {

    private BigInteger N;

    private static int bits = 2048;

    public PublicKey(BigInteger n) {
        N = n;
    }

    public BigInteger getN() {
        return N;
    }

    public JSONObject toJson() {
        JSONObject object = new JSONObject();
        object.put("N", this.getN());
        return object;
    }

    public BigInteger encrypt(BigInteger m) {
        return encryptAndReturnRandomness(m);
    }

    /**
     * if m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
     * return nil, nil, ErrMessageTooLong
     * }
     * x = common.GetRandomPositiveRelativelyPrimeInt(publicKey.N)
     * N2 := publicKey.NSquare()
     * // 1. gamma^m mod N2
     * Gm := new(big.Int).Exp(publicKey.Gamma(), m, N2)
     * // 2. x^N mod N2
     * xN := new(big.Int).Exp(x, publicKey.N, N2)
     * // 3. (1) * (2) mod N2
     * c = common.ModInt(N2).Mul(Gm, xN)
     *
     * @param m
     * @return
     */
    public BigInteger encryptAndReturnRandomness(BigInteger m) {
        // m < 0 || m >= N ?
        if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(N) >= 0) {
            throw new IllegalArgumentException("m is error argument");
        }
        BigInteger x;
        do {
            x = new BigInteger(bits, new Random());
        } while (x.compareTo(N) >= 0);

        BigInteger n2 = nSquare();
        BigInteger gamma = gamma();

        BigInteger gm = gamma.modPow(m, n2);
        BigInteger xN = x.modPow(N, n2);
        BigInteger c = gm.multiply(xN).mod(n2);
        return c;
    }

    public BigInteger gamma() {
        return N.add(BigInteger.ONE);
    }

    /**
     * func (publicKey *PublicKey) NSquare() *big.Int {
     * return new(big.Int).Mul(publicKey.N, publicKey.N)
     * }
     */

    public BigInteger nSquare() {
        return N.multiply(N);
    }

    /**
     * func (publicKey *PublicKey) HomoMult(m, c1 *big.Int) (*big.Int, error) {
     * if m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
     * return nil, ErrMessageTooLong
     * }
     * N2 := publicKey.NSquare()
     * if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { // c1 < 0 || c1 >= N2 ?
     * return nil, ErrMessageTooLong
     * }
     * // cipher^m mod N2
     * return common.ModInt(N2).Exp(c1, m), nil
     * }
     */
    public BigInteger homoMult(BigInteger m, BigInteger c1) {
        // m < 0 || m >= N ?
        if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(N) >= 0) {
            throw new IllegalArgumentException("m is error argument");
        }
        BigInteger n2 = nSquare();
        // c1 < 0 || c1 >= N2 ?
        if (c1.compareTo(BigInteger.ZERO) < 0 || c1.compareTo(n2) >= 0) {
            throw new IllegalArgumentException("c1 is error argument");
        }
        BigInteger c2 = c1.modPow(m, n2);
        return c2;
    }

    /**
     * func (publicKey *PublicKey) HomoAdd(c1, c2 *big.Int) (*big.Int, error) {
     * N2 := publicKey.NSquare()
     * if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { // c1 < 0 || c1 >= N2 ?
     * return nil, ErrMessageTooLong
     * }
     * if c2.Cmp(zero) == -1 || c2.Cmp(N2) != -1 { // c2 < 0 || c2 >= N2 ?
     * return nil, ErrMessageTooLong
     * }
     * // c1 * c2 mod N2
     * return common.ModInt(N2).Mul(c1, c2), nil
     * }
     */
    public BigInteger homoAdd(BigInteger c1, BigInteger c2) {
        BigInteger n2 = nSquare();
        // c1 < 0 || c1 >= N2 ?
        if (c1.compareTo(BigInteger.ZERO) < 0 || c1.compareTo(n2) >= 0) {
            throw new IllegalArgumentException("c1 is error argument");
        }
        // c2 < 0 || c2 >= N2 ?
        if (c2.compareTo(BigInteger.ZERO) < 0 || c2.compareTo(n2) >= 0) {
            throw new IllegalArgumentException("c2 is error argument");
        }
        return c1.multiply(c2).mod(n2);
    }
}
