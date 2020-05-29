package com.debuggor.paillier;

/**
 * @Author:yong.huang
 * @Date:2020-05-29 22:46
 */
public class Paillier {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public Paillier(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

}
