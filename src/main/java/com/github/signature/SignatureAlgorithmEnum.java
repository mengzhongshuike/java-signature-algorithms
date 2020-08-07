package com.github.signature;

public enum SignatureAlgorithmEnum {
    MD5withRSA("RSA", 1024), SHA1withRSA("RSA", 1024), SHA256withRSA("RSA", 1024),
    SHA1withDSA("DSA", 512), SHA256withDSA("DSA", 512), SHA1withECDSA("EC", 256),
    SHA256withECDSA("EC", 256), SHA512withECDSA("EC", 256);

    /**
     * 签名算法 RSA、DSA、EC
     */
    private String algorithm;

    /**
     * 签名算法特定的keysize
     */
    private int keysize;

    SignatureAlgorithmEnum(String algorithm, int keysize) {
        this.algorithm = algorithm;
        this.keysize = keysize;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getKeysize() {
        return keysize;
    }
}
