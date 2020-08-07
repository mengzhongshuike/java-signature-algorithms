package com.github.signature;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public final class EncryptAlgorithm {
    private static final String PUBLIC_KEY = "PublicKey";
    private static final String PRIVATE_KEY = "PrivateKey";

    public static String getPublicKeyStr(Map<String, Object> keyMap) {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return base64EncodeToString(key.getEncoded());
    }

    public static String getPrivateKeyStr(Map<String, Object> keyMap) {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return base64EncodeToString(key.getEncoded());
    }

    static PublicKey generatePublicKeyFrom(String key, String algorithm) throws Exception {
        byte[] keyBytes = base64DecodeString(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(keySpec);
    }

    static PrivateKey generatePrivateKeyFrom(String key, String algorithm) throws Exception {
        byte[] keyBytes = base64DecodeString(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePrivate(keySpec);
    }

    static String base64EncodeToString(byte[] key) {
        return Base64.getEncoder().encodeToString(key);
    }

    static byte[] base64DecodeString(String s) {
        return Base64.getDecoder().decode(s);
    }

    public static Map<String, Object> initAlgorithmKey(SignatureAlgorithmEnum signatureAlgorithmEnum) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(signatureAlgorithmEnum.getAlgorithm());
        keyPairGen.initialize(signatureAlgorithmEnum.getKeysize());
        KeyPair keyPair = keyPairGen.generateKeyPair();
        Map<String, Object> keyMap = new HashMap<>(4);
        keyMap.put(PUBLIC_KEY, keyPair.getPublic());
        keyMap.put(PRIVATE_KEY, keyPair.getPrivate());
        return keyMap;
    }
}
