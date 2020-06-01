package self.xuwenhui.signature;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public final class RSA {
	private static final String KEY_ALGORITHM = "RSA";
	private static final String PUBLIC_KEY = "RSAPublicKey";
	private static final String PRIVATE_KEY = "RSAPrivateKey";

	public static String getPublicKeyStr(Map<String, Object> keyMap) throws Exception {
		Key key = (Key)keyMap.get(PUBLIC_KEY);
		return base64EncodeToString(key.getEncoded());
	}

	public static String getPrivateKeyStr(Map<String, Object> keyMap) throws Exception {
		Key key = (Key)keyMap.get(PRIVATE_KEY);
		return base64EncodeToString(key.getEncoded());
	}

	static PublicKey generatePublicKeyFrom(String key) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(key);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		return keyFactory.generatePublic(keySpec);
	}

	static PrivateKey generatePrivateKeyFrom(String key) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(key);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		return keyFactory.generatePrivate(keySpec);
	}

	static String base64EncodeToString(byte[] key) {
		return Base64.getEncoder().encodeToString(key);
	}

	static byte[] base64DecodeString(String s) {
		return Base64.getDecoder().decode(s);
	}

	public static Map<String, Object> initRSAKey() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGen.initialize(1024);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
		Map<String, Object> keyMap = new HashMap<>(4);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
}
