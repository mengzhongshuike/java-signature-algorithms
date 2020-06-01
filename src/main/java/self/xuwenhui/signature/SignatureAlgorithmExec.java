package self.xuwenhui.signature;

import java.security.Signature;

public class SignatureAlgorithmExec {
	public static String sign(String data, String privateKeyStr, SignatureAlgorithmEnum signatureAlgorithm)
			throws Exception {
		Signature signature = Signature.getInstance(signatureAlgorithm.name());
		signature.initSign(RSA.generatePrivateKeyFrom(privateKeyStr));
		signature.update(data.getBytes());
		byte[] bytes = signature.sign();
		return RSA.base64EncodeToString(bytes);
	}

	public static boolean verify(String data, String signateStr, String publicKeyStr,
			SignatureAlgorithmEnum signatureAlgorithm) throws Exception {
		Signature signature = Signature.getInstance(signatureAlgorithm.name());
		signature.initVerify(RSA.generatePublicKeyFrom(publicKeyStr));
		signature.update(data.getBytes());
		return signature.verify(RSA.base64DecodeString(signateStr));
	}
}
