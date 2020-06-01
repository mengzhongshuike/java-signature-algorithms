package self.xuwenhui.examples;

import self.xuwenhui.signature.RSA;
import self.xuwenhui.signature.SignatureAlgorithmEnum;
import self.xuwenhui.signature.SignatureAlgorithmExec;

import java.util.Map;

public class SignatureAlgorithmExample {
	public static void main(String[] args) {
		try {
			Map<String, Object> keyMap = RSA.initRSAKey();
			System.out.println("public key --------------------------------------------");
			String publicKey = RSA.getPublicKeyStr(keyMap);
			System.out.println(publicKey);
			System.out.println("--------------------------------------------");
			String privateKey = RSA.getPrivateKeyStr(keyMap);
			System.out.println("private key --------------------------------------------");
			System.out.println(privateKey);
			System.out.println("--------------------------------------------");

			for (SignatureAlgorithmEnum algorithmEnum : SignatureAlgorithmEnum.values()) {
				String originalStr = "Hello World";

				String signatureStr = SignatureAlgorithmExec.sign(originalStr, privateKey, algorithmEnum);
				System.out.println(algorithmEnum.name() + " signatureStr: " + signatureStr);

				boolean status = SignatureAlgorithmExec.verify(originalStr, signatureStr, publicKey, algorithmEnum);
				System.out.println(algorithmEnum.name() +  " status: " + status);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
