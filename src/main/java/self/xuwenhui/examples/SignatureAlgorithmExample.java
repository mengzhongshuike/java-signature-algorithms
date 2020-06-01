package self.xuwenhui.examples;

import self.xuwenhui.signature.EncryptAlgorithm;
import self.xuwenhui.signature.SignatureAlgorithmEnum;
import self.xuwenhui.signature.SignatureAlgorithmExec;

import java.util.Map;

public class SignatureAlgorithmExample {
    public static void main(String[] args) {
        try {
            for (SignatureAlgorithmEnum signatureAlgorithmEnum : SignatureAlgorithmEnum.values()) {
                Map<String, Object> keyMap = EncryptAlgorithm.initAlgorithmKey(signatureAlgorithmEnum);
                String publicKey = EncryptAlgorithm.getPublicKeyStr(keyMap);
                System.out.println("publicKey: " + publicKey);
                String privateKey = EncryptAlgorithm.getPrivateKeyStr(keyMap);
                System.out.println("privateKey: " + privateKey);


                String originalStr = "Hello World";

                String signatureStr = SignatureAlgorithmExec.sign(originalStr, privateKey, signatureAlgorithmEnum);
                System.out.println("【" + signatureAlgorithmEnum.name() + "】 signatureStr: " + signatureStr);

                boolean status = SignatureAlgorithmExec.verify(originalStr, signatureStr, publicKey, signatureAlgorithmEnum);
                System.out.println("【" + signatureAlgorithmEnum.name() + "】 status: " + status);

                System.out.println("-----------------------------------------------------------------------------------");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
