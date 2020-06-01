package self.xuwenhui.signature;

import java.security.Signature;

public class SignatureAlgorithmExec {

    /**
     * 签名
     *
     * @param data               待签名的字符串
     * @param privateKeyStr      预先分配好的私钥
     * @param signatureAlgorithm 签名算法
     * @return 签名完成后的字符串数据
     * @throws Exception
     */
    public static String sign(String data, String privateKeyStr, SignatureAlgorithmEnum signatureAlgorithm)
            throws Exception {
        Signature signature = Signature.getInstance(signatureAlgorithm.name());
        signature.initSign(EncryptAlgorithm.generatePrivateKeyFrom(privateKeyStr, signatureAlgorithm.getAlgorithm()));
        signature.update(data.getBytes());
        byte[] bytes = signature.sign();
        return EncryptAlgorithm.base64EncodeToString(bytes);
    }

    /**
     * 验签
     *
     * @param data               需要验证的数据(上面方法的参数 data)
     * @param signatureStr       签名的字符串(上面方法的返回值)
     * @param publicKeyStr       预先分配好的公钥
     * @param signatureAlgorithm 签名算法
     * @return true表示成功，false表示失败
     * @throws Exception
     */
    public static boolean verify(String data, String signatureStr, String publicKeyStr,
                                 SignatureAlgorithmEnum signatureAlgorithm) throws Exception {
        Signature signature = Signature.getInstance(signatureAlgorithm.name());
        signature.initVerify(EncryptAlgorithm.generatePublicKeyFrom(publicKeyStr, signatureAlgorithm.getAlgorithm()));
        signature.update(data.getBytes());
        return signature.verify(EncryptAlgorithm.base64DecodeString(signatureStr));
    }
}
