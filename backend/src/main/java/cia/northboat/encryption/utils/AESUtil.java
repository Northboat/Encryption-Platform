package cia.northboat.encryption.utils;


import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESUtil {

    private static final byte[] key = getRandomKey();
    private static Charset charset = StandardCharsets.UTF_8;

    public static byte[] getRandomKey() {

        try{
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

            // 设置密钥长度和随机源
            keyGenerator.init(128, new SecureRandom());
            // 生成密钥
            SecretKey secretKey = keyGenerator.generateKey();
            // 获取密钥内容
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return null;

    }

    public static byte[] enc(byte[] data, byte[] key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }

    public static byte[] dec(byte[] data, byte[] key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }

    public static String encrypt(String content){
        try{
            return Base64.getEncoder().encodeToString(enc(content.getBytes(charset), key));
//            return Base64.encodeBase64String(enc(content.getBytes(charset), key));
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String content) { // 解密
        try{
            byte[] bytes = Base64.getDecoder().decode(content);
            byte[] result = dec(bytes, key);
            return new String(result, charset);
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

}
