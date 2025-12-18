package cia.northboat.encryption.crypto.arch;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Component
public class SimpleMinerArchetype {


    public static String generateRandomString(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        Random random = new Random();

        for (int i = 0; i < length; i++) {
            int index = random.nextInt(chars.length());
            sb.append(chars.charAt(index));
        }
        return sb.toString();
    }

    // 将任意字符串进行 SHA-256 哈希
    public String sha256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));

        // 将字节数组转换为十六进制字符串
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public Map<String, Object> mine(int difficulty){
        String blockData = generateRandomString(9);

        Map<String, Object> data = new HashMap<>();
        data.put("difficulty", difficulty);
        data.put("block data", blockData);

        int nonce = 0;
        String hash;

        // 要求哈希值的前缀有 difficulty 个 0，才满足要求
        String targetPrefix = "0".repeat(difficulty);

        long startTime = System.currentTimeMillis(), endTime;
        while (true) {
            // blockData 是假设的上一个区块的数据摘要
            String input = blockData + nonce;
            try {
                hash = sha256(input);
            } catch (Exception e) {
                data.put("Error", e.toString());
                return data;
            }
            if (hash.startsWith(targetPrefix)) {
                System.out.println("🎉 找到符合条件的 nonce: " + nonce);
                System.out.println("🔒 对应哈希值: " + hash);
                data.put("nonce", nonce);
                data.put("hash", hash);
                break;
            }
            endTime = System.currentTimeMillis();
            if(endTime - startTime >= 3600000){ // 当超过 1h，自动退出
                break;
            }
            nonce++;
        }

        endTime = System.currentTimeMillis();
        System.out.println("⏱️ 挖矿耗时: " + (endTime - startTime) + " ms");

        data.put("time_cost", endTime-startTime);

        return data;
    }

    public static void main(String[] args) throws Exception {
        SimpleMinerArchetype miner = new SimpleMinerArchetype();
        Map<String, Object> data = miner.mine(5);
        System.out.println(data);
    }
}