package cia.northboat.encryption.utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.math.BigInteger;
import java.util.Base64;

public class EncodeUtil {

    /*
        一维编码，对单个字段进行简单的大小编码，大于则为 1，小于则为 0
     */
    public static String singleDimensionDec(Element[] m, Element[] w, int n){
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < n; i++){
            BigInteger a = m[i].toBigInteger();
            BigInteger b = w[i].toBigInteger();
            if(a.compareTo(b) < 0 || a.compareTo(b) == 0){ // 当 w 大于等于 m 添 1
                sb.append("1");
            } else { // 当 w 小于 m 添 0
                sb.append("0");
            }
        }
        return sb.toString();
    }

    // 根据原有前缀和新添的前缀构造新的前缀
    public static String[] superposePrefix(String[] prefix, String cur, int n){
        String[] newPrefix = new String[n];
        for(int i = 0; i < n; i++){
            newPrefix[i] = prefix[i] + cur.charAt(i);
        }
        return newPrefix;
    }

    /*
        Z阶码，对二维点数据进行前缀编码
     */
    public static String zCodeEnc(int x1, int y1, int x2, int y2){
        if(x1 <= x2){
            if(y1 >= y2){
                return "00";
            } else {
                return "01";
            }
        } else if(y1 >= y2){
            return "10";
        }
        return "11";
    }

    public static int getMatchedIndex(String z){
        return switch (z) { // 找下标
            case "00" -> 0;
            case "01" -> 1;
            case "10" -> 2;
            case "11" -> 3;
            default -> -1;
        };
    }

    /*
       BigInteger 和 Element 到 base64 编码的转换
     */

    public static String parseBigInteger2HexStr(BigInteger bi){
        return bi.toString(16);
    }

    public static BigInteger parseHexStr2BigInteger(String str){
        return new BigInteger(str, 16);
    }


    public static String parseElement2Base64Str(Element element){
        byte[] bytes = element.toBytes(); // 转为 byte[]
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static Element parseBase64Str2Element(String base64, Field field){
        byte[] bytes = Base64.getDecoder().decode(base64);
        return field.newElementFromBytes(bytes).getImmutable();
    }
}
