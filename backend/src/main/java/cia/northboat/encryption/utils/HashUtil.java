package cia.northboat.encryption.utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class HashUtil {


    public static byte[] concat(byte[] ... arr) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try{
            for(byte[] bytes: arr){
                outputStream.write(bytes);
            }
        } catch (IOException e){
            System.out.println("IOException: concat bytes error");
        }
        return outputStream.toByteArray();
    }


    public static Element hashByte2Group(Field group, byte[] bytes){
        return group.newElementFromHash(bytes, 0, bytes.length).getImmutable();
    }


    public static Element hashStr2Group(Field group, String ... strings){
        int n = strings.length;
        byte[][] bytes = new byte[n][];
        for(int i = 0; i < n; i++){
            bytes[i] = strings[i].getBytes();
        }
        byte[] input = concat(bytes);
        return hashByte2Group(group, input);
    }


    // 字符串映射，通过 ASCII 码将每个字符映射到 Zr 群上
    // 映射为 Zr 群上的整数数组，但文献上给的 {0,1} 串（可能是布隆过滤器）
    // n 是映射后的数组长度，超出的空的元素将被认为是 0
    public static Element[] hashStr2ZrArr(Field Zr, String word, int n){
        Element[] W = new Element[n];
        for(int i = 0; i < n; i++){
            if(i >= word.length()){
                W[i] = Zr.newZeroElement().getImmutable();
                continue;
            }
            // ASCII 码
            int number = word.charAt(i);
            W[i] = Zr.newElement(number).getImmutable();
        }
        return W;
    }


    public static Element hashStr2GT(Field Zr, Element gt, String word, int n){
        Element[] W = hashStr2ZrArr(Zr, word, n);
        return hashZrArr2GT(gt, W);
    }

    public static Element hashZrArr2GT(Element gt, Element[] W){
        return hashZrArr2G(gt, W);
    }

    // 四个 G 上的元素通过累乘哈希为一个 G 上的元素
    public static Element hash4G(Element g1, Element g2, Element g3, Element g4){
        return g1.mul(g2).mul(g3).mul(g4).getImmutable();
    }

    // 将 Zr 群上的数组 w 通过 G 上的生成元 g 映射为 Zr 群上的单个元素
    public static Element hashZrArr2Zr(Field Zr, Element[] w){
        Element h = Zr.newOneElement();
        for(Element e: w){
            if(!e.isZero()){
                h.mul(e);
            }
        }
        return h.getImmutable();
    }

    // 将 G 上元素 e 映射到 Zr 群上
    public static Element hashG2Zr(Field Zr, Element e){
        byte[] hash = e.toBytes();
        return Zr.newElementFromHash(hash, 0, hash.length).getImmutable();
    }

    // 把 Zr 群上元素 r 通过 G 上生成元 g 映射到 G 上
    public static Element hashZr2G(Element g, Element r){
        return g.powZn(r).getImmutable();
    }

    // 通过生成元 g 把 {0,1}* 映射到 G 上
    public static Element hashZrArr2G(Element g, Element[] w){
        Element h = g.duplicate();
        for(Element e: w){
            if(!e.isZero()){
                h.powZn(e);
            }
        }
        return h.getImmutable();
    }

    public static Element hashZrArr2GWithTwoFact(Element pk1, Element pk2, Element[] w){
        Element h = pk1.mul(pk2).duplicate();
        for(Element e: w){
            if(!e.isZero()){
                h.powZn(e);
            }
        }
        return h;
    }


    public static Element[] hashStrArr2ZrArr(Field Zr, String[] m){
        int n = m.length;
        Element[] w = new Element[n];
        for(int i = 0; i < n; i++){
            w[i] = hashStr2Group(Zr, m[i]);
        }
        return w;
    }

    public static Element[] fillInArr(Field Zr, Element[] raw, int l){
        Element[] dist = new Element[l];
        for(int i = 0; i < l; i++){
            if(i < raw.length){
                dist[i] = raw[i];
            } else {
                dist[i] = Zr.newZeroElement().getImmutable();
            }
        }
        return dist;
    }

    // 将 GT 上元素 gt 和 Zr 群上数组 w 映射到群 G 上
    public static Element hashGT2GWithZrArr(Field G, Element gt, Element[] w){
        Element h = gt.duplicate();
        for(Element e: w){
            if(!e.isZero()){
                h.powZn(e);
            }
        }
        byte[] bytes = h.toBytes();
        return G.newElementFromHash(bytes, 0, bytes.length).getImmutable();
    }

    public static Element hashGT2G(Field G, Element gt){
        byte[] bytes = gt.toBytes();
        return G.newElementFromHash(bytes, 0, bytes.length).getImmutable();
    }

    public static Element hashG2ZrWithZr(Field Zr, Element g, Element r){
        return hashG2Zr(Zr, g.powZn(r)).getImmutable();
    }

    public static Element hashGT2Zr(Field Zr, Element gt){
        byte[] bytes = gt.toBytes();
        return Zr.newElementFromHash(bytes, 0, bytes.length).getImmutable();
    }

    // 将 GT 上元素 gt 映射为 log(q) 位的 Zr 上的整数元素
    public static Element hashGT2ZrWithQ(Field Zr, Element gt, int q){
        byte[] bytes = gt.toBytes();
        BigInteger b = new BigInteger(1, bytes);
        BigInteger qMask = BigInteger.ONE.shiftLeft(q).subtract(BigInteger.ONE); // log(q)位掩码
        BigInteger truncatedHash = b.and(qMask);
        return Zr.newElement(truncatedHash).getImmutable();
    }

    public static Element getInvModP(Field Zr, Element e, Element p){
//        System.out.println(e);
//        System.out.println(p);
        return Zr.newElement(e.toBigInteger().modInverse(p.toBigInteger())).getImmutable();
    }

}
