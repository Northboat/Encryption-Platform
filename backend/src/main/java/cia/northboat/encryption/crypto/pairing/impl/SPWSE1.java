package cia.northboat.encryption.crypto.pairing.impl;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
import cia.northboat.encryption.utils.HashUtil;
import it.unisa.dia.gas.jpbc.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;


@Component
public class SPWSE1 extends PairingSystem {


    Field G2;
    Element g1, g2, h, v, r, m;
    @Autowired
    public SPWSE1(Field G1, Field GT, Field Zr, Pairing bp, Field G2){
        super(G1, GT, Zr, bp);
        this.G2 = G2;
    }
    public Element[] H, S, T, R;


    // 初始化主公钥、主私钥
    @Override
    public void setup(){ // 一些参与计算的随机数
        g1 = randomG();
        g2 = G2.newRandomElement().getImmutable();
        v = this.getZr().newRandomElement().getImmutable();
        r = this.getZr().newRandomElement().getImmutable();
        m = this.getZr().newRandomElement().getImmutable();
    }

    @Override
    public void keygen(){
        h = g1.powZn(v).getImmutable();

        S = new Element[2*this.getN()];
        T = new Element[2*this.getN()];
        H = new Element[2*this.getN()];

        for(int i = 0; i < 2*this.getN(); i++){
            S[i] = this.getZr().newRandomElement().getImmutable();
            T[i] = this.getZr().newRandomElement().getImmutable();
            H[i] = g1.powZn(S[i]).mul(h.powZn(T[i])).getImmutable();
        }

        R = new Element[this.getN()];
        for(int i = 0; i < this.getN(); i++){
            // 取随机数填充 R
            R[i] = this.getZr().newRandomElement().getImmutable();
        }
    }


    // 加密后的密文
    public Element C1, C2;
    public Element[] E;
    @Override
    public void enc(String word){

//        System.out.println("加密关键词 " + word + "\n=====================");

        // 将字符串各个字符映射到整数群 W，长度为 n
        Element[] W = HashUtil.hashStr2ZrArr(this.getZr(), word, this.getN());

//        System.out.print("关键词的 ASCII 码映射 W: ( ");
//        for(Element e: W){
//            System.out.print(e + " ");
//        }
//        System.out.println(")");



        Element[] X = new Element[2*this.getN()];
        // 通过 W 构造向量 X
        for(int i = 0; i < this.getN(); i++){
            // 实际上文档里给的是 x[2i-1] = r*ri*wi，但我从0开始存，所以偶数用这个
            // 即用 x[0] 表示 x1
            X[2*i] = r.mul(R[i]).mul(W[i]).getImmutable();
            // 而奇数用 -r*ri
            X[2*i+1] = r.negate().mul(R[i]).getImmutable();
        }

//        System.out.print("关键词的加密的中间态 X: ( ");
//        for(Element e: X){
//            System.out.print(e + " ");
//        }
//        System.out.println(")");



        // 计算关键词 word 的密文
        C1 = g1.powZn(r).getImmutable();
        C2 = h.powZn(r).getImmutable();
        // 将向量 X 扩展为二维的密文 E
        E = new Element[2*this.getN()];
        for(int i = 0; i < 2*this.getN(); i++){
            E[i] = g1.powZn(X[i]).mul(H[i].powZn(r)).getImmutable();
        }

//        System.out.println("关键词密文 C1: " + C1 + "\n关键词密文 C2: " + C2);
//        System.out.println("关键词密文 E: ");
//        for(Element e: E){
//            System.out.println(e);
//        }
//        System.out.println("=====================\n");

    }


    // 计算要查找的关键词的陷门（加密信息）
    public Element T1, T2;
    public Element[] K;
    @Override
    public void trap(String word){
//        System.out.println("计算陷门 " + word + "\n=====================");

        // 将关键词字符串映射为整数群向量，这里的处理和上面一样，用 0 填充多余的位置
        Element[] W = HashUtil.hashStr2ZrArr(this.getZr(), word, this.getN());

//        System.out.print("陷门的 ASCII 码映射 W: ( ");
//        for(Element e: W){
//            System.out.print(e + " ");
//        }
//        System.out.println(")");

        // 通过 W 构造关键词对应的向量 Y
        Element[] Y = new Element[2*this.getN()];
        for(int i = 0; i < this.getN(); i++){
            if(i < word.length() && word.charAt(i) != '*'){
                Y[2*i] = this.getZr().newOneElement().getImmutable();
                Y[2*i+1] = W[i];
            } else {
                Y[2*i] = this.getZr().newZeroElement().getImmutable();
                Y[2*i+1] = this.getZr().newZeroElement().getImmutable();
            }
        }

//        System.out.print("陷门加密的中间态 Y: ( ");
//        for(Element e: Y){
//            System.out.print(e + " ");
//        }
//        System.out.println(")");


        // 将 Y 扩展为二维矩阵 K
        Element s1 = this.getZr().newZeroElement(), s2 = this.getZr().newZeroElement();
        K = new Element[2*this.getN()];
        for(int i = 0; i < 2*this.getN(); i++){
            s1.add(S[i].mul(Y[i]));
            s2.add(T[i].mul(Y[i]));
//            System.out.println(S[i].mul(Y[i]));
//            System.out.println("s1: " + s1);
//            System.out.println("s2: " + s2 + "\n");
            K[i] = g2.powZn(m.mul(Y[i])).getImmutable();
        }
        T1 = g2.powZn(m.mul(s1)).getImmutable();
        T2 = g2.powZn(m.mul(s2)).getImmutable();


//        System.out.println("陷门 T1: " + T1 + "\n陷门 T2: " + T2 + "\n陷门 K:");
//        for(Element e: K){
//            System.out.println(e);
//        }
//        System.out.println("=====================\n");
    }


    boolean flag;
    Element left, right;
    @Override
    public boolean search(){
//        System.out.println("开始匹配\n=====================");
        Element acc = this.getGT().newOneElement();
        for(int i = 0; i < 2*this.getN(); i++){
            acc.mul(this.getBp().pairing(E[i], K[i]));
        }
//        Element m = acc.getImmutable();
        Element d = this.getBp().pairing(C1, T1).mul(this.getBp().pairing(C2, T2)).getImmutable();

        Element ans = acc.div(d).getImmutable();

        left = ans;
        right = this.getGT().newOneElement().getImmutable();
        System.out.println("left: " + left);
        System.out.println("right: " + right);
//        System.out.println("=====================\n\n");

        flag = left.isEqual(right);
        return flag;
    }


    @Override
    public Map<String, Object> test(String word, List<String> words, int round) {
        Map<String, Object> data = super.test(word, words, round);
        data.put("flag", flag);
        data.put("left", left);
        data.put("right", right);
        return data;
    }
}