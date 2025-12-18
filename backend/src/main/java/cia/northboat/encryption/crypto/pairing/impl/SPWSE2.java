package cia.northboat.encryption.crypto.pairing.impl;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
import cia.northboat.encryption.utils.HashUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class SPWSE2 extends PairingSystem {

    @Autowired
    public SPWSE2(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }


    public Element g, h, g1, pkc, pka, EK, a1, b1, b2, xt, xti, v, r, Ni, Fi, Ei, Di, Mi;
    public Element[] H, S, V, R;


    public Element f(Element x){
        return a1.mul(x).add(b1).getImmutable();
    }


    @Override
    public void setup(){ // 参与计算的随机数
        g = randomG();
        a1 = this.getZr().newRandomElement().getImmutable();
        b1 = this.getZr().newRandomElement().getImmutable();
        b2 = this.getZr().newRandomElement().getImmutable();
        xt = this.getZr().newRandomElement().getImmutable();
        xti = this.getZr().newRandomElement().getImmutable();
        v = this.getZr().newRandomElement().getImmutable();
        r = this.getZr().newRandomElement().getImmutable();

        pkc = this.getG().newRandomElement().getImmutable();
        pka = this.getG().newRandomElement().getImmutable();

        // 初始化用户私钥
        Mi = r;
        m = this.getZr().newRandomElement().getImmutable();
        s = this.getZr().newRandomElement().getImmutable();
    }


    @Override
    public void keygen(){
        // 系统公钥
        g1 = g.powZn(b1).getImmutable();
        EK = g.powZn(f(xt).div(b1)).getImmutable();
        // 这里从g1改成了g
        h = g.powZn(v).getImmutable();

        Di = g.powZn(b2.mul(f(xti)).mul(xt.negate().div(xti.sub(xt)))).getImmutable();
        Ei = g1.powZn(b2.mul(xti.negate().div(xt.sub(xti)))).getImmutable();

        // 用户公钥
        Ni = g.powZn(r).getImmutable();
        Fi = g.powZn(r.mul(b2)).getImmutable();


        S = new Element[2*this.getN()];
        V = new Element[2*this.getN()];
        H = new Element[2*this.getN()];

        for(int i = 0; i < 2*this.getN(); i++){
            S[i] = this.getZr().newRandomElement().getImmutable();
            V[i] = this.getZr().newRandomElement().getImmutable();
            H[i] = g.powZn(S[i]).mul(h.powZn(V[i])).getImmutable();
        }

        R = new Element[this.getN()];
        for(int i = 0; i < this.getN(); i++){
            // 取随机数填充 R
            R[i] = this.getZr().newRandomElement().getImmutable();
        }
    }

    // 密文
    public Element C1, C2, C3;
    public Element[] E;
    @Override
    public void enc(String word){
        Element[] W = HashUtil.hashStr2ZrArr(this.getZr(), word, this.getN());
        Element[] X = new Element[2*this.getN()];
        for(int i = 0; i < this.getN(); i++){
            X[2*i] = Mi.mul(R[i]).mul(W[i]).getImmutable();
            X[2*i+1] = Mi.negate().mul(R[i]).getImmutable();
        }
        C1 = Fi;
        C2 = EK.powZn(Mi).getImmutable();
        C3 = Ni;
        E = new Element[2*this.getN()];
        // 这里从g1改成了g
        for(int i = 0; i < 2*this.getN(); i++){
            E[i] = g.powZn(Mi.mul(X[i])).getImmutable();
        }
    }


    // 参与计算的随机数
    public Element m, s;
    // 陷门
    public Element T1, T2, T3, T4, T5;
    public Element[] K, P;

    @Override
    public void trap(String word){
        Element[] W = HashUtil.hashStr2ZrArr(this.getZr(), word, this.getN());
        // 构造 2n 长向量 Y
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

        T1 = g1.powZn(s).getImmutable();
        T2 = Ei.powZn(s).getImmutable();
//        System.out.println("T2: " + T2);
//        System.out.println(g.powZn(s.mul(b2).mul(xti.negate().div(xt.sub(xti)))));
        T3 = Di.powZn(s).getImmutable();
//        System.out.println("T3: " + T3);
//        System.out.println(g.powZn(s.mul(b2).mul(f(xti).mul(xt.negate().div(xti.sub(xt))))));


        K = new Element[2*this.getN()];
        P = new Element[2*this.getN()];
        Element s1 = this.getZr().newZeroElement(), s2 = this.getZr().newZeroElement(); // 用于计算和
        for(int i = 0; i < 2*this.getN(); i++){
            s1.add(S[i].mul(Y[i]));
            s2.add(V[i].mul(Y[i]));
            K[i] = g.powZn(m.mul(Y[i])).getImmutable();
            P[i] = H[i].powZn(s).getImmutable();
        }
//        System.out.println("s1: " + s1 + "\ns2: " + s2);
        T4 = g.powZn(s.mul(m.mul(s1))).getImmutable();
        // 这里之前写错了sub，已改
        T5 = g.powZn(s.mul(m.mul(s2))).getImmutable();
    }


    boolean flag;
    Element left, right;
    @Override
    public boolean search(){
        Element acc = this.getGT().newOneElement();
        for(int i = 0; i < 2*this.getN(); i++){
//            System.out.println("E[" + i + "] = " + E[i]);
//            System.out.println("P[" + i + "] = " + P[i]);
            acc.mul(this.getBp().pairing(E[i].mul(P[i]), K[i]));
//            System.out.println("acc step " + i + ": " + acc);
        }
        Element d = this.getBp().pairing(g, T4).mul(this.getBp().pairing(h, T5)).getImmutable();


        Element part1 = this.getBp().pairing(C1, T1).getImmutable();
        Element part2 = acc.div(d).getImmutable();
        Element part3 = this.getBp().pairing(C2, T2).getImmutable();
        Element part4 = this.getBp().pairing(C3, T3).getImmutable();

//        System.out.println("part1: " + part1);
//        System.out.println("part3*4: " + part3.mul(part4));

//        System.out.println("part2: " + part2);

//        System.out.println("part1: " + part1);
//        System.out.println("part2: " + part2);
//        System.out.println("part3: " + part3);
//        System.out.println("part4: " + part4);
//
//        System.out.println("C1 pairing check: " + bp.pairing(C1, T1));  // part1
//        System.out.println("C2 pairing check: " + bp.pairing(C2, T2));  // part3
//        System.out.println("acc pairing check: " + acc);  // part2
//        System.out.println("T4 pairing check: " + bp.pairing(g, T4));   // T4
//        System.out.println("T5 pairing check: " + bp.pairing(h, T5));   // T5

        left = part1.mul(part2).getImmutable();
        right = part3.mul(part4).getImmutable();

        System.out.println("left: " + left + "\nright: " + right);
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
