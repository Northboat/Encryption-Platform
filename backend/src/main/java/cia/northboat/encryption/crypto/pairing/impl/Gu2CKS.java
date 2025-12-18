package cia.northboat.encryption.crypto.pairing.impl;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class Gu2CKS extends PairingSystem {

    Element g;
    @Autowired
    public Gu2CKS(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }


    Element ZERO, ONE, TWO, SEVEN;
    @Override
    public void setup(){
        g = randomG();
        ZERO = this.getZr().newZeroElement().getImmutable();
        ONE = this.getZr().newOneElement().getImmutable();
        TWO = this.getZr().newElement(2).getImmutable();
        SEVEN = this.getZr().newElement(7).getImmutable();
    }



    Element skc, pkc, g1;
    Element[] sk, pk;
    @Override
    public void keygen(){
        skc = this.getZr().newRandomElement().getImmutable();
        pkc = g.powZn(skc).getImmutable();
        Element x1 = this.getZr().newRandomElement().getImmutable();
        g1 = g.powZn(x1).getImmutable();

        sk = new Element[getK()]; pk = new Element[getK()];
        for(int i = 0; i < getK() ; i++){
            sk[i] = this.getZr().newRandomElement().getImmutable();
            pk[i] = g.powZn(sk[i]).getImmutable();
        }
    }


    Element[] eta, B;
    Element C1;
    @Override
    public void enc(List<String> words){
        // 模拟传入的关键词
        eta = new Element[3]; B = new Element[3];
        eta[0] = this.getZr().newElement(207).getImmutable();
        eta[1] = this.getZr().newElement(-30).getImmutable();
        eta[2] = this.getZr().newOneElement().getImmutable();

        Element r1 = this.getZr().newRandomElement().getImmutable();


        for(int i = 0; i < 3; i++){
            B[i] = g.powZn(r1.mul(eta[i]).mul(SEVEN.invert())).getImmutable();
        }
        // 207-30x(10)+(10)^2 = 7
        Element part1 = this.getBp().pairing(g1, pk[0]).powZn(r1).getImmutable();
        Element part2 = this.getBp().pairing(g1, pk[1]).powZn(r1).getImmutable();
        Element part3 = this.getBp().pairing(g1, pk[2]).powZn(r1).getImmutable();
        C1 = part1.mul(part2).mul(part3).getImmutable();
    }



    Element T10, T11, T12, T13, T20, T21, T22, T23, T30, T31, T32, T33;
    @Override
    public void trap(List<String> words){
        // 模拟关键词的哈希值
        Element w1 = this.getZr().newElement(10).getImmutable();
        Element w2 = this.getZr().newElement(20).getImmutable();
        Element a = this.getZr().newRandomElement().getImmutable();
        Element b = this.getZr().newRandomElement().getImmutable();
        Element c = this.getZr().newRandomElement().getImmutable();
        Element d = null;

        T10 = pk[0].powZn(a).getImmutable();
        d = pkc.powZn(sk[0].mul(a));
        T11 = g1.powZn(sk[0].mul(TWO.invert()).mul(w1.powZn(ZERO).add(w2.powZn(ZERO)))).mul(d).getImmutable();
        T12 = g1.powZn(sk[0].mul(TWO.invert()).mul(w1.powZn(ONE).add(w2.powZn(ONE)))).mul(d).getImmutable();
        T13 = g1.powZn(sk[0].mul(TWO.invert()).mul(w1.powZn(TWO).add(w2.powZn(TWO)))).mul(d).getImmutable();

        d = pkc.powZn(sk[1].mul(b));
        T20 = pk[1].powZn(b).getImmutable();
        T21 = g1.powZn(sk[1].mul(TWO.invert()).mul(w1.powZn(ZERO).add(w2.powZn(ZERO)))).mul(d).getImmutable();
        T22 = g1.powZn(sk[1].mul(TWO.invert()).mul(w1.powZn(ONE).add(w2.powZn(ONE)))).mul(d).getImmutable();
        T23 = g1.powZn(sk[1].mul(TWO.invert()).mul(w1.powZn(TWO).add(w2.powZn(TWO)))).mul(d).getImmutable();

        d = pkc.powZn(sk[2].mul(c));
        T30 = pk[2].powZn(c).getImmutable();
        T31 = g1.powZn(sk[2].mul(TWO.invert()).mul(w1.powZn(ZERO).add(w2.powZn(ZERO)))).mul(d).getImmutable();
        T32 = g1.powZn(sk[2].mul(TWO.invert()).mul(w1.powZn(ONE).add(w2.powZn(ONE)))).mul(d).getImmutable();
        T33 = g1.powZn(sk[2].mul(TWO.invert()).mul(w1.powZn(TWO).add(w2.powZn(TWO)))).mul(d).getImmutable();
    }


    boolean flag;
    Element K;
    static Element[] T;
    public boolean search(){
        T = new Element[3];

        T[0] = T11.div(T10.powZn(skc)).mul(T21.div(T20.powZn(skc))).mul(T31.div(T30.powZn(skc))).getImmutable();
        T[1] = T12.div(T10.powZn(skc)).mul(T22.div(T20.powZn(skc))).mul(T32.div(T30.powZn(skc))).getImmutable();
        T[2] = T13.div(T10.powZn(skc)).mul(T23.div(T20.powZn(skc))).mul(T33.div(T30.powZn(skc))).getImmutable();

        Element part1 = this.getBp().pairing(B[0], T[0]).getImmutable();
        Element part2 = this.getBp().pairing(B[1], T[1]).getImmutable();
        Element part3 = this.getBp().pairing(B[2], T[2]).getImmutable();

        K = part1.mul(part2).mul(part3).getImmutable();

        System.out.println("Gu2CKS K: " + K);
        System.out.println("Gu2CKS C1: " + C1);

        flag = K.isEqual(C1);
        return flag;
    }


    @Override
    public Map<String, Object> test(String word, List<String> words, int round) {
        Map<String, Object> data = super.test(word, words, round);
        data.put("flag", flag);
        data.put("K", K);
        data.put("C1", C1);
        return data;
    }

}
