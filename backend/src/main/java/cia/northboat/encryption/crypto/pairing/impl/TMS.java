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
public class TMS extends PairingSystem {

    Element g;
    @Autowired
    public TMS(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }

    public Element H(List<String> words){
        Element h = g.duplicate();
        for(String str: words){
            Element[] w = HashUtil.hashStr2ZrArr(this.getZr(), str, this.getN());
            h = HashUtil.hashZrArr2G(h, w);
        }
        return h.getImmutable();
    }


    public static Element ONE, TWO, THREE, FOUR, FIVE, SIX;
    public static Element f(Element x){
        Element part1 = THREE.mul(x.mul(x)).getImmutable();
        Element part2 = TWO.mul(x).getImmutable();
        Element part3 = FIVE;
        return part1.add(part2).add(part3).getImmutable();
    }


    @Override
    public void setup(){
        g = randomG();
        ONE = this.getZr().newOneElement().getImmutable();
        TWO = this.getZr().newElement(2).getImmutable();
        THREE = this.getZr().newElement(3).getImmutable();
        FOUR = this.getZr().newElement(4).getImmutable();
        FIVE = this.getZr().newElement(5).getImmutable();
        SIX = this.getZr().newElement(6).getImmutable();
    }


    private Element[] sk, pk;
    @Override
    public void keygen(){
        sk = new Element[getL()]; pk = new Element[getL()];
        for(int i = 0; i < getL(); i++){
            Element x = this.getZr().newElement(i+1).getImmutable();
            sk[i] = f(x);
            pk[i] = g.powZn(sk[i]).getImmutable();
        }
    }



    Element Q, C1, C2, pk5, K5;
    @Override
    public void enc(List<String> words){
        Element part1 = pk[0].powZn(FOUR).getImmutable();
        Element part2 = pk[1].powZn(SIX.negate()).getImmutable();
        Element part3 = pk[2].powZn(FOUR).getImmutable();
        Element part4 = pk[3].powZn(ONE.negate()).getImmutable();
        Q = part1.add(part2).add(part3).add(part4).getImmutable();

        Element s = this.getZr().newRandomElement().getImmutable();
        C1 = g.powZn(s).getImmutable();
        C2 = this.getBp().pairing(H(words), Q).powZn(s).getImmutable();
        pk5 = g.powZn(this.getZr().newElement(90)).getImmutable();
        K5 = this.getBp().pairing(H(words), pk5.powZn(s)).getImmutable();
    }



    Element[] T;
    Element D;
    @Override
    public void trap(List<String> words){
        T = new Element[sk.length];

        Element H = H(words).getImmutable();
//        System.out.println(H);
        for(int i = 0; i < T.length; i++){
//            System.out.println(sk[i]);
            T[i] = H.powZn(sk[i]).getImmutable();
        }
        D = this.getBp().pairing(C1, H).getImmutable();
    }


    boolean flag;
    Element K1, K2, K3, K;
    @Override
    public boolean search(){
        K1 = this.getBp().pairing(T[0], C1);
        K2 = this.getBp().pairing(T[1], C1);
        K3 = this.getBp().pairing(T[2], C1);

        Element part1 = D.powZn(sk[0].mul(this.getZr().newElement(15).div(FOUR))).getImmutable();
        Element part2 = D.powZn(sk[1].mul(FIVE.negate())).getImmutable();
        Element part3 = D.powZn(sk[2].mul(FIVE.div(TWO))).getImmutable();
        Element part4 = D.powZn(this.getZr().newElement(90).mul(FOUR.invert().negate())).getImmutable();

        K = part1.mul(part2).mul(part3).mul(part4);
        System.out.println("TMS K: " + K);
        System.out.println("TMS C2: " + C2);
        flag = K.isEqual(C2);
        return flag;
    }

    @Override
    public Map<String, Object> test(String word, List<String> words, int round) {
        Map<String, Object> data = super.test(word, words, round);
        data.put("flag", flag);
        data.put("left", K);
        data.put("right", C2);
        return data;
    }
}
