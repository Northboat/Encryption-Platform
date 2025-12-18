package cia.northboat.encryption.crypto.pairing.impl;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
import cia.northboat.encryption.utils.HashUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Component
public class SCF extends PairingSystem {

    @Autowired
    public SCF(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }

    public Element h2(String w){
        Element[] W = HashUtil.hashStr2ZrArr(this.getZr(), w, this.getN());
        return HashUtil.hashZrArr2Zr(this.getZr(), W);
    }

    public Element h3(Element gt){
        return HashUtil.hashGT2Zr(this.getZr(), gt);
    }

    public Element h4(Element gt){
        return h3(gt);
    }

    public Element h5(Element g){
        return HashUtil.hashG2Zr(this.getZr(), g);
    }

    private Element P, Q; // G群上元素
    @Override
    public void setup(){
        P = this.getG().newRandomElement().getImmutable();
        Q = this.getG().newRandomElement().getImmutable();
    }

    private Element SK_do, SK_dr;
    public Element PK_do, PK_dr;
    @Override
    public void keygen(){
        Element a = this.getZr().newRandomElement().getImmutable(), b = this.getZr().newRandomElement().getImmutable();
        SK_do = a; PK_do = P.mulZn(a).getImmutable();
        SK_dr = b; PK_dr = P.mulZn(b).getImmutable();
    }



    public Element t, eh, uh, CV, v;
    @Override
    public void enc(String w){
        t = this.getZr().newRandomElement().getImmutable();
        eh = h3(this.getBp().pairing(PK_dr.mulZn(SK_do), Q.mulZn(h2(w)).powZn(t))).getImmutable();
        uh = h4(this.getBp().pairing(PK_dr.mulZn(SK_do), Q.mulZn(h2(w)).powZn(t))).getImmutable();
        Element l = this.getZr().newRandomElement().getImmutable();
        CV = h5(PK_dr.mulZn(l)).getImmutable();
        v = h5(P.mulZn(l).mulZn(SK_dr)).getImmutable();
    }

    public long[] hashTimeCost(){
        Element l = randomZ();

        long s1 = System.currentTimeMillis();
        CV = h5(PK_dr.mulZn(l)).getImmutable();
        long e1 = System.currentTimeMillis();

        long s2 = System.currentTimeMillis();
        v = h5(P.mulZn(l).mulZn(SK_dr)).getImmutable();
        long e2 = System.currentTimeMillis();

        return new long[]{e1-s1, e2-s2};
    }


    public Element T;
    @Override
    public void trap(String w){
        T = Q.mulZn(h2(w)).mulZn(SK_dr).mulZn(t).powZn(t).getImmutable();
    }


    boolean flag;
    Element left, right;
    @Override
    public boolean search(){
        Element pairing = this.getBp().pairing(PK_do, T);
        System.out.println("SCF Pairing: " + pairing);
        left = h3(pairing);
        right = h4(pairing);

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

    @Override
    public List<Long> test(List<String> words, int sender, int receiver, int round){
        long t1 = 0, t2 = 0, t3 = 0;
        for(int i = 0; i < round; i++){
            setup();
            keygen();
            for(String word: words){
                long s1 = System.currentTimeMillis();
                for(int j = 0; j < sender * receiver; j++)
                    enc(word);
                long e1 = System.currentTimeMillis();
                t1 += e1-s1;

                long s2 = System.currentTimeMillis();
                for(int j = 0; j < receiver * sender; j++)
                    trap(word);
                long e2 = System.currentTimeMillis();
                t2 += e2-s2;

                long s3 = System.currentTimeMillis();
                for(int j = 0; j < receiver * sender; j++)
                    System.out.println(search());
                long e3 = System.currentTimeMillis();
                t3 += e3-s3;
            }
        }

        return Arrays.asList(t1/round, t2/round, t3/round);
    }
}
