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
public class PREKS extends PairingSystem {

    @Autowired
    public PREKS(Field G1, Field GT, Field Zr, Pairing bp) {
        super(G1, GT, Zr, bp);
    }

    public Element H1(String str){
        return HashUtil.hashZrArr2G(g, h(str));
    }

    public Element H2(Element gt){
        return HashUtil.hashGT2G(getG(), gt);
    }

    Element g, h, sk1, pk1, sk2, pk2;
    @Override
    public void setup() {
        g = randomG();
        h = randomG();
        reEncCost = 0;
    }

    @Override
    public void keygen() {
        sk1 = randomZ();
        pk1 = g.powZn(sk1).getImmutable();

        sk2 = randomZ();
        pk2 = g.powZn(sk2).getImmutable();
    }


    String A;
    Element B, C, D, E, F;
    @Override
    public void enc(String w) {
        Element r = randomZ();
        Element m = randomGT();
        A = randomNum();
        B = pk1.powZn(r).getImmutable();
        C = pairing(g, H1(A)).powZn(r).mul(m).getImmutable();
        D = H1(A).powZn(r).getImmutable();
        E = h.powZn(r).getImmutable();

        Element t = pairing(g, H1(w)).powZn(r).getImmutable();
        F = H2(t);
    }

    Element T_w;
    @Override
    public void trap(String q) {
        T_w = H1(q).powZn(sk1.invert()).getImmutable();
    }

    Element B1;
    @Override
    public void reEnc(){
        pairing(B, H1(A)).isEqual(pairing(pk1, D));
        pairing(B, h).isEqual(pairing(pk1, E));

        B1 = B.powZn(sk2.div(sk1)).getImmutable();
    }

    long reEncCost;
    boolean flag;
    Element left, right;
    @Override
    public boolean search() {
        long s = System.currentTimeMillis();
        reEnc();
        reEncCost += System.currentTimeMillis() - s;

        left = F.getImmutable();
        right = H2(pairing(B, T_w)).getImmutable();
        System.out.println("left: " + left);
        System.out.println("right: " + right);
        flag = left.isEqual(right);
        return flag;
    }

    @Override
    public Map<String, Object> test(String word, List<String> words, int round){
        Map<String, Object> data = super.test(word, words, round);
        data.put("flag", flag);
        data.put("ReEncCost", reEncCost);
        data.put("g", g);
        data.put("pk1", pk1);
        data.put("C", C);
        data.put("T_w", T_w);
        data.put("left", left);
        data.put("right", right);
        return data;
    }
}
