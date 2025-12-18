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
public class CRIMA extends PairingSystem {

    @Autowired
    public CRIMA(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }


    private Element g, msk, s, sk_svr, id_a, id_b;
    public void setup(){
        g = randomG();
        msk = randomZ();
        s = randomZ();
        sk_svr = randomZ();

        id_a = randomZ();
        id_b = randomZ();
    }


    public Element mpk, pk_svr, sk_b, pk_b;
    private Element[] sk_a, pk_a;
    public void keygen(){
        pk_svr = g.powZn(sk_svr);
        mpk = g.powZn(msk).getImmutable();

        sk_a = new Element[2];
        sk_a[0] = s;
        sk_a[1] = HashUtil.hashZr2G(g, id_a).powZn(msk).getImmutable();

        pk_a = new Element[2];
        pk_a[0] = g.powZn(s).getImmutable();
        pk_a[1] = HashUtil.hashZr2G(g, id_a).getImmutable();

        sk_b = HashUtil.hashZr2G(g, id_b).powZn(msk).getImmutable();
        pk_b = HashUtil.hashZr2G(g, id_b).getImmutable();
    }

    public Element Ci;
    @Override
    public void enc(String str){
        Element[] w = h(str);
        Element k = pairing(sk_a[1], pk_b).getImmutable();
        Element h1 = HashUtil.hashGT2GWithZrArr(this.getZr(), k, w).getImmutable();
        Element h2 = HashUtil.hashG2ZrWithZr(this.getZr(), pk_a[0], h1).getImmutable();
        Ci = pk_svr.powZn(s.mul(h2)).getImmutable();
    }


    public Element Ti;
    public void trap(String str){
        Element[] w = h(str);
        // 这个地方太奇怪了
        Element k = pairing(pk_a[1], sk_b).getImmutable();
        Ti = HashUtil.hashGT2GWithZrArr(this.getZr(), k, w).getImmutable();
    }

    boolean flag;
    Element left, right;
    @Override
    public boolean search(){
        left = Ci;
        right = pk_a[0].powZn(sk_svr.mul(HashUtil.hashG2ZrWithZr(this.getZr(), pk_a[0], Ti))).getImmutable();
        System.out.println("CR-IMA left: " + left);
        System.out.println("CR-IMA right: " + right);
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
