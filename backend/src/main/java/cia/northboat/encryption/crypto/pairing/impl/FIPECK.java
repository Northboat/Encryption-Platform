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
public class FIPECK extends PairingSystem {

    @Autowired
    public FIPECK(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }

    public Element H1(Element gt){
        return HashUtil.hashGT2Zr(this.getZr(), gt);
    }

    public Element H2(String str){
        Element[] w = HashUtil.hashStr2ZrArr(this.getZr(), str, this.getN());
        return HashUtil.hashZrArr2Zr(this.getZr(), w);
    }

    public Element H3(String str){
        Element[] w = HashUtil.hashStr2ZrArr(this.getZr(), str, this.getN());
        return HashUtil.hashZrArr2G(g, w);
    }

    Element g, sk_s, sk_r, x, pk_r, X, pk_s, V, K;

    @Override
    public void setup(){
        g = this.getG().newRandomElement().getImmutable();
        sk_s = this.getZr().newRandomElement().getImmutable();
        V = this.getG().newRandomElement().getImmutable();
        pk_s = g.powZn(sk_s).getImmutable();

        sk_r = this.getZr().newRandomElement().getImmutable();
        pk_r = g.powZn(sk_r).getImmutable();

        x = this.getZr().newRandomElement().getImmutable();
        X = g.powZn(x).getImmutable();
    }


    final String rou = "user";

    @Override
    public void keygen(){
        Element p = H3(rou);
        Element r = this.getZr().newRandomElement().getImmutable();
        Element k = this.getGT().newRandomElement().getImmutable();

        Element EK = k.mul(this.getBp().pairing(pk_s, p).powZn(r)).getImmutable();
        Element pi = this.getBp().pairing(g.powZn(sk_s.mul(sk_r).mul(r)), p).getImmutable();

        K = EK.div(pi.powZn(sk_r.invert())).getImmutable();
    }

    public Element t, C1, C2, C3;
    @Override
    public void enc(String W){
        Element r = this.getZr().newRandomElement().getImmutable(), s = this.getZr().newRandomElement().getImmutable();
        C1 = pk_r.powZn(r).getImmutable();
        t = this.getBp().pairing(X, V).powZn(s).getImmutable();
        C2 = H1(this.getBp().pairing(g, g.powZn(H2(W))).powZn(r).mul(t));
        C3 = g.powZn(s).getImmutable();
    }

    public Element T1, T2;
    @Override
    public void trap(String W){
        Element pi = this.getZr().newRandomElement().getImmutable();
        T1 = g.powZn(H2(W)).powZn(sk_r.invert()).mul(X.powZn(pi)).getImmutable();
        T2 = g.powZn(pi).getImmutable();
    }

    boolean flag;
    Element left, right;
    @Override
    public boolean search(){
        left = H1(this.getBp().pairing(C1, T1.div(T2.powZn(x))).mul(t));
        right = C2;
        System.out.println("left: " + left);
        System.out.println("right: " + right);
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
