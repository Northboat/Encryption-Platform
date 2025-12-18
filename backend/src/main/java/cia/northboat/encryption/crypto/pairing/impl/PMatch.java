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
public class PMatch extends PairingSystem {


    @Autowired
    public PMatch(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }

    public Element f(Element x){
        return x1.add(f1.mul(x)).getImmutable();
    }


    private Element g, x1, x2, f1, t, t_i;
    @Override
    public void setup(){
        g = this.getG().newRandomElement().getImmutable();
        x1 = this.getZr().newRandomElement().getImmutable();
        x2 = this.getZr().newRandomElement().getImmutable();
        f1 = this.getZr().newRandomElement().getImmutable();
        t = this.getZr().newRandomElement().getImmutable();
        t_i = this.getZr().newRandomElement().getImmutable();
    }


    public Element g1, g2, EK, D_i, E_i;
    @Override
    public void keygen(){
        g1 = g.powZn(x1).getImmutable();
        g2 = g.powZn(x2).getImmutable();
        EK = g.powZn(f(t).div(x1)).getImmutable();

        Element t1 = t.negate().div(t_i.sub(t)).getImmutable();
        Element t2 = t_i.negate().div(t.sub(t_i)).getImmutable();
        D_i = g2.powZn(f(t_i).mul(t1)).getImmutable();
        E_i = g2.powZn(x1.mul(t2)).getImmutable();
    }


    public Element C1, C2, C3, C4;
    @Override
    public void enc(String str){
        Element[] w = h(str);
        Element r1 = randomZ(), r2 = randomZ();
        C1 = g2.powZn(r2).mul(HashUtil.hashZrArr2G(g, w).powZn(r1)).getImmutable();
        C2 = g1.powZn(r1).getImmutable();
        C3 = EK.powZn(r2).getImmutable();
        C4 = g.powZn(r2).getImmutable();
    }


    public Element T1, T2, T3, T4;
    public void trap(String str){
        Element[] w = h(str);
        Element s = randomZ();
        T1 = g1.powZn(s);
        T2 = HashUtil.hashZrArr2G(g, w).powZn(s).getImmutable();
        T3 = E_i.powZn(s).getImmutable();
        T4 = D_i.powZn(s).getImmutable();
    }


    boolean flag;
    Element left, right;
    @Override
    public boolean search(){
        left = pairing(C1, T1);
        Element p1 = pairing(C2, T2);
        Element p2 = pairing(C3, T3);
        Element p3 = pairing(C4, T4);

        right = p1.mul(p2).mul(p3).getImmutable();
        System.out.println("pMatch left: " + left);
        System.out.println("pMatch right: " + right);
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
