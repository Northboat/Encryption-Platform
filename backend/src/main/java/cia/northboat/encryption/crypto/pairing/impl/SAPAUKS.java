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
public class SAPAUKS extends PairingSystem {

    @Autowired
    public SAPAUKS(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }

    private Element g, sk_s, sk_r, sk_ss, sk_rs, sk_cs;
    @Override
    public void setup(){
        g = randomG();
        sk_s = randomZ();
        sk_r = randomZ();
        sk_ss = randomZ();
        sk_rs = randomZ();
        sk_cs = randomZ();
    }


    private Element pk_s, pk_r, pk_ss, pk_rs, pk_cs;
    @Override
    public void keygen(){
        pk_s = g.powZn(sk_s).getImmutable();
        pk_r = g.powZn(sk_r).getImmutable();
        pk_ss = g.powZn(sk_ss).getImmutable();
        pk_rs = g.powZn(sk_rs).getImmutable();
        pk_cs = g.powZn(sk_cs).getImmutable();
    }


    public Element c1, c2, c3, c_1, c_2, c_3, c_4, c_5;
    public void enc(String str){
        Element x1 = randomZ(), x2 = randomZ();
        Element[] w = h(str);

        c1 = HashUtil.hashZrArr2GWithTwoFact(pk_ss, pk_rs, w).powZn(sk_s).mul(g.powZn(x1.add(x2))).getImmutable();

//        System.out.println(c1);

        c2 = pk_rs.powZn(x1).getImmutable();
        c3 = pk_cs.powZn(x2).getImmutable();

        Element x3 = randomZ();
        c_1 = c1.powZn(sk_ss).mul(g.powZn(x3.mul(sk_ss))).getImmutable();
        c_2 = c2.powZn(sk_ss).getImmutable();
        c_3 = c3.powZn(sk_ss).mul(pk_cs.powZn(x3.mul(sk_ss))).getImmutable();
        c_4 = pk_s.powZn(sk_ss).getImmutable();
        c_5 = pk_s;

    }


    public Element t1, t2, t3, t_1, t_2, t_3, t_4, t_5;
    public void trap(String str){
        Element[] w = h(str);

        Element y1 = randomZ(), y2 = randomZ();
        t1 = HashUtil.hashZrArr2GWithTwoFact(pk_ss, pk_rs, w).powZn(sk_r).mul(g.powZn(y1.add(y2))).getImmutable();

        t2 = pk_ss.powZn(y1).getImmutable();
        t3 = pk_cs.powZn(y2).getImmutable();

        Element y3 = randomZ();
        t_1 = t1.powZn(sk_rs).mul(g.powZn(y3.mul(sk_rs))).getImmutable();
        t_2 = t2.powZn(sk_rs).getImmutable();
        t_3 = t3.powZn(sk_rs).mul(pk_cs.powZn(y3.mul(sk_rs))).getImmutable();
        t_4 = pk_r.powZn(sk_rs).getImmutable();
        t_5 = pk_r;
    }

    boolean flag;
    Element left, right;
    @Override
    public boolean search(){
        Element part1 = pairing(c_1.div(c_3.powZn(sk_cs.invert())), t_4).getImmutable();
        Element part2 = pairing(c_2, t_5).getImmutable();
        Element part3 = pairing(t_1.div(t_3.powZn(sk_cs.invert())), c_4).getImmutable();
        Element part4 = pairing(t_2, c_5).getImmutable();

        left = part1.div(part2).getImmutable();
        right = part3.div(part4).getImmutable();

        System.out.println("SA-PAUKS left: " + left);
        System.out.println("SA-PAUKS right: " + right);

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
