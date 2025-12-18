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
public class PAUKS extends PairingSystem {

    @Autowired
    public PAUKS(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp, true);
    }


    // 系统的密钥
    Element g, sk_r1, sk_r2, sk_r3, sk_r4, sk_s;
    @Override
    public void setup(){
        g = randomG();
        sk_r1 = randomZ();
        sk_r2 = randomZ();
        sk_r3 = randomZ();
        sk_r4 = randomZ();
        sk_s = randomZ();
    }

    Element pk_r1, pk_r2, pk_r3, pk_r4, pk_s;
    @Override
    public void keygen(){
        pk_r1 = g.powZn(sk_r1).getImmutable();
        pk_r2 = g.powZn(sk_r2).getImmutable();
        pk_r3 = g.powZn(sk_r3).getImmutable();
        pk_r4 = g.powZn(sk_r4).getImmutable();
        pk_s = g.powZn(sk_s).getImmutable();
    }


    public Element C1, C2, C3, C4, C5;
    public void enc(String str){
        Element r1 = randomZ(), r2 = randomZ();
        Element[] w = h(str);


        C1 = pk_r2.powZn(HashUtil.hashZrArr2Zr(this.getZr(), w)).mul(pk_r3).powZn(r1).getImmutable();


        C2 = g.powZn(r1).getImmutable();
        C3 = pk_r2.powZn(HashUtil.hashG2Zr(this.getZr(), pk_r1.powZn(sk_s)))
                .mul(pk_r3).powZn(r2)
                .mul(g.powZn(HashUtil.hashG2Zr(this.getZr(), pk_r1.powZn(sk_s)).mul(r1)))
                .getImmutable();

        C4 = HashUtil.hashZrArr2G(g, w).powZn(r2).getImmutable();
        C5 = HashUtil.hash4G(C1, C2, C3, C4).powZn(r1).getImmutable();
    }

    public Element T1, T2;
    @Override
    public void trap(String str){
        Element r3 = randomZ();
        Element[] w = h(str);

        T1 = g.powZn(r3.div(sk_r2.mul(HashUtil.hashZrArr2Zr(this.getZr(), w)).add(sk_r3))).getImmutable();
        T2 = g.powZn(r3).getImmutable();
    }

    boolean flag;
    Element left, right;
    @Override
    public boolean search(){
        System.out.println("C1: " + C1);
        System.out.println("C2: " + C2);
        System.out.println("T1: " + T1);
        System.out.println("T2: " + T2);
        left = this.getBp().pairing(C1, T1);
        right = this.getBp().pairing(C2, T2);
        System.out.println("PAUKS verify test left: " + left);
        System.out.println("PAUKS verify test right: " + right);

        flag = left.isEqual(right);
        return flag;
    }


    private Element uk_s1, uk_s2;
    @Override
    public void updateKey(){
        uk_s1 = HashUtil.hashG2Zr(this.getZr(), pk_s.powZn(sk_r1)).getImmutable();
        uk_s2 = sk_r4.div(sk_r2.mul(HashUtil.hashG2Zr(this.getZr(), pk_s.powZn(sk_r1))).add(sk_r3)).getImmutable();
    }

    public Element C6;
    public Element[] C;
    @Override
    public void reEnc(){
        C6 = C3.div(C2.powZn(uk_s1)).powZn(uk_s2).getImmutable();

        Element left = this.getBp().pairing(HashUtil.hash4G(C1, C2, C3, C4), C2);
        Element right = this.getBp().pairing(C5, g);

        if(left.isEqual(right)){
            C = new Element[5];
            C[0] = C1; C[1] = C2; C[2] = C3; C[3] = C4; C[4] = C5;
        } else {
            C = new Element[6];
            C[0] = C1; C[1] = C2; C[2] = C3; C[3] = C4; C[4] = C5; C[5] = C6;
        }

    }



    public Element T_1, T_2;
    @Override
    public void constTrap(String str){
        Element[] w = HashUtil.hashStr2ZrArr(this.getZr(), str, this.getN());
        Element r = this.getZr().newRandomElement().getImmutable();
        T_1 = g.powZn(sk_r4.mul(r)).getImmutable();
        T_2 = HashUtil.hashZrArr2G(g, w).powZn(r).getImmutable();
    }


    boolean updateFlag;
    @Override
    public boolean updateSearch(){
        Element left = this.getBp().pairing(C4, T_1);
        Element right = this.getBp().pairing(C6, T_2);
        System.out.println("PAUKS update test left: " + left);
        System.out.println("PAUKS update test right: " + right);
        updateFlag = left.isEqual(right);
        return updateFlag;
    }


    @Override
    public Map<String, Object> test(String word, List<String> words, int round) {
        Map<String, Object> data = super.test(word, words, round);
        data.put("flag", flag);
        data.put("left", left);
        data.put("right", right);
        data.put("update_flag", updateFlag);
        return data;
    }
}
