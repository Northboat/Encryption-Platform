package cia.northboat.encryption.crypto.pairing.impl;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
import cia.northboat.encryption.utils.HashUtil;
import cia.northboat.encryption.utils.PolynomialUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;


@Component
public class PECKS extends PairingSystem {

    @Autowired
    public PECKS(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }

    public Element H(String str){
        Element[] w = h(str);
        return HashUtil.hashZrArr2Zr(this.getZr(), w);
    }


    private Element g, g1, g2, EK, sk_cs, sk_ts, pk_cs, pk_ts, x_t, b1, a1, b2;
    @Override
    public void setup(){
        g = this.getG().newRandomElement().getImmutable();
        a1 = this.getZr().newRandomElement().getImmutable();
        b1 = this.getZr().newRandomElement().getImmutable();
        b2 = this.getZr().newRandomElement().getImmutable();
        x_t = this.getZr().newRandomElement().getImmutable();
        sk_cs = this.getZr().newRandomElement().getImmutable();
        sk_ts = this.getZr().newRandomElement().getImmutable();

        g1 = g.powZn(b1).getImmutable();
        g2 = g.powZn(b2).getImmutable();
        EK = g.powZn(f(x_t).div(b1)).getImmutable();
        pk_cs = g.powZn(sk_cs).getImmutable();
        pk_ts = g.powZn(sk_ts).getImmutable();
    }

    public Element f(Element x){
        return b1.add(a1.mul(x)).getImmutable();
    }

    Element D_i, E_i, F_i, G_i, PK_i;
    @Override
    public void keygen(){
        Element x_ti = this.getZr().newRandomElement().getImmutable();
        Element y_i = this.getZr().newRandomElement().getImmutable();

        D_i = g2.powZn(f(x_ti).mul(x_t.negate().div(x_ti.sub(x_t)))).getImmutable();
        E_i = g2.powZn(b1.mul(x_ti.negate().div(x_t.sub(x_ti)))).getImmutable();
        G_i = y_i.getImmutable();
        PK_i = g.powZn(y_i).getImmutable();
    }

    Element[] C1;
    Element C2, C3;
    int l;
    @Override
    public void enc(List<String> W) {
        Element r = this.getZr().newRandomElement().getImmutable();
        C2 = EK.powZn(r).getImmutable();
        C3 = g.powZn(r).getImmutable();


        l = W.size();

        List<Element> factors = new ArrayList<>(l);
        for(int i = 0; i < l; i++){
            factors.add(H(W.get(i)));
        }
//        System.out.println("function params: " + factors);

        List<Element> pi = PolynomialUtil.getCoefficients(this.getZr(), factors);
        pi.set(0, pi.get(0).add(this.getZr().newOneElement()).getImmutable());
//        System.out.println("polynomial coefficients: " + pi);

        C1 = new Element[l+1];
        for(int i = 0; i <= l; i++){
            C1[i] = g1.powZn(r.mul(pi.get(i))).getImmutable();
        }
    }


    Element[] T1;
    Element T2, T3, T4;
    @Override
    public void trap(List<String> Q) {
        Element s = this.getZr().newRandomElement().getImmutable(), pi = this.getZr().newRandomElement().getImmutable();
        T2 = E_i.powZn(s).getImmutable();
        T3 = D_i.powZn(s).getImmutable();
        T4 = g.powZn(pi).getImmutable();

        if(Q.size() > l){
            return;
        }

        T1 = new Element[l+1];
        Element m = this.getZr().newElement(Q.size()).getImmutable();

        for(int i = 0; i <= l; i++){
            Element sum = this.getZr().newZeroElement();
            Element fai = this.getZr().newElement(i).getImmutable();

            for (String str: Q) {
                sum.add(H(str).powZn(fai));
            }
            sum.getImmutable();

            T1[i] = g2.powZn(s.mul(m.invert()).mul(sum)).mul(pk_cs.powZn(pi)).getImmutable();
        }
    }

    boolean flag;
    Element left, right;
    @Override
    public boolean search() {
        left = this.getGT().newOneElement();
        for(int i = 0; i <= l; i++){
            Element cur = this.getBp().pairing(C1[i], T1[i].div(T4.powZn(sk_cs)));
            left.mul(cur);
        }
        left.getImmutable();

        right = this.getBp().pairing(C2, T2).mul(this.getBp().pairing(C3, T3)).getImmutable();

        System.out.println("PECKS Left: " + left);
        System.out.println("PECKS Right: " + right);

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

            Long s1 = System.currentTimeMillis();
            for(int j = 0; j < sender; j++)
                enc(words);
            Long e1 = System.currentTimeMillis();
            t1 += e1-s1;

            Long s2 = System.currentTimeMillis();
            for(int j = 0; j < receiver; j++)
                trap(words);
            Long e2 = System.currentTimeMillis();
            t2 += e2-s2;

            Long s3 = System.currentTimeMillis();
            for(int j = 0; j < receiver * sender; j++)
                System.out.println(search());
            Long e3 = System.currentTimeMillis();
            t3 += e3-s3;
        }
        return Arrays.asList(t1/round, t2/round, t3/round);
    }
}
