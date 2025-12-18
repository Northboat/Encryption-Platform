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
public class TBEKS extends PairingSystem {

    Element g, h;
    @Autowired
    public TBEKS(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }

    // MSK
    Element r, d, s, v, alpha, ONE, TWO, THREE, FOUR, FIVE;
    @Override
    public void setup(){
        g = randomG();
        h = randomG();

        r = this.getZr().newElement(5).getImmutable();
        d = this.getZr().newElement(4).getImmutable();
        v = this.getZr().newElement(6).getImmutable();
        s = this.getZr().newRandomElement().getImmutable();
        alpha = this.getZr().newRandomElement().getImmutable();

        ONE = this.getZr().newOneElement().getImmutable();
        TWO = this.getZr().newElement(2).getImmutable();
        THREE = this.getZr().newElement(3).getImmutable();
        FOUR = this.getZr().newElement(4).getImmutable();
        FIVE = this.getZr().newElement(5).getImmutable();
    }


    public Element f1(Element x){
        return FIVE.add(TWO.mul(x)).add(THREE.mul(x.mul(x))).getImmutable();
    }
    public Element f2(Element x){
        return FOUR.add(x).add(TWO.mul(x.mul(x))).getImmutable();
    }

    public Element H(String word){
        Element[] w = HashUtil.hashStr2ZrArr(this.getZr(), word, this.getN());
        return HashUtil.hashZrArr2Zr(this.getZr(), w);
    }

    private Element u, w1, w2;
    private Element[] R, D;
    @Override
    public void keygen(){
        u = s.div(d).getImmutable();
        w1 = g.powZn(r.div(d)).getImmutable();
        w2 = g.powZn(r.mul(u)).getImmutable();

        R = new Element[getK()]; D = new Element[getK()];
        for(int i = 0; i < getK(); i++){
            Element x = this.getZr().newElement(i+1).getImmutable();
            R[i] = f1(x);
            D[i] = f2(x);
        }
    }


    // l: 关键词数量
    public Element I0, I1;
    public Element[] I;
    @Override
    public void enc(List<String> words){
        int l = words.size();
        I0 = h.powZn(alpha.negate()).getImmutable();
        I1 = w1.powZn(alpha).getImmutable();

        I = new Element[l];
        for(int i = 0; i < l; i++){
            I[i] = w2.powZn(alpha.mul(H(words.get(i)))).getImmutable();
        }
    }



    public Element A, B, T1, T2;
    public Element[] lambda, mu;
    @Override
    public void trap(List<String> words){
        Element beta = this.getZr().newRandomElement().getImmutable();
        Element sum = this.getZr().newZeroElement();
        for(String w: words){
            sum.add(H(w));
        }
        sum.getImmutable();

        A = g.powZn(beta).getImmutable();
        B = h.powZn(u.mul(sum).add(beta)).getImmutable();

        // 固定为 3 个用户
        lambda = new Element[3]; mu = new Element[3];
        Element a = null;
        T1 = this.getG().newOneElement();
        T2 = this.getG().newOneElement();
        for(int i = 0; i < 3; i++){
            switch (i) {
                case 0 -> a = THREE;
                case 1 -> a = THREE.negate();
                case 2 -> a = ONE;
            }
            lambda[i] = A.powZn(R[i].mul(a)).getImmutable();
            mu[i] = B.powZn(D[i].mul(a)).getImmutable();
            T1.mul(lambda[i]);
            T2.mul(mu[i]);
        }
        T1.getImmutable();
        T2.getImmutable();
    }

    boolean flag;
    Element left, right;
    @Override
    public boolean search(){
        Element part1 = pairing(I0, T1);
        Element part2 = pairing(I1, T2);

        Element product = this.getG().newOneElement();
        for(Element i: I){
            product.mul(i);
        }
        product = product.getImmutable();
//        System.out.println(product);
        Element part3 = pairing(product, h);

        left = part1.mul(part2).getImmutable();
        right = part3.getImmutable();

        System.out.println("TBEKS Left: " + left);
        System.out.println("TBEKS Right: " + right);

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
