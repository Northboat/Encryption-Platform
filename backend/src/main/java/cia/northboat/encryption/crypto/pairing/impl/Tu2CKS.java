package cia.northboat.encryption.crypto.pairing.impl;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
import cia.northboat.encryption.utils.AESUtil;
import cia.northboat.encryption.utils.BitUtil;
import cia.northboat.encryption.utils.HashUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

@Component
public class Tu2CKS extends PairingSystem {
    @Autowired
    public Tu2CKS(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }
    private Element H(String str){
        return HashUtil.hashZrArr2Zr(this.getZr(), HashUtil.hashStr2ZrArr(this.getZr(), str, this.getN())).getImmutable();
    }

    private Element H1(Element e){
        return HashUtil.hashZr2G(g, e).getImmutable();
    }

    private Element H2(Element e){
        return HashUtil.hashG2Zr(this.getZr(), e).getImmutable();
    }

    private Element f(Element x){
        Element res = t.duplicate();
        // fi 一共 k-1 长，最后一轮 x 的指数将是 k-2+1 = k-1 次，正确的
        for(int i = 0; i < getK()-1; i++){
            Element e = x.duplicate();
            e.pow(new BigInteger(String.valueOf(i+1)));
            res.add(fi[i].mul(e));
        }
        return res;
    }


    Element g, g1, g2, h, t, a, alpha, beta, lambda, r2, sk_c, pk_c, sk_kgc, pk_kgc, ZERO, ONE, TWO, THREE;
    Element[] sk_p, pk_p, fi, id;
    private static byte[] k1, k2;
    public void setup() {

        g = randomG();
        Element x1 = randomZ();
        Element x2 = randomZ();
        t = randomZ();
        a = randomZ();
        alpha = randomZ();
        beta = randomZ();
        lambda = randomZ();
        Element id_p = randomZ();

        g1 = g.powZn(x1).getImmutable();
        g2 = g.powZn(x2).getImmutable();
//        Element Y = pairing(g, g).powZn(beta).getImmutable();

        r2 = H2(g.powZn(x1.mul(x2)));

        sk_c = randomZ();
        pk_c = g.powZn(sk_c).getImmutable();

        sk_p = new Element[2];
        sk_p[0] = randomZ();
        sk_p[1] = H1(id_p).powZn(alpha).getImmutable();

        System.out.println("sk_p[0]: " + sk_p[0]);


        pk_p = new Element[2];
        pk_p[0] = g.powZn(sk_p[0]).getImmutable();
        pk_p[1] = H1(id_p).getImmutable();

        System.out.println("g^y: " + g.powZn(sk_p[0]));
        System.out.println("pk_p[0]: " + pk_p[0]);

        Element id_kgc = randomZ();
        sk_kgc = H1(id_kgc).powZn(alpha).getImmutable();
        pk_kgc = H1(id_kgc).getImmutable();

        fi = new Element[getK()-1];
        fi[0] = randomZ();
        fi[1] = randomZ();

        id = new Element[3];
        id[0] = this.getZr().newElement(123).getImmutable();
        id[1] = this.getZr().newElement(456).getImmutable();
        id[2] = this.getZr().newElement(789).getImmutable();

        ZERO = this.getZr().newZeroElement().getImmutable();
        ONE = this.getZr().newOneElement().getImmutable();
        TWO = this.getZr().newElement(2).getImmutable();
        THREE = this.getZr().newElement(3).getImmutable();

        // AES 密钥
        k1 = AESUtil.getRandomKey();
        k2 = AESUtil.getRandomKey();
    }


    public Element aes(Element id){
        try{
            byte[] theta = this.getZr().newRandomElement().toBytes();
            byte[] zeta = AESUtil.enc(id.toBytes(), k1);
            return this.getZr().newElementFromBytes(AESUtil.enc(BitUtil.connect(zeta, theta), k2)).getImmutable();
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public Element delta(Element[] t, int i){
        Element delta = this.getZr().newOneElement();
        for(int j = 0; j < t.length; j++){
            if(j != i){
                Element e = t[j].negate().div(t[i].sub(t[j]));
                delta.mul(e);
            }
        }
        return delta.getImmutable();
    }


    public void keygen(Element[] sk, Element[] pk, Element[] id, Element[] delta,
                              Element[] r, Element[] mu, Element[] t, int i){
        sk[0] = g.powZn(beta.sub(a.mul(r[i])).div(lambda.add(delta[i]))).getImmutable();
        sk[1] = delta[i].getImmutable();
        sk[2] = g.powZn(r[i]).getImmutable();
        sk[3] = H1(id[i]).powZn(alpha).getImmutable();

        sk[4] = mu[i].getImmutable();
        sk[5] = r2.mul(f(t[i]).mul(delta(t, i))).getImmutable();

        pk[0] = H1(id[i]).getImmutable();
        pk[1] = g.powZn(mu[i]).getImmutable();
    }


    private Element[] sk_u1, sk_u2, sk_u3, pk_u1, pk_u2, pk_u3;
    public void keygen(){

        Element[] delta = new Element[getK()];
        Element[] r = new Element[getK()];
        Element[] mu = new Element[getK()];
        Element[] t = new Element[getK()];
        for(int i = 0; i < getK(); i++){
            t[i] = randomZ();
            mu[i] = randomZ();
            r[i] = randomZ();
            delta[i] = aes(id[i]);
        }
        sk_u1 = new Element[6]; sk_u2 = new Element[6]; sk_u3 = new Element[6];
        pk_u1 = new Element[2]; pk_u2 = new Element[2]; pk_u3 = new Element[6];

        keygen(sk_u1, pk_u1, id, delta, r, mu, t, 0);
        keygen(sk_u2, pk_u2, id, delta, r, mu, t, 1);
        keygen(sk_u3, pk_u3, id, delta, r, mu, t, 2);
    }




    public Element C1, C2, r1;
    public Element[] B;
    @Override
    public void enc(String w){

        r1 = randomZ();
        C1 = g2.powZn(t.mul(r2)).getImmutable();
        C2 = pairing(g, g).powZn(r1.negate()).getImmutable();


        B = new Element[4];
        B[0] = g.powZn(r1.mul(this.getZr().newElement(-5))).getImmutable();
        B[1] = g.powZn(r1.mul(this.getZr().newElement(11))).getImmutable();
        B[2] = g.powZn(r1.mul(this.getZr().newElement(-6))).getImmutable();
        B[3] = g.powZn(r1.mul(this.getZr().newElement(1))).getImmutable();
    }

    public Element[] T1_u1, T1_u2, T1_u3;
    public Element T2_u1, T3_u1, T2_u2, T3_u2, T2_u3, T3_u3;
    public Element[] usrTrap(Element HW, Element[] T1, Element[] sk){
        Element p = pk_p[0].powZn(sk[4]).getImmutable();

        T1[0] = g.powZn(HW.powZn(ZERO)).mul(p).getImmutable();
        T1[1] = g.powZn(HW.powZn(ONE)).mul(p).getImmutable();
        T1[2] = g.powZn(HW.powZn(TWO)).mul(p).getImmutable();
        T1[3] = g.powZn(HW.powZn(THREE)).mul(p).getImmutable();

        Element[] R = new Element[2];
        // 返回 T2
        R[0] = pairing(g1, g2).powZn(sk[5]).mul(pairing(sk[3], pk_p[1])).getImmutable();
        // 返回 T3
        R[1] = pairing(sk[3], pk_kgc).getImmutable();
        return R;
    }

    public void usrTrap(){
        Element[] R;

        // USR1
        Element HW1 = ONE;
        T1_u1 = new Element[4];
        R = usrTrap(HW1, T1_u1, sk_u1);
        T2_u1 = R[0];
        T3_u1 = R[1];

        // USR2
        Element HW2 = TWO;
        T1_u2 = new Element[4];
        R = usrTrap(HW2, T1_u2, sk_u2);
        T2_u2 = R[0];
        T3_u2 = R[1];

        Element HW3 = THREE;
        T1_u3 = new Element[4];
        R = usrTrap(HW3, T1_u3, sk_u3);
        T2_u3 = R[0];
        T3_u3 = R[1];
    }


    public static Element T1, T3;
    public static Element[] T_Q;
    @Override
    public void trap(String t){
        usrTrap();

        Element s = randomZ();
        T1 = g1.powZn(s).getImmutable();


        Element p1 = pk_u1[1].powZn(sk_p[0]).getImmutable();
        Element p2 = pk_u2[1].powZn(sk_p[0]).getImmutable();
        Element p3 = pk_u3[1].powZn(sk_p[0]).getImmutable();
        Element p4 = pk_c.powZn(sk_p[0]).getImmutable();


        T_Q = new Element[4];
        for(int i = 0; i < 4; i++){
            Element e1 = T1_u1[i].div(p1);
            Element e2 = T1_u2[i].div(p2);
            Element e3 = T1_u3[i].div(p3);
            T_Q[i] = e1.mul(e2).mul(e3).mul(p4).getImmutable();
        }


        Element p5 = T2_u1.div(pairing(pk_u1[0], sk_p[1])).getImmutable();
        Element p6 = T2_u2.div(pairing(pk_u2[0], sk_p[1])).getImmutable();

        Element p7 = T2_u3.div(pairing(pk_u3[0], sk_p[1])).getImmutable();
        T3 = (p5.mul(p6).mul(p7)).powZn(s).getImmutable();
    }

    boolean flag;
    Element left, right;
    @Override
    public boolean search(){

        Element m = this.getZr().newElement(3).getImmutable();
        Element inv = m.invert().getImmutable();
        Element e = pk_p[0].powZn(sk_c).getImmutable();

        Element p1 = pairing(C1, T1).getImmutable();
        Element p2 = pairing(B[0], T_Q[0].div(e).powZn(inv)).getImmutable();
        Element p3 = pairing(B[1], T_Q[1].div(e).powZn(inv)).getImmutable();
        Element p4 = pairing(B[2], T_Q[2].div(e).powZn(inv)).getImmutable();
        Element p5 = pairing(B[3], T_Q[3].div(e).powZn(inv)).getImmutable();


        Element p6 = C2.mul(p2).mul(p3).mul(p4).mul(p5).getImmutable();

        left = p1.mul(p6).getImmutable();
        right = T3;


        System.out.println(p6);
        System.out.println(left);
        System.out.println(right);

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
