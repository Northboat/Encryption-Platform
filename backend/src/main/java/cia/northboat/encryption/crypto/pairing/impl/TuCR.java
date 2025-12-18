package cia.northboat.encryption.crypto.pairing.impl;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
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
public class TuCR extends PairingSystem {

    @Autowired
    public TuCR(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }

    public Element f(Element x){
        Element res = v.duplicate();
        // fi 一共 k-1 长，最后一轮 x 的指数将是 k-2+1 = k-1 次，正确的
        for(int i = 0; i < fi.length; i++){
            Element e = x.duplicate();
            e.pow(new BigInteger(String.valueOf(i+1)));
            res.add(fi[i].mul(e));
        }
        return res.getImmutable();
    }

    public Element H(String str){
        Element[] w = h(str);
        return HashUtil.hashZrArr2G(g, w).getImmutable();
    }

    public Element H1(Element r){
        return HashUtil.hashZr2G(g, r).getImmutable();
    }

    public Element H2(Element gt){
        return HashUtil.hashGT2G(this.getZr(), gt).getImmutable();
    }


    public Element g, g1, g2, sk_svr, pk_svr, sk_f, pk_f, alpha, v, m;
    Element[] id;
    private static Element[] fi, p_u;
    public void setup(){
        g = randomG();
        Element x1 = randomZ();
        Element x2 = randomZ();
        alpha = randomZ();


        g1 = g.powZn(x1).getImmutable();
        g2 = g.powZn(x2).getImmutable();

        sk_svr = randomZ();
        pk_svr = g.powZn(sk_svr).getImmutable();
        sk_f = randomZ();
        pk_f = g.powZn(sk_f).getImmutable();

        fi = new Element[2];
        fi[0] = this.getZr().newElement(11).getImmutable();
        fi[1] = this.getZr().newElement(13).getImmutable();

        m = this.getZr().newElement(3).getImmutable();
        v = this.getZr().newElement(7).getImmutable();

        p_u = new Element[3];
        p_u[0] = this.getZr().newElement(2).getImmutable();
        p_u[1] = this.getZr().newElement(3).getImmutable();
        p_u[2] = this.getZr().newElement(5).getImmutable();

        id = new Element[3];
        id[0] = this.getZr().newElement(123).getImmutable();
        id[1] = this.getZr().newElement(456).getImmutable();
        id[2] = this.getZr().newElement(789).getImmutable();
    }


    public Element delta(Element t_u1, Element t_u2){
        return t_u2.negate().div(t_u1.sub(t_u2)).getImmutable();
    }

    public void keygen(Element id, Element[] S, Element[] P, int i,
                              Element t_u1, Element t_u2, Element t_u3){

        Element mu = randomZ();
        S[0] = H1(id).powZn(alpha).getImmutable();
        S[1] = f(t_u1).mul(delta(t_u1, t_u2)).mul(delta(t_u1, t_u3)).getImmutable();
        S[2] = mu.getImmutable();

        P[0] = H1(id).getImmutable();
        P[1] = p_u[i].getImmutable();
        P[2] = g.powZn(mu).getImmutable();
    }


    private Element[] S_u1, S_u2, S_u3, t_u, P_u1, P_u2, P_u3;
    @Override
    public void keygen(){
        S_u1 = new Element[3]; S_u2 = new Element[3]; S_u3 = new Element[3];
        P_u1 = new Element[3]; P_u2 = new Element[3]; P_u3 = new Element[3];
        t_u = new Element[3];
        t_u[0] = randomZ();
        t_u[1] = randomZ();
        t_u[2] = randomZ();

        keygen(id[0], S_u1, P_u1, 0, t_u[0], t_u[1], t_u[2]);
        keygen(id[1], S_u2, P_u2, 1, t_u[1], t_u[0], t_u[2]);
        keygen(id[2], S_u3, P_u3, 2, t_u[2], t_u[0], t_u[1]);
    }


    public Element[] C;
    @Override
    public void enc(String str){

        Element HW = H(str);

        Element r1 = randomZ();
        Element r2 = randomZ();

        System.out.println(r1);
        System.out.println(HW.powZn(r1));

        C = new Element[4];
        C[0] = g2.powZn(r2).mul(HW.powZn(r1)).getImmutable();
        C[1] = g2.powZn(v).mul(HW.powZn(r1)).getImmutable();
        C[2] = g1.powZn(r1).getImmutable();
        C[3] = g2.powZn(r2).getImmutable();
    }


    public Element[] T;
    @Override
    public void trap(String str){
        Element HQ = H(str).getImmutable();

        System.out.println(HQ);

        Element s = randomZ();

        System.out.println(s);
        System.out.println(HQ.powZn(s).getImmutable());

        T = new Element[3];
        T[0] = g1.powZn(s).getImmutable();
        T[1] = HQ.powZn(s).mul(pk_svr.powZn(S_u1[2])).getImmutable();
        T[2] = pairing(g1, g2).powZn(s).getImmutable();
    }

    boolean flag;
    Element left, right;
    @Override
    public boolean search(){
        left = pairing(C[0], T[0]).getImmutable();

        Element p1 = pairing(C[2], T[1].div(P_u1[2].powZn(sk_svr))).getImmutable();
        Element p2 = pairing(T[0], C[3]).getImmutable();
        right = p1.mul(p2).getImmutable();

        System.out.println(p1);
        System.out.println(p2);

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


    public Element N, C_id;
    public Element[] N_u, N_inv, C_id_su;
    public void usrAuth() throws Exception{
        System.out.println("=========== Usr Authenticate ===========");

        N = this.getZr().newOneElement();
        for(Element p: p_u){
            N.mul(p);
        }
        N = N.getImmutable();

        N_u = new Element[3]; N_inv = new Element[3];

        N_u[0] = N.div(p_u[0]).getImmutable();
        // 求在特定模数下的逆
        N_inv[0] = HashUtil.getInvModP(this.getZr(), N_u[0], p_u[0]);
        N_u[1] = N.div(p_u[1]).getImmutable();
        N_inv[1] = HashUtil.getInvModP(this.getZr(), N_u[1], p_u[1]);
        N_u[2] = N.div(p_u[2]).getImmutable();
        N_inv[2] = HashUtil.getInvModP(this.getZr(), N_u[2], p_u[2]);

        for(int i = 0; i < 3; i++){
            System.out.print(N_u[i] + " ");
            System.out.println(N_inv[i]);
        }

        C_id_su = new Element[3];
        Element e1 = H2(pairing(S_u3[0], P_u1[0])).getImmutable();
        Element e2 = H2(pairing(S_u3[0], P_u2[0])).getImmutable();
        Element e3 = H2(pairing(S_u3[0], P_u3[0])).getImmutable();

        C_id_su[0] = HashUtil.getInvModP(this.getZr(), e1, P_u1[1]).getImmutable();
        C_id_su[1] = HashUtil.getInvModP(this.getZr(), e2, P_u2[1]).getImmutable();
        C_id_su[2] = HashUtil.getInvModP(this.getZr(), e3, P_u3[1]).getImmutable();


        C_id = this.getZr().newZeroElement();
        for(int i = 0; i < 3; i++){
            Element e = C_id_su[i].mul(N_u[i]).mul(N_inv[i]).getImmutable();
            C_id.add(e);
        }
        C_id = HashUtil.getInvModP(this.getZr(), C_id, N).getImmutable();

        System.out.println(e1 + " % " + P_u1[1] + " = " + C_id_su[0]);
        System.out.println(e2 + " % " + P_u2[1] + " = " + C_id_su[1]);
        System.out.println(e3 + " % " + P_u3[1] + " = " + C_id_su[2]);
        System.out.println(N);
        System.out.println(C_id);

    }


    public static Element[] C_id_u;
    public void usrAuthorize(){
        C_id_u = new Element[3];
        C_id_u[0] = HashUtil.getInvModP(this.getZr(), H2(pairing(P_u3[0], S_u1[0])), P_u1[1]).getImmutable();
        C_id_u[1] = HashUtil.getInvModP(this.getZr(), H2(pairing(P_u3[0], S_u2[0])), P_u2[1]).getImmutable();
        C_id_u[2] = HashUtil.getInvModP(this.getZr(), H2(pairing(P_u3[0], S_u3[0])), P_u3[1]).getImmutable();
    }

    public boolean usrIDMatch(){
        System.out.println("========= User Identity Match =========");
        Element left1 = C_id_su[0];
        Element right1 = HashUtil.getInvModP(this.getZr(), C_id_u[0], P_u1[1]);
        Element left2 = C_id_su[1];
        Element right2 = HashUtil.getInvModP(this.getZr(), C_id_u[1], P_u2[1]);
        Element left3 = C_id_su[2];
        Element right3 = HashUtil.getInvModP(this.getZr(), C_id_u[2], P_u3[1]);
        System.out.println(left1 + "  " + right1);
        System.out.println(left2 + "  " + right2);
        System.out.println(left3 + "  " + right3);
        return left1.isEqual(right1) && left2.isEqual(right2) && left3.isEqual(right3);
    }


    public Element[] Af_u;
    public Element UAf;
    public void usrAuthorizationFactor(){
        Af_u = new Element[3];

        Element p = pairing(g1, g2).getImmutable();
        Element p1 = pairing(P_u3[0], S_u1[0]).getImmutable();
        Element p2 = pairing(P_u3[0], S_u2[0]).getImmutable();

        Af_u[0] = p.powZn(S_u1[1]).mul(p1).getImmutable();
        Af_u[1] = p.powZn(S_u2[1]).mul(p2).getImmutable();
        UAf = Af_u[0].mul(Af_u[1]).getImmutable();

        System.out.println(Af_u[0]);
        System.out.println(Af_u[1]);
        System.out.println(UAf);
    }



    public Element K, A;
    public void retrievalAuthGen(){
        Element p1 = pairing(P_u3[0], S_u1[0]).getImmutable();
        Element p2 = pairing(P_u3[0], S_u2[0]).getImmutable();
        K = p1.mul(p2).getImmutable();

        Af_u[2] = pairing(g1, g2).powZn(S_u3[1]).getImmutable();
        A = UAf.div(K).mul(Af_u[2]).getImmutable();

        System.out.println(K);
        System.out.println(Af_u[2]);
        System.out.println(A);
        System.out.println();
    }


    public Element[] T_h;
    public void federatedTrap(String q){
        System.out.println("======== Federated Trap ==========");
        Element s = randomZ();
        T_h = new Element[3];
        T_h[0] = g1.powZn(s).getImmutable();
        T_h[1] = H(q).powZn(s).mul(pk_f.powZn(S_u3[2])).getImmutable();
        T_h[2] = A.powZn(s).getImmutable();

        for(Element t: T_h){
            System.out.println(t);
        }
        System.out.println(pairing(g1, g2).powZn(v.mul(s)));
        System.out.println();
    }


    public boolean federatedMatch(){
        System.out.println("======= Federated Match ========");

        Element left = pairing(C[1], T_h[0]).getImmutable();

        Element p = T_h[1].div(P_u3[2].powZn(sk_f)).getImmutable();
        Element right = pairing(C[2], p).mul(T_h[2]).getImmutable();

        System.out.println(p);
        System.out.println(T_h[2]);
        System.out.println(left);
        System.out.println(right);

        return left.isEqual(right);
    }

}
