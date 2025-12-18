package cia.northboat.encryption.crypto.auth.impl;

import cia.northboat.encryption.crypto.auth.SignatureSystem;
import cia.northboat.encryption.crypto.auth.model.CryptoMap;
import cia.northboat.encryption.crypto.auth.model.KeyPair;
import cia.northboat.encryption.utils.HashUtil;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


// Sanitizable Blind Signature
// 可擦除盲签名
@Component
public class SBS extends SignatureSystem {


    @Autowired
    public SBS(Pairing BP, Field G1, Field GT, Field Zr) {
        super(BP, G1, null, GT, Zr, true, true);
        g  = randomG1(); // 生成元
    }

    Element g;
    /* ========= KeyGen ========= */
    @Override
    public KeyPair keygen() {

        Element sk = randomZ(); // Z_q 元素
        Element pk = g.powZn(sk).getImmutable();

        KeyPair kp = new KeyPair();
        kp.sk.put("a", sk);
        kp.pk.put("A", pk);
        return kp;
    }


    // 把 str 映射到 Zr
    public Element h(String message){
        return HashUtil.hashStr2Group(this.getZr(), message);
    }


    /* ========= Sign ========= */
    // 使用签名者的私钥和擦除者的公钥进行签名
    @Override
    public CryptoMap sign(String message, CryptoMap key) {
        Element sk_sig = key.getE("sk_sig", this.getZr()); // 签名私钥

        Element pk_san = key.getE("pk_san", this.getG1()); // 擦除公钥
//        Element pk_sig = key.getE("pk_sig", this.getG1()); // 签名公钥

        Element m  = h(message); // 明文哈希 H(m)∈G1
        Element X = pk_san.powZn(m).getImmutable();
//        Element Y = pk_sig.powZn(m).getImmutable();

        // 构造 mu 和 eta
        Element r = randomZ();
        Element R = g.powZn(r).getImmutable();
        Element mu = X.powZn(sk_sig.add(r)).getImmutable();
//        Element eta = Y.powZn(sk_sig.add(r)).getImmutable();


        CryptoMap signature = new CryptoMap();
        signature.put("m", m);
        signature.put("X", X);
//        signature.put("Y", Y);
        signature.put("R", R);
        signature.put("mu", mu);
//        signature.put("eta", eta);
        return signature;
    }


    /* ========= Verify ========= */
    // 使用签名者的公钥和擦除者的公钥进行验签
    @Override
    public Boolean verify(CryptoMap key, CryptoMap signature) {

        Element pk_sig = key.getE("pk_sig", this.getG1());
        Element pk_san = key.getE("pk_san", this.getG1());

        Element X = signature.getE("X", this.getG1());
//        Element Y = signature.getE("Y", this.getG1());

        Element R = signature.getE("R", this.getG1());
        Element mu = signature.getE("mu", this.getG1());
//        Element eta = signature.getE("eta", this.getG1());

        Element m = signature.getE("m", this.getZr());
        Element X1 = pk_san.powZn(m).getImmutable();
//        Element Y1 = pk_sig.powZn(m).getImmutable();

        boolean flag1 = X.isEqual(X1);
//        boolean flag2 = Y.isEqual(Y1);

        System.out.println("f1: " + flag1);
//        System.out.println("f2: " + flag2);

        Element left1 = pairing(mu, g).getImmutable();
        Element right1 = pairing(X1, pk_sig).mul(pairing(R, X1)).getImmutable();
        boolean flag2 = left1.isEqual(right1);
        System.out.println("f2: " + flag2);


//        Element left2 = pairing(eta, g).getImmutable();
//        Element right2 = pairing(Y1, pk_sig).mul(pairing(R, Y1)).getImmutable();
//        boolean flag4 = left2.isEqual(right2);
//        System.out.println("f4: " + flag4);

        return flag1 && flag2;
    }


    /* ========= Sanitize ========= */
    @Override
    public CryptoMap sanitize(String message, CryptoMap key, CryptoMap signature) {

        Element sk_san = key.getE("sk_san", this.getZr());
//        sk_san = sk_san.add(this.getI("1"));
        Element X = signature.getE("X", this.getG1());
        Element m = signature.getE("m", this.getZr());

        if(!X.powZn(sk_san.invert()).isEqual(g.powZn(m))){
            System.out.println("不具备擦除权力，签名照旧");
            return signature;
        }

        Element s = h(message); // 根据新的消息更新明文 m
        m = m.mul(s).getImmutable();

//        Element Y = signature.getE("Y", this.getG1());
        Element mu = signature.getE("mu", this.getG1());
//        Element eta = signature.getE("eta", this.getG1());

        // 重签 eta
        Element X1 = X.powZn(s).getImmutable();
//        Element Y1 = Y.powZn(s).getImmutable();
        Element mu1 = mu.powZn(s).getImmutable();
//        Element eta1 = eta.powZn(s).getImmutable();


        signature.put("m", m);
        signature.put("X", X1);
//        signature.put("Y", Y1);
        signature.put("mu", mu1);
//        signature.put("eta", eta1);

        return signature;
    }

}
