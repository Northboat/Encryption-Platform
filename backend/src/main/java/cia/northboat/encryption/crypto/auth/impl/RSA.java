package cia.northboat.encryption.crypto.auth.impl;

import cia.northboat.encryption.crypto.auth.SignatureSystem;
import cia.northboat.encryption.crypto.auth.model.CryptoMap;
import cia.northboat.encryption.crypto.auth.model.KeyPair;
import cia.northboat.encryption.utils.HashUtil;
import it.unisa.dia.gas.jpbc.Field;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.SecureRandom;


// JPBC 并不适用，用 BigInteger 手写的
@Component
public class RSA extends SignatureSystem {

    @Autowired
    public RSA(Field Zr) {
        super(null, null, null, null, Zr, false, false);
    }

    @Override
    public KeyPair keygen(){

        BigInteger p = BigInteger.probablePrime(512, new SecureRandom());
        BigInteger q = BigInteger.probablePrime(512, new SecureRandom());
        BigInteger n = p.multiply(q);
        // 欧拉函数
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger e = BigInteger.probablePrime(128, new SecureRandom());
        BigInteger d = e.modInverse(phi);


        KeyPair k = new KeyPair();

        k.sk.put("d", d);
        k.sk.put("phi", phi);
        k.sk.put("n", n);
        k.pk.put("e", e);
        k.pk.put("n", n);

        return k;
    }


    // s = H(m)^d
    @Override
    public CryptoMap sign(String message, CryptoMap sk){
        // 明文哈希
        BigInteger m = HashUtil.hashStr2Group(getZr(), message).toBigInteger();
        BigInteger d = sk.getI("d");
        BigInteger n = sk.getI("n");
        BigInteger s = m.modPow(d, n);

        CryptoMap signature = new CryptoMap();
        signature.put("m", m);
        signature.put("s", s); // s = m^d % n

        return signature;
    }


    // H(m) ?= s^e
    @Override
    public Boolean verify(CryptoMap pk, CryptoMap signature){
        BigInteger s = signature.getI("s");
        BigInteger e = pk.getI("e");
        BigInteger n = pk.getI("n");
        BigInteger m = signature.getI("m");

        BigInteger recovered = s.modPow(e, n);
        return m.equals(recovered);
    }

}
