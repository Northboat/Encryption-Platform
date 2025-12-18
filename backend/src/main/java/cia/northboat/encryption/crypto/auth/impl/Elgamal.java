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

@Component
public class Elgamal extends SignatureSystem {

    @Autowired
    public Elgamal(Field Zr) {
        super(null, null, null, null, Zr, false, false);
    }


    @Override
    public KeyPair keygen(){
        BigInteger p = BigInteger.probablePrime(1024, new SecureRandom());

        BigInteger g = randomZ().toBigInteger();

        BigInteger x = randomZ().toBigInteger();
        BigInteger y = g.modPow(x, p);

        KeyPair key = new KeyPair();
        key.sk.put("x", x);
        key.sk.put("g", g);
        key.sk.put("p", p);

        key.pk.put("g", g);
        key.pk.put("y", y);
        key.pk.put("p", p);

        return key;
    }


    @Override
    public CryptoMap sign(String message, CryptoMap sk){
        BigInteger g = sk.getI("g");
        BigInteger p = sk.getI("p");
        BigInteger x = sk.getI("x");

        BigInteger m = HashUtil.hashStr2Group(getZr(), message).toBigInteger();
        // k 必须是可逆的
        BigInteger k = BigInteger.probablePrime(128, new SecureRandom());
        BigInteger k1 = k.modInverse(p.subtract(BigInteger.ONE)); // k的逆
        BigInteger r = g.modPow(k, p);
        BigInteger s = m.subtract(x.multiply(r)).multiply(k1).mod(p.subtract(BigInteger.ONE));

        CryptoMap signature = new CryptoMap();
        signature.put("m", m);
        signature.put("r", r);
        signature.put("s", s);

        return signature;
    }


    @Override
    public Boolean verify(CryptoMap pk, CryptoMap signature){
        BigInteger g = pk.getI("g");
        BigInteger y = pk.getI("y");
        BigInteger p = pk.getI("p");
        BigInteger r = signature.getI("r");
        BigInteger s = signature.getI("s");
        BigInteger m = signature.getI("m");

        BigInteger left = y.modPow(r, p).multiply(r.modPow(s, p)).mod(p);
        BigInteger right = g.modPow(m, p);


        return left.equals(right);

    }
}
