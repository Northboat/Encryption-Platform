package cia.northboat.encryption.crypto.auth.impl;

import cia.northboat.encryption.crypto.auth.SignatureSystem;
import cia.northboat.encryption.crypto.auth.model.CryptoMap;
import cia.northboat.encryption.crypto.auth.model.KeyPair;
import cia.northboat.encryption.utils.HashUtil;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Element;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class Schnorr extends SignatureSystem {


    @Autowired
    public Schnorr(Field G1, Field Zr) {
        super(null, G1, null, null, Zr, false, false);
    }



    // y = xG
    @Override
    public KeyPair keygen(){
        Element g = randomG1();
        Element x = randomZ();
        Element y = g.mulZn(x).getImmutable();

        KeyPair keyPair = new KeyPair();
        keyPair.sk.put("g", g);
        keyPair.sk.put("x", x);
        keyPair.pk.put("g", g);
        keyPair.pk.put("y", y);

        return keyPair;
    }


    // R = rG, c = H(msg, R), z = r+cx
    @Override
    public CryptoMap sign(String message, CryptoMap sk){
        Element g = sk.getE("g", getG1());
        Element x = sk.getE("x", getZr());

        Element r = randomZ();
        Element R = g.mulZn(r).getImmutable();
        Element c = HashUtil.hashStr2Group(getZr(), message, R.toString());
        Element z = r.add(x.mulZn(c)).getImmutable();


        CryptoMap signature = new CryptoMap();
        signature.put("z", z);
        signature.put("c", c);
        signature.put("m", message);

        return signature;
    }

    // R1 = zG-xGc = (r+cx)G-cxG = rG = R
    // H(msg, R1) = H(msg, R) = c
    @Override
    public Boolean verify(CryptoMap pk, CryptoMap signature){
        Element y = pk.getE("y", getG1());
        Element g = pk.getE("g", getG1());
        Element z = signature.getE("z", getZr());
        Element c = signature.getE("c", getZr());
        String m = signature.get("m");

        Element R1 = g.mulZn(z).sub(y.mulZn(c)).getImmutable();


        return c.isEqual(HashUtil.hashStr2Group(getZr(), m, R1.toString()));
    }
}
