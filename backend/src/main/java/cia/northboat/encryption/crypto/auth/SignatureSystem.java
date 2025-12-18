package cia.northboat.encryption.crypto.auth;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.math.BigInteger;

@Getter
@Setter
@Data
public abstract class SignatureSystem implements Auth {

    Pairing BP;
    Field G1, G2, GT, Zr;
    Boolean sanitizable, updatable;

    public SignatureSystem(Pairing BP, Field G1, Field G2, Field GT, Field Zr, Boolean sanitizable, Boolean updatable){
        this.BP = BP;
        this.G1 = G1;
        this.G2 = G2;
        this.GT = GT;
        this.Zr = Zr;
        this.sanitizable = sanitizable;
        this.updatable = updatable;
    }

    public Element randomZ(){
        return Zr.newRandomElement().getImmutable();
    }

    public Element getI(String i){
        BigInteger bi = new BigInteger(i);
        return Zr.newElement(bi).getImmutable();
    }

    public Element randomG1(){
        return G1.newRandomElement().getImmutable();
    }

    public Element randomG2(){
        return G2.newRandomElement().getImmutable();
    }

    public Element randomGT(){
        return GT.newRandomElement().getImmutable();
    }

    public Element pairing(Element a, Element b){
        return BP.pairing(a, b).getImmutable();
    }
}
