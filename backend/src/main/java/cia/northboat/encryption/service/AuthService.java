package cia.northboat.encryption.service;


import cia.northboat.encryption.crypto.auth.SignatureSystem;
import cia.northboat.encryption.crypto.auth.impl.Elgamal;
import cia.northboat.encryption.crypto.auth.impl.RSA;
import cia.northboat.encryption.crypto.auth.model.KeyPair;
import cia.northboat.encryption.crypto.auth.impl.Schnorr;
import cia.northboat.encryption.crypto.auth.model.CryptoMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final SignatureSystem rsa, schnorr, elgamal;
    @Autowired
    public AuthService(RSA rsa, Schnorr schnorr, Elgamal elgamal){
        this.rsa = rsa;
        this.schnorr = schnorr;
        this.elgamal = elgamal;
    }


    public SignatureSystem selectSystem(String algo){
        if (algo.equalsIgnoreCase("schnorr")){
            return schnorr;
        } else if (algo.equalsIgnoreCase("rsa")){
            return rsa;
        } else if (algo.equalsIgnoreCase("elgamal")){
            return elgamal;
        }
        return null;
    }


    public KeyPair keygen(String algo){
        SignatureSystem signatureSystem = selectSystem(algo);
        if(signatureSystem == null){
            return null;
        }
        return signatureSystem.keygen();
    }


    public CryptoMap sign(String algo, String message, CryptoMap sk){
        SignatureSystem signatureSystem = selectSystem(algo);
        if(signatureSystem == null){
            return null;
        }
        return signatureSystem.sign(message, sk);
    }

    public Boolean verify(String algo, CryptoMap pk, CryptoMap signature){
        SignatureSystem signatureSystem = selectSystem(algo);
        if(signatureSystem == null){
            return null;
        }
        return signatureSystem.verify(pk, signature);
    }
}
