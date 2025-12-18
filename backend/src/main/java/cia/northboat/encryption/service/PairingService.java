package cia.northboat.encryption.service;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
import cia.northboat.encryption.crypto.pairing.impl.*;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;


@Service
public class PairingService {
    private final PairingSystem ap, crima, dibaeks, dpreks, dumse, fipeck, gu2cks, paeks, pauks, pecks, peks, pmatch, preks, sapauks, scf, spwse1, spwse2, tbeks, tms, tu2cks, tucr, hve;

    public PairingService(AP ap, CRIMA crima, DIBAEKS dibaeks, DPREKS dpreks, DuMSE dumse, FIPECK fipeck,
                          Gu2CKS gu2cks, PAEKS paeks, PAUKS pauks, PECKS pecks, PEKS peks, PMatch pmatch,
                          PREKS preks, SAPAUKS sapauks, SCF scf, SPWSE1 spwse1, SPWSE2 spwse2, TBEKS tbeks,
                          TMS tms, Tu2CKS tu2cks, TuCR tucr, HVE hve){
        this.ap = ap;
        this.crima = crima;
        this.dibaeks = dibaeks;
        this.dpreks = dpreks;
        this.dumse = dumse;
        this.fipeck = fipeck;
        this.gu2cks = gu2cks;
        this.paeks = paeks;
        this.pauks = pauks;
        this.pecks = pecks;
        this.peks = peks;
        this.pmatch = pmatch;
        this.preks = preks;
        this.sapauks = sapauks;
        this.scf = scf;
        this.spwse1 = spwse1;
        this.spwse2 = spwse2;
        this.tbeks = tbeks;
        this.tms = tms;
        this.tu2cks = tu2cks;
        this.tucr = tucr;
        this.hve = hve;
    }



    public Map<String, Object> test(String algo, String word, List<String> words, int round){
        if(algo.equalsIgnoreCase("ap")){
            return ap.test(word, words, round);
        } else if(algo.equalsIgnoreCase("crima")){
            return crima.test(word, words, round);
        } else if(algo.equalsIgnoreCase("dibaeks")){
            return dibaeks.test(word, words, round);
        } else if(algo.equalsIgnoreCase("dpreks")){
            return dpreks.test(word, words, round);
        } else if(algo.equalsIgnoreCase("dumse")){
            return dumse.test(word, words, round);
        } else if(algo.equalsIgnoreCase("fipeck")){
            return fipeck.test(word, words, round);
        } else if(algo.equalsIgnoreCase("gu2cks")){
            return gu2cks.test(word, words, round);
        } else if(algo.equalsIgnoreCase("paeks")){
            return paeks.test(word, words, round);
        } else if(algo.equalsIgnoreCase("pauks")){
            return pauks.test(word, words, round);
        } else if(algo.equalsIgnoreCase("pecks")){
            return pecks.test(word, words, round);
        } else if(algo.equalsIgnoreCase("peks")){
            return peks.test(word, words, round);
        } else if(algo.equalsIgnoreCase("pmatch")){
            return pmatch.test(word, words, round);
        } else if(algo.equalsIgnoreCase("preks")){
            return preks.test(word, words, round);
        } else if(algo.equalsIgnoreCase("sapauks")){
            return sapauks.test(word, words, round);
        } else if(algo.equalsIgnoreCase("scf")){
            return scf.test(word, words, round);
        } else if(algo.equalsIgnoreCase("spwse1")){
            return spwse1.test(word, words, round);
        } else if(algo.equalsIgnoreCase("spwse2")){
            return spwse2.test(word, words, round);
        } else if(algo.equalsIgnoreCase("tbeks")){
            return tbeks.test(word, words, round);
        } else if(algo.equalsIgnoreCase("tms")){
            return tms.test(word, words, round);
        } else if(algo.equalsIgnoreCase("tu2cks")){
            return tu2cks.test(word, words, round);
        } else if(algo.equalsIgnoreCase("tucr")){
            return tucr.test(word, words, round);
        } else if(algo.equalsIgnoreCase("hve")){
            return hve.test(word, words, round);
        }
        return Map.of("msg", "Algo Not Exists");
    }

}
