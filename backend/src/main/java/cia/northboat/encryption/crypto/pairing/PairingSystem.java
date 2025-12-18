package cia.northboat.encryption.crypto.pairing;

import cia.northboat.encryption.utils.HashUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import lombok.Getter;
import lombok.Setter;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Getter
@Setter
public abstract class PairingSystem implements SearchableEncryption{
    Field G, GT, Zr;
    Pairing bp;
    int n = 26, l = 4, k = 3, q = 1024;
    boolean updatable;

    public PairingSystem(Field G, Field GT, Field Zr, Pairing bp) {
        this.G = G;
        this.GT = GT;
        this.Zr = Zr;
        this.bp = bp;
        this.updatable = false;
    }

    public PairingSystem(Field G, Field GT, Field Zr, Pairing bp, boolean updatable) {
        this.G = G;
        this.GT = GT;
        this.Zr = Zr;
        this.bp = bp;
        this.updatable = updatable;
    }

    public Element[] h(String str){
        return HashUtil.hashStr2ZrArr(Zr, str, n);
    }

    public Field getG(){
        return G;
    }

    public Field getGT() {
        return GT;
    }

    public Field getZr() {
        return Zr;
    }

    public int getN() {
        return n;
    }

    public Pairing getBp() {
        return bp;
    }

    public boolean getUpdatable(){
        return updatable;
    }

    public Element randomZ(){
        return Zr.newRandomElement().getImmutable();
    }

    public Element getI(String i){
        BigInteger bi = new BigInteger(i);
        return Zr.newElement(bi).getImmutable();
    }

    public Element randomG(){
        return G.newRandomElement().getImmutable();
    }

    public Element randomGT(){
        return GT.newRandomElement().getImmutable();
    }

    public String randomNum(){
        UUID randomUUID = UUID.randomUUID();
        return randomUUID.toString().replaceAll("-", "");
    }

    public Element pairing(Element u, Element v){
        return bp.pairing(u, v).getImmutable();
    }


    public Map<String, Object> test(String word, List<String> words, int round){
        long t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0;
        Map<String, Object> res = new HashMap<>();
        setup();
        for(int i = 0; i < round; i++){
            keygen();
            long s1 = System.currentTimeMillis();
            try{
                enc(word);
            }catch (UnsupportedOperationException e){
                enc(words);
            }
            long e1 = System.currentTimeMillis();
            t1 += e1-s1;


            long s2 = System.currentTimeMillis();
            try{
                trap(word);
            }catch (UnsupportedOperationException e){
                trap(words);
            }
            long e2 = System.currentTimeMillis();
            t2 += e2-s2;

            long s3 = System.currentTimeMillis();
            System.out.println(search());
            long e3 = System.currentTimeMillis();
            t3 += e3-s3;


            if(getUpdatable()){
                long s7 = System.currentTimeMillis();
                updateKey();
                long e7 = System.currentTimeMillis();
                t7 += e7-s7;

                long s4 = System.currentTimeMillis();
                reEnc();
                long e4 = System.currentTimeMillis();
                t4 += e4-s4;


                long s5 = System.currentTimeMillis();
                try{
                    constTrap(word);
                }catch (UnsupportedOperationException e){
                    constTrap(words);
                }

                long e5 = System.currentTimeMillis();
                t5 += e5-s5;

                long s6 = System.currentTimeMillis();
                System.out.println(updateSearch());
                long e6 = System.currentTimeMillis();
                t6 += e6-s6;
            }

        }
        res.put("EncCost", t1);
        res.put("TrapCost", t2);
        res.put("SearchCost", t3);
        if(updatable){
            res.put("ReEncCost", t4);
            res.put("ConstTrapCost", t5);
            res.put("UpdateSearchCost", t6);
            res.put("UpdateKeyCost", t7);
        }
        return res;
    }

    // 某一次仿真的需求
    public List<Long> test(List<String> words, int sender, int receiver, int round) {
        throw new UnsupportedOperationException("test(List<String> words, int sender, int receiver, int round) is not supported");
    }
}
