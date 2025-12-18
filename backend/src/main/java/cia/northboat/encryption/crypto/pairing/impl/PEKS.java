package cia.northboat.encryption.crypto.pairing.impl;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class PEKS extends PairingSystem {

    public PEKS(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }


    Element g;
    @Override
    public void setup(){
        g = randomG();
    }

    Element g1, g2, s, r, gs, gr;
    @Override
    public void keygen(){
        g1 = g.powZn(randomZ()).getImmutable();
        g2 = g.powZn(randomZ()).getImmutable();
        s = randomZ();
        r = randomZ();
        gs = g.powZn(s).getImmutable();
        gr = g.powZn(r).getImmutable();
    }



    Element[] C, F;
    Element[][] B, D;
    @Override
    public void enc(String word){
        B = new Element[2][8];
        C = new Element[3];
        F = new Element[5];
        D = new Element[5][8];

        Element s1 = randomZ();
        B[0][0] = g2.powZn(s1.mul(getI("1"))).mul(gr.powZn(s1)).getImmutable();
        B[0][1] = g2.powZn(s1.mul(getI("37"))).mul(gr.powZn(s1)).getImmutable();
        B[0][2] = g2.powZn(s1.mul(getI("1369"))).mul(gr.powZn(s1)).getImmutable();
        B[0][3] = g2.powZn(s1.mul(getI("50653"))).mul(gr.powZn(s1)).getImmutable();
        B[0][4] = g2.powZn(s1.mul(getI("1874161"))).mul(gr.powZn(s1)).getImmutable();
        B[0][5] = g2.powZn(s1.mul(getI("69343957"))).mul(gr.powZn(s1)).getImmutable();
        B[0][6] = g2.powZn(s1.mul(getI("2565726409"))).mul(gr.powZn(s1)).getImmutable();
        B[0][7] = g2.powZn(s1.mul(getI("94931877133"))).mul(gr.powZn(s1)).getImmutable();

        B[1][0] = g2.powZn(s1.mul(getI("1"))).mul(gr.powZn(s1)).getImmutable();
        B[1][1] = g2.powZn(s1.mul(getI("34"))).mul(gr.powZn(s1)).getImmutable();
        B[1][2] = g2.powZn(s1.mul(getI("1156"))).mul(gr.powZn(s1)).getImmutable();
        B[1][3] = g2.powZn(s1.mul(getI("39304"))).mul(gr.powZn(s1)).getImmutable();
        B[1][4] = g2.powZn(s1.mul(getI("1336336"))).mul(gr.powZn(s1)).getImmutable();
        B[1][5] = g2.powZn(s1.mul(getI("45435424"))).mul(gr.powZn(s1)).getImmutable();
        B[1][6] = g2.powZn(s1.mul(getI("1544804416"))).mul(gr.powZn(s1)).getImmutable();
        B[1][7] = g2.powZn(s1.mul(getI("52523350144"))).mul(gr.powZn(s1)).getImmutable();


        C[0] = g.powZn(s1).getImmutable();
        C[1] = g2.powZn(s1.mul(s).mul(getI("97568873720"))).getImmutable();
        C[2] = g2.powZn(s1.mul(s).mul(getI("54114966815"))).getImmutable();


        D[0][0] = g2.powZn(s1.mul(getI("1"))).mul(gr.powZn(s1)).getImmutable();
        D[0][1] = g2.powZn(s1.mul(getI("17"))).mul(gr.powZn(s1)).getImmutable();
        D[0][2] = g2.powZn(s1.mul(getI("289"))).mul(gr.powZn(s1)).getImmutable();
        D[0][3] = g2.powZn(s1.mul(getI("4913"))).mul(gr.powZn(s1)).getImmutable();
        D[0][4] = g2.powZn(s1.mul(getI("83521"))).mul(gr.powZn(s1)).getImmutable();
        D[0][5] = g2.powZn(s1.mul(getI("1419857"))).mul(gr.powZn(s1)).getImmutable();
        D[0][6] = g2.powZn(s1.mul(getI("24137569"))).mul(gr.powZn(s1)).getImmutable();
        D[0][7] = g2.powZn(s1.mul(getI("410338673"))).mul(gr.powZn(s1)).getImmutable();

        D[1][0] = g2.powZn(s1.mul(getI("1"))).mul(gr.powZn(s1)).getImmutable();
        D[1][1] = g2.powZn(s1.mul(getI("16"))).mul(gr.powZn(s1)).getImmutable();
        D[1][2] = g2.powZn(s1.mul(getI("256"))).mul(gr.powZn(s1)).getImmutable();
        D[1][3] = g2.powZn(s1.mul(getI("4096"))).mul(gr.powZn(s1)).getImmutable();
        D[1][4] = g2.powZn(s1.mul(getI("65536"))).mul(gr.powZn(s1)).getImmutable();
        D[1][5] = g2.powZn(s1.mul(getI("1048576"))).mul(gr.powZn(s1)).getImmutable();
        D[1][6] = g2.powZn(s1.mul(getI("16777216"))).mul(gr.powZn(s1)).getImmutable();
        D[1][7] = g2.powZn(s1.mul(getI("268435456"))).mul(gr.powZn(s1)).getImmutable();

        D[2][0] = g2.powZn(s1.mul(getI("1"))).mul(gr.powZn(s1)).getImmutable();
        D[2][1] = g2.powZn(s1.mul(getI("27"))).mul(gr.powZn(s1)).getImmutable();
        D[2][2] = g2.powZn(s1.mul(getI("729"))).mul(gr.powZn(s1)).getImmutable();
        D[2][3] = g2.powZn(s1.mul(getI("19683"))).mul(gr.powZn(s1)).getImmutable();
        D[2][4] = g2.powZn(s1.mul(getI("531441"))).mul(gr.powZn(s1)).getImmutable();
        D[2][5] = g2.powZn(s1.mul(getI("14348907"))).mul(gr.powZn(s1)).getImmutable();
        D[2][6] = g2.powZn(s1.mul(getI("387420489"))).mul(gr.powZn(s1)).getImmutable();
        D[2][7] = g2.powZn(s1.mul(getI("10460353203"))).mul(gr.powZn(s1)).getImmutable();

        D[3][0] = g2.powZn(s1.mul(getI("1"))).mul(gr.powZn(s1)).getImmutable();
        D[3][1] = g2.powZn(s1.mul(getI("12"))).mul(gr.powZn(s1)).getImmutable();
        D[3][2] = g2.powZn(s1.mul(getI("144"))).mul(gr.powZn(s1)).getImmutable();
        D[3][3] = g2.powZn(s1.mul(getI("1728"))).mul(gr.powZn(s1)).getImmutable();
        D[3][4] = g2.powZn(s1.mul(getI("20736"))).mul(gr.powZn(s1)).getImmutable();
        D[3][5] = g2.powZn(s1.mul(getI("248832"))).mul(gr.powZn(s1)).getImmutable();
        D[3][6] = g2.powZn(s1.mul(getI("2985984"))).mul(gr.powZn(s1)).getImmutable();
        D[3][7] = g2.powZn(s1.mul(getI("35831808"))).mul(gr.powZn(s1)).getImmutable();

        D[4][0] = g2.powZn(s1.mul(getI("1"))).mul(gr.powZn(s1)).getImmutable();
        D[4][1] = g2.powZn(s1.mul(getI("15"))).mul(gr.powZn(s1)).getImmutable();
        D[4][2] = g2.powZn(s1.mul(getI("225"))).mul(gr.powZn(s1)).getImmutable();
        D[4][3] = g2.powZn(s1.mul(getI("3375"))).mul(gr.powZn(s1)).getImmutable();
        D[4][4] = g2.powZn(s1.mul(getI("50625"))).mul(gr.powZn(s1)).getImmutable();
        D[4][5] = g2.powZn(s1.mul(getI("759375"))).mul(gr.powZn(s1)).getImmutable();
        D[4][6] = g2.powZn(s1.mul(getI("11390625"))).mul(gr.powZn(s1)).getImmutable();
        D[4][7] = g2.powZn(s1.mul(getI("170859375"))).mul(gr.powZn(s1)).getImmutable();

        F[0] = g2.powZn(s1.mul(s).mul(getI("435984840"))).getImmutable();
        F[1] = g2.powZn(s1.mul(s).mul(getI("286331153"))).getImmutable();
        F[2] = g2.powZn(s1.mul(s).mul(getI("10862674480"))).getImmutable();
        F[3] = g2.powZn(s1.mul(s).mul(getI("39089245"))).getImmutable();
        F[4] = g2.powZn(s1.mul(s).mul(getI("183063616"))).getImmutable();
    }


    int testIndex;
    Element[] T;
    Element[][] E;
    @Override
    public void trap(String word){
        testIndex = 0;
        E = new Element[2][8];
        T = new Element[4];

        Element r1 = randomZ();
        E[0][0] = g1.powZn(r1.mul(getI("-370137600"))).mul(gs.powZn(r1)).getImmutable();
        E[0][1] = g1.powZn(r1.mul(getI("206359200"))).mul(gs.powZn(r1)).getImmutable();
        E[0][2] = g1.powZn(r1.mul(getI("-42562224"))).mul(gs.powZn(r1)).getImmutable();
        E[0][3] = g1.powZn(r1.mul(getI("4426670"))).mul(gs.powZn(r1)).getImmutable();
        E[0][4] = g1.powZn(r1.mul(getI("-256213"))).mul(gs.powZn(r1)).getImmutable();
        E[0][5] = g1.powZn(r1.mul(getI("8349"))).mul(gs.powZn(r1)).getImmutable();
        E[0][6] = g1.powZn(r1.mul(getI("-143"))).mul(gs.powZn(r1)).getImmutable();
        E[0][7] = g1.powZn(r1.mul(getI("1"))).mul(gs.powZn(r1)).getImmutable();


        T[0] = g1.powZn(r1.mul(getI("-202161960")).mul(r)).getImmutable();
        T[1] = g.powZn(r1).getImmutable();
        T[2] = gs.powZn(r1.mul(getI("8").mul(r))).getImmutable();

        buildEAndT(E, T, r1, nums[testIndex]);
    }


    String[][] nums = new String[][] {
            {"-5582618624", "1776287744", "-234651648", "16601088", "-676032", "15792", "-196", "1", "-4025041875"},
            {"-1289945088", "465813504", "-71373312", "6011584", "-300451", "8907", "-145", "1", "-889785000"},
            {"-24138569268", "5757575472", "-581797657", "32273645", "-1061110", "20674", "-221", "1", "-18931558464"},
            {"-4478976", "3732480", "-1306368", "248832", "-27864", "1836", "-66", "1", "-1830125"},
            {"-972000000", "385560000", "-63709200", "5677380", "-294648", "8917", "-146", "1", "-644757696"},
            {"-10440000", "13375200", "-5862404", "1067464", "-96173", "4531", "-107", "1", "-1951488"},
            {"-478406250", "202753125", "-36450000", "3594375", "-209250", "7155", "-132", "1", "-308710976"},
            {"-94921875", "54421875", "-12571875", "1546875", "-110625", "4625", "-105", "1", "-51631104"},
    };

    public void buildEAndT(Element[][] E, Element[] T, Element r1, String[] nums){
        for(int i = 0; i < 8; i++){
            E[1][i] = g1.powZn(r1.mul(getI(nums[i]))).mul(gs.powZn(r1)).getImmutable();
        }
        T[3] =g1.powZn(r1.mul(r).mul(getI(nums[8]))).getImmutable();
    }


    boolean flag = false;
    Element left, right;
    @Override
    public boolean search(){
        Element z1 = pairing(B[0][0], E[0][0]).mul(pairing(B[0][1], E[0][1])).mul(pairing(B[0][2], E[0][2])).mul(pairing(B[0][3], E[0][3])).mul(pairing(B[0][4], E[0][4])).mul(pairing(B[0][5], E[0][5])).mul(pairing(B[0][6], E[0][6])).mul(pairing(B[0][7], E[0][7])).getImmutable();
        Element tau1 = pairing(C[0], T[0]).mul(pairing(C[1], T[1])).mul(pairing(C[0], T[2])).getImmutable();

        Element z2 = pairing(B[1][0], E[0][0]).mul(pairing(B[1][1], E[0][1])).mul(pairing(B[1][2], E[0][2])).mul(pairing(B[1][3], E[0][3])).mul(pairing(B[1][4], E[0][4])).mul(pairing(B[1][5], E[0][5])).mul(pairing(B[1][6], E[0][6])).mul(pairing(B[1][7], E[0][7])).getImmutable();
        Element tau2 = pairing(C[0], T[0]).mul(pairing(C[2], T[1])).mul(pairing(C[0], T[2])).getImmutable();

        Element z3 = pairing(D[0][0], E[1][0]).mul(pairing(D[0][1], E[1][1])).mul(pairing(D[0][2], E[1][2])).mul(pairing(D[0][3], E[1][3])).mul(pairing(D[0][4], E[1][4])).mul(pairing(D[0][5], E[1][5])).mul(pairing(D[0][6], E[1][6])).mul(pairing(D[0][7], E[1][7])).getImmutable();
        Element tau3 = pairing(C[0], T[3]).mul(pairing(F[0], T[1])).mul(pairing(C[0], T[2])).getImmutable();

        Element z4 = pairing(D[1][0], E[1][0]).mul(pairing(D[1][1], E[1][1])).mul(pairing(D[1][2], E[1][2])).mul(pairing(D[1][3], E[1][3])).mul(pairing(D[1][4], E[1][4])).mul(pairing(D[1][5], E[1][5])).mul(pairing(D[1][6], E[1][6])).mul(pairing(D[1][7], E[1][7])).getImmutable();
        Element tau4 = pairing(C[0], T[3]).mul(pairing(F[1], T[1])).mul(pairing(C[0], T[2])).getImmutable();

        Element z5 = pairing(D[2][0], E[1][0]).mul(pairing(D[2][1], E[1][1])).mul(pairing(D[2][2], E[1][2])).mul(pairing(D[2][3], E[1][3])).mul(pairing(D[2][4], E[1][4])).mul(pairing(D[2][5], E[1][5])).mul(pairing(D[2][6], E[1][6])).mul(pairing(D[2][7], E[1][7])).getImmutable();
        Element tau5 = pairing(C[0], T[3]).mul(pairing(F[2], T[1])).mul(pairing(C[0], T[2])).getImmutable();

        Element z6 = pairing(D[3][0], E[1][0]).mul(pairing(D[3][1], E[1][1])).mul(pairing(D[3][2], E[1][2])).mul(pairing(D[3][3], E[1][3])).mul(pairing(D[3][4], E[1][4])).mul(pairing(D[3][5], E[1][5])).mul(pairing(D[3][6], E[1][6])).mul(pairing(D[3][7], E[1][7])).getImmutable();
        Element tau6 = pairing(C[0], T[3]).mul(pairing(F[3], T[1])).mul(pairing(C[0], T[2])).getImmutable();

        Element z7 = pairing(D[4][0], E[1][0]).mul(pairing(D[4][1], E[1][1])).mul(pairing(D[4][2], E[1][2])).mul(pairing(D[4][3], E[1][3])).mul(pairing(D[4][4], E[1][4])).mul(pairing(D[4][5], E[1][5])).mul(pairing(D[4][6], E[1][6])).mul(pairing(D[4][7], E[1][7])).getImmutable();
        Element tau7 = pairing(C[0], T[3]).mul(pairing(F[4], T[1])).mul(pairing(C[0], T[2])).getImmutable();


        System.out.println("TestIndex: " + testIndex);
        System.out.println("z1: " + z1 + "\ntau1: " + tau1);
        System.out.println("z2: " + z2 + "\ntau2: " + tau2);
        System.out.println("z3: " + z3 + "\ntau3: " + tau3);
        System.out.println("z4: " + z4 + "\ntau4: " + tau4);
        System.out.println("z5: " + z5 + "\ntau5: " + tau5);
        System.out.println("z6: " + z6 + "\ntau6: " + tau6);
        System.out.println("z7: " + z7 + "\ntau7: " + tau7);
        switch (testIndex) {
            case 0, 1 -> {
                flag = z2.isEqual(tau2) && z4.isEqual(tau4); // test0 & test1
                left = z4;
                right = tau4;
            }
            case 2 -> {
                flag = z2.isEqual(tau2) && z5.isEqual(tau5); // test2
                left = z5;
                right = tau5;
            }
            case 3, 4, 5 -> {
                flag = z2.isEqual(tau2) && z6.isEqual(tau6); // test3 & test4 & test5
                left = z6;
                right = tau6;
            }
            case 6, 7 -> {
                flag = z2.isEqual(tau2) && z7.isEqual(tau7); // test6 & test7
                left = z7;
                right = tau7;
            }
        }
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
