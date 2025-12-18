package cia.northboat.encryption.crypto.pairing.impl;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
import cia.northboat.encryption.utils.HashUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

// Hidden Vector Encryption
@Component
public class HVE extends PairingSystem {


    private final Element M;
    @Autowired
    public HVE(Field G1, Field GT, Field Zr, Pairing BP) {
        super(G1, GT, Zr, BP);
        M = HashUtil.hashStr2GT(this.getZr(), randomGT(), "test", this.getN());
    }


    public List<String> buildGrayPath(int l) {
        if (l == 0) return new ArrayList<>(List.of(""));
        List<String> prev = buildGrayPath(l-1);
        List<String> path = new ArrayList<>();

        // 正序添加，前缀 0
        for (String code : prev) {
            path.add("0" + code);
        }
        // 反序添加，前缀 1
        for (int i = prev.size()-1; i >= 0; i--) {
            path.add("1" + prev.get(i));
        }
        return path;
    }


    // 优化的 Gray 编码器
    public Map<String, String> grayOptimizer(Map<String, Double> cells, int l){
        // 构建长度为 l 的 Gray 编码路径
        if(cells.size() > Math.pow(2, l)){
            System.out.println("Cells too Much, Can't Encode");
            return null;
        }
        List<String> codes = buildGrayPath(l);
        System.out.println(codes);

        // 构建大顶堆，对 cells 按照权重从大到小排序
        PriorityQueue<String> sortedCells = new PriorityQueue<>((a, b) -> {
            if(cells.get(b) - cells.get(a) < 0){
                return -1;
            } else if(cells.get(b) - cells.get(a) == 0){
                return 0;
            } else {
                return 1;
            }
        });
        for(String cell: cells.keySet()){
            sortedCells.offer(cell);
        }

        // 分配 Gray 编码
        Map<String, String> grayCode = new HashMap<>();
        int i = 0;
        while(!sortedCells.isEmpty()){
            String cell = sortedCells.poll();
            String code = codes.get(i++);
            grayCode.put(cell, code);
        }
        return grayCode;
    }


    Element g, a;
    @Override
    public void setup() {
        g = randomG();
        a = randomZ();
    }


    Element[] u, h, w, U, H, W;
    @Override
    public void keygen() {
        u = new Element[getL()];
        h = new Element[getL()];
        w = new Element[getL()];
        U = new Element[getL()];
        H = new Element[getL()];
        W = new Element[getL()];
        for(int i = 0; i < getL(); i++){
            Element t = randomG();
            u[i] = t; U[i] = t;
            t = randomG();
            h[i] = t; H[i] = t;
            t = randomG();
            w[i] = t; W[i] = t;
        }
    }


    Element C0, C1;
    Element[] C2, C3;
    @Override
    public void enc(String w) {
        Element s = randomZ();
        C0 = M.mul(pairing(g, g).powZn(a.mul(s))).getImmutable();
        C1 = g.powZn(s).getImmutable();

        C2 = new Element[getL()];
        C3 = new Element[getL()];
        for(int i = 0; i < getL(); i++){
            Element I = w.charAt(i) == '1' ? getI("1") : getI("0");
            C2[i] = U[i].powZn(I).mul(H[i]).powZn(s).getImmutable();
//            C2[i] = U[i].powZn(I).mul(H[i]).getImmutable();
            C3[i] = W[i].powZn(s).getImmutable();
//            C3[i] = W[i].getImmutable();
        }



//        Element test = this.getG().newOneElement();
//        for(int i = 0; i < l; i++){
//            test.mul(C2[i]).mul(C3[i]);
//        }
//        System.out.println("test: " + test);
//        System.out.println("M:" + M);
//        System.out.println("e(g,g)^{as}: " + pairing(g, g).powZn(a.mul(s)));
        System.out.println("C0: " + C0);
//        System.out.println("C0/e(g,g)^{as}: " + C0.div(pairing(g, g).powZn(a.mul(s))) + "\n");
    }


    String T;
    Element K0;
    Element[] K1, K2;
    @Override
    public void trap(String q) {
        T = q;
        K1 = new Element[getL()];
        K2 = new Element[getL()];

        Element c = this.getG().newOneElement();
        for(int i = 0; i < getL(); i++){
            if(q.charAt(i) != '*'){
                Element T = q.charAt(i) == '1' ? getI("1") : getI("0");
                Element r1 = randomZ(), r2 = randomZ();
                K1[i] = g.powZn(r1).getImmutable();
                K2[i] = g.powZn(r2).getImmutable();
                c.mul(u[i].powZn(T).mul(h[i]).powZn(r1).mul(w[i].powZn(r2)));
//                c.mul(u[i].powZn(T).mul(h[i]).mul(w[i]));
            }
        }
        c.getImmutable();
        K0 = g.powZn(a).mul(c).getImmutable();

//        System.out.println("Product: " + c);
//        System.out.println("e(C1, K0): " + pairing(C1, K0) + "\n");
        System.out.println("K0: " + K0);

    }


    Boolean flag;
    Element M1;
    @Override
    public boolean search() {
        Element part1 = pairing(C1, K0);

//        System.out.println("cal: " + part1.div(C0));

        Element part2 = this.getGT().newOneElement();
        for(int i = 0; i < getL(); i++){
            if(T.charAt(i) != '*'){
                Element part3 = pairing(C2[i], K1[i]);
                Element part4 = pairing(C3[i], K2[i]);

                part2.mul(part3.mul(part4));
            }
        }
        part2.getImmutable();

//        System.out.println("Pairing Product: " + part2);
//        System.out.println("part2: " + part2);
//        System.out.println("e(C1, K0)/Pairing Product: "+ part1.div(part2));

        M1 = C0.div(part1.div(part2)).getImmutable();

        System.out.println("HVE M: " + M);
        System.out.println("HVE M': " + M1);
        flag = M.isEqual(M1);
        return flag;
    }


    @Override
    public Map<String, Object> test(String word, List<String> words, int round) {
        Map<String, Object> data = super.test(word, words, round);
        data.put("flag", flag);
        data.put("M", M);
        data.put("M1", M1);
        return data;
    }

}
