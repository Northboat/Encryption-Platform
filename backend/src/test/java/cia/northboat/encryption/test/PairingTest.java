package cia.northboat.encryption.test;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
import cia.northboat.encryption.crypto.pairing.impl.*;
import cia.northboat.encryption.utils.FileUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;


@SpringBootTest
public class PairingTest {

    @Autowired
    private Field<?> G1, G2, GT, Zr;

    @Autowired
    private Pairing bp;


    public static List<List<Long>> times = new ArrayList<>();

    public List<String> readFile(String file){
        return FileUtil.readFileToList(file);
    }

    @Test
    public void singleThreadTest(){
        int round = 1;
        String w = "hello world";
        List<String> words = readFile("2.txt");

        PairingSystem pauks = new PAUKS(G1, GT, Zr, bp);
        PairingSystem sapauks = new SAPAUKS(G1, GT, Zr, bp);
        PairingSystem dibaeks = new DIBAEKS(G1, GT, Zr, bp);
        PairingSystem pmatch = new PMatch(G1, GT, Zr, bp);
        PairingSystem crima = new CRIMA(G1, GT, Zr, bp);
        PairingSystem tu2cks = new Tu2CKS(G1, GT, Zr, bp);
        PairingSystem tucr = new TuCR(G1, GT, Zr, bp);
        PairingSystem dumse = new DuMSE(G1, GT, Zr, bp);
        PairingSystem paeks = new PAEKS(G1, GT, Zr, bp);
        PairingSystem spwse1 = new SPWSE1(G1, GT, Zr, bp, G2);
        PairingSystem spwse2 = new SPWSE2(G1, GT, Zr, bp);
        PairingSystem peks = new PEKS(G1, GT, Zr, bp);
        PairingSystem dpreks = new DPREKS(G1, GT, Zr, bp);
        PairingSystem preks = new PREKS(G1, GT, Zr, bp);
        PairingSystem fipeck = new FIPECK(G1, GT, Zr, bp);


        test(pauks, w, null, round);
        test(sapauks, w, null, round);

        test(crima, w, null, round);
        test(dibaeks, w, null, round);
        test(dpreks, w, null, round);
        test(dumse, w, null, round);

        test(fipeck, w, null, round);
        test(pmatch, w, null, round);

        test(tu2cks, w, null, round);
        test(tucr, w, null, round);

        test(paeks, w, null, round);
        test(spwse1, w, null, round);
        test(spwse2, w, null, round);
        test(peks, w, null, round);
        test(preks, w, null, round);

        PairingSystem tms = new TMS(G1, GT, Zr, bp);
        PairingSystem tbeks = new TBEKS(G1, GT, Zr, bp);
        PairingSystem gu2cks = new Gu2CKS(G1, GT, Zr, bp);

        test(tms, "", words, round);
        test(tbeks, "", words, round);
        test(gu2cks, "", words, round);

        printTime();
    }

    public void test(PairingSystem pairingSystem, String word, List<String> words, int m){
        System.out.println(pairingSystem.getClass() + " test:");

        Map<String, Object> res = pairingSystem.test(word, words, m);

        long encCost = (long) res.get("EncCost");
        long trapCost = (long) res.get("TrapCost");
        long searchCost = (long) res.get("SearchCost");

        if(pairingSystem.getUpdatable()){
            encCost += (long) res.get("ReEncCost");
            trapCost += (long) res.get("ConstTrapCost");
            searchCost += (long) res.get("UpdateSearchCost");
        }
        times.add(Arrays.asList(encCost, trapCost, searchCost));

        System.out.println(pairingSystem.getClass() + " test finished!\n");
    }


    public void multiThreadTest() {
        int round = 1, sender = 1, receiver = 1;

        List<String> words = readFile("2.txt");

        PairingSystem ap = new AP(G1, GT, Zr, bp, G2);
        PairingSystem scf = new SCF(G1, GT, Zr, bp);
        PairingSystem pecks = new PECKS(G1, GT, Zr, bp);

        List<PairingSystem> pairingSystems = new ArrayList<>();
        pairingSystems.add(scf);
        pairingSystems.add(ap);
        pairingSystems.add(pecks);

        executorServiceTest(pairingSystems, words, sender, receiver, round);

        System.out.println("The Time Cost Log in ./time.log");
    }


    // 简单的多线程测试，数据量太大了，应该能快点
    public void executorServiceTest(List<PairingSystem> pairingSystems, List<String> words,
                                           int sender, int receiver, int round){
        int n = pairingSystems.size();

        System.out.println("Thread Pool Start, " + n + " Threads in Total");

        // 需要测试的算法数量
        List<List<Long>> times = new ArrayList<>(n);
        for (PairingSystem system : pairingSystems) {
            System.out.println(system.getClass() + "Test");
            times.add(new ArrayList<>());
        }
        ExecutorService executor = Executors.newFixedThreadPool(n);
        List<Future<List<Long>>> futures = new ArrayList<>();
        // 提交任务
        for(PairingSystem pairingSystem : pairingSystems){
            futures.add(executor.submit(() -> pairingSystem.test(words, sender, receiver, round)));
        }

        // 获取结果
        try {
            // 这一步是阻塞的，用 set 保证各算法先后次序是我所希望的
            for(int i = 0; i < n; i++){
                Future<List<Long>> future = futures.get(i);
                times.set(i, future.get());
            }
            // 记录结果
            logTime(times);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            // 关闭线程池
            executor.shutdown();
            System.out.println("Thread Pool Shutdown");
        }
    }

    public void printTime(){
        System.out.println("=== Time Cost ===");
        for(List<Long> t: times){
            for(long i: t){
                System.out.print(i + "\t");
            }
            System.out.println();
        }
        System.out.println();
    }

    public void logTime(List<List<Long>> times){
        FileUtil.writeCostToLog("============= Time Cost ============\n");
        for(List<Long> t: times){
            for(int i = 0; i < t.size(); i++){
                if(i != 0){
                    FileUtil.writeCostToLog("\t" + t.get(i));
                    continue;
                }
                FileUtil.writeCostToLog(t.get(i) + "");
            }
            FileUtil.writeCostToLog("\n");
        }
        FileUtil.writeCostToLog("\n\n");
    }


    public void testMem(Field G1, Field G2, Field GT, Field Zr){
        Element g1 = G1.newRandomElement();
        Element g2 = G2.newRandomElement();
        Element gt = GT.newRandomElement();
        Element zr = Zr.newRandomElement();

        int a = 100, b = 100, n = 2, m = 2, lambda = 32;
        int g1Length = g1.toBytes().length, g2Length = g2.toBytes().length, gtLength = gt.toBytes().length, zrLength = zr.toBytes().length;

        int AP1, AP2, SCF, PECKS;
        for(int i = 0; i < 7; i++){

            // 密钥传输 1
//            AP1 = a*(G1+G2+ZR);
//            SCF = a*(G1+ZR);
//            PECKS = a*(3*G1+ZR);
            // 密钥传输 2
//            AP1 = b*(G2+ZR);
//            SCF = b*(G1+ZR);
//            PECKS = b*(3*G1+ZR);


            // 密文传输
//            AP1 = a*(GT+(n+3)*G2+G1);
//            AP2 = (a*b-a)*(3*GT+(n+3)*G2+2*G1);
//            SCF = (a*b*n)*(9*lambda);
//            PECKS = a*((n+3)*G1);

            // 陷门传输
            AP1 = b*((n+3)*g1Length+zrLength);
            AP2 = (a*b-b)*((n+3)*g1Length+zrLength);
            SCF = (a*b*m)*g1Length;
            PECKS = b*((n+4)*g1Length);



            System.out.println(AP1);
            System.out.println(AP2);
            System.out.println(SCF);
            System.out.println(PECKS);
            System.out.println();

//            a += 50;
            b += 50;
//            m += 100;
//            n += 100;
        }
    }

}
