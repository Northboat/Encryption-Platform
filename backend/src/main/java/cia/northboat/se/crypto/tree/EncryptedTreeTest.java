package cia.northboat.se.crypto.tree;

import cia.northboat.se.crypto.tree.model.TreeNode;
import cia.northboat.se.utils.CsvReaderUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openjdk.jol.info.ClassLayout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class EncryptedTreeTest {

    @Autowired
    private CsvReaderUtil csvReaderUtil;
    @Autowired
    private EncryptedTree TREE;

    private List<List<String>> data;

    @BeforeEach
    public void setup(){
        int dimension = 3, size = 5000;
        TREE.init(dimension);
        data = csvReaderUtil.readCsvWithRange("classpath:test_data/csv/hi.csv", 0, dimension-1, size);
        System.out.println(data.size());
    }

    @Test
    public void insert(){
//        String[] str1 = new String[]{"nmsl", "test", "wcnm", "wdnmd"};
        String[] str1 = new String[]{"nmsl", "test", "wcnm"};
        TreeNode t1 = TREE.insert(str1);

//        String[] str2 = new String[]{"nmsl", "test", "sad", "wdnmd"};
        String[] str2 = new String[]{"nmsl", "test", "sad"};
        TreeNode t2 = TREE.insert(str2);

        System.out.println(t1);
        System.out.println(t2);

        System.out.println(TREE.getTreeStruct());
        System.out.println(ClassLayout.parseInstance(t1).toPrintable());
        System.out.println(ClassLayout.parseInstance(t2).toPrintable());

        assertEquals(2, TREE.getSize()-1);
    }

    @Test
    public void build(){
        long cost = 0;
        int loop = 10;
        for(int i = 0; i < loop; i++)
            cost += TREE.build(data);

        System.out.println(TREE.getTreeStruct());
        System.out.println(cost/10 + "ms");

        assertEquals(data.size(), (TREE.getSize()-1) / loop);
    }



    @AfterEach
    public void search(){
        List<TreeNode> result = new ArrayList<>();

        int loop = 10;

        long s = System.currentTimeMillis();
        for(int i = 1; i <= loop; i++){
            result.add(TREE.search(data.get(490*i)));
        }
        long e = System.currentTimeMillis();

        System.out.println((e-s) / loop);


        System.out.println(ClassLayout.parseInstance(result.get(9)).toPrintable());
        assertEquals(loop, result.size());
    }
}
