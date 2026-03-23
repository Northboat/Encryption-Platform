---
title: 基于属性加密的可搜索前缀多叉树
date: 2024-11-18 00:00:00
permalink: /pages/6ba8e2/
author: 
  name: Northboat
  link: https://github.com/Northboat
---

## IPFE 算法

### 公式

1️⃣ Keygen

选取生成元
$$
g,h\in G
$$
选取 l 长的随机数组
$$
s_i,t_i\in Z_p\quad i\in[1,l]
$$
计算数组
$$
h_i=g^{s_i}h^{t_i}\quad i\in[1,l]
$$
则系统公钥为
$$
mpk:=(G,Z_p,g,h,\{h_i\}_{i=1}^l)
$$
私钥
$$
msk:=(\{s_i\}_{i=1}^l,\{t_i\}_{i=1}^l)
$$

2️⃣ Encrypt

对明文数组 x 进行加密
$$
C_x=(s_x,t_x)=(\sum_{i=1}^ls_i\cdot x_i, \sum_{i=1}^lt_i\cdot x_i)
$$
实际上就是两个内积和

3️⃣ Trap

计算明文数据 y 的陷门，一个 l 长的整数数组，选取随机数 r，加密如下
$$
C = g^r\quad D=h^r
$$

$$
E_i=g^{y_i}h_i^r\quad i\in[1,l]
$$

密文 Cy 为
$$
C_y=(C,D,E_i)
$$

4️⃣ Match

根据主公钥，私钥 x 和查询 Cy 进行匹配
$$
E_{x,y}=\frac{\Pi_{i=1}^lE_i^{x_i}}{C^{s_x}\cdot D^{t_x}}=g^{<x_i,y_i>}
$$
"The inner product of the vectors x and y can be recovered from computing the discrete logarithm of Ex as regards the base g"

这个等式是恒成立的，如果想要做到“匹配”的效果，应该把等式右侧换为
$$
E_{x,y}\stackrel{?}{=}g^{<x_i,x_i>}
$$
这样的话，只有 y 完全等于 x 时，等式才成立，从而达到搜索匹配的效果

### IPFE 实现

初始化和密钥生成

```java
@Slf4j
public class IPFEUtil {

    private static int l;

    // 公钥
    public static Element g, h;
    private static Element[] s, t, h_i;


    public static Element getBase(){
        return g;
    }

    public static void keygen(Field G1, Field Zr, int n){

        l = n;
        g = G1.newRandomElement().getImmutable();
        h = G1.newRandomElement().getImmutable();

        s = new Element[n];
        t = new Element[n];
        h_i = new Element[n];
        for(int i = 0; i < n; i++){
            s[i] = Zr.newRandomElement().getImmutable();
            t[i] = Zr.newRandomElement().getImmutable();
            h_i[i] = g.powZn(s[i]).mul(h.powZn(t[i])).getImmutable();
        }

    }
}
```

加密，加密对象是`Element[] m`

1. 将明文哈希 m 扩充长度至 l（用 Zero 填充）得到 x
2. 使用密钥 `s, t`对填充后的 x 进行 IPFE 加密，构建 TreeNode

其中`String[] prefix, int n`其实不参与加密，但要作为属性封装进 TreeNode 用于后续构造和搜索

```java
// 加密生成节点，关键的加密原料 x 完全来自于哈希过的明文 m
// 加密长度和数据维度保持一致
public static TreeNode enc(Field Zr, String[] prefix, Element[] x){

    //        System.out.println("====== Encrypt ======");
    Element s1 = Zr.newZeroElement();
    Element s2 = Zr.newZeroElement();

    for(int i = 0; i < l; i++){
        s1 = s1.add(s[i].mul(x[i]));
        s2 = s2.add(t[i].mul(x[i]));
    }
    Element s_x = s1.getImmutable();
    Element t_x = s2.getImmutable();

    return TreeNode.builder()
        .x(x)
        .t_x(t_x)
        .s_x(s_x)
        .prefix(prefix)
        .n(l)
        .subtree(new TreeNode[(int)Math.pow(2, l)])
        .build();
}
```

计算陷门，同样接收用户输入`Element[] q`，与加密过程的`Element[] m`一样，得到一份密文`Ciphertext`

```java
public static Ciphertext trap(Field Zr, Element[] y){

    Element r = Zr.newRandomElement().getImmutable();
    int n = y.length;
    Element C = g.powZn(r).getImmutable();
    Element D = h.powZn(r).getImmutable();
    Element[] E = new Element[n];
    for(int i = 0; i < n; i++){
        E[i] = g.powZn(y[i]).mul(h_i[i].powZn(r)).getImmutable();
    }

    return Ciphertext.builder()
        .y(y)
        .C(C)
        .D(D)
        .E(E)
        .build();
}

```

输入 TreeNode 和 Ciphertext 进行匹配

```java
public static Boolean match(Field G1, Field Zr, TreeNode node, Ciphertext text, Element g){
    Element[] x = node.getX();
    Element s_x = node.getS_x();
    Element t_x = node.getT_x();
    int n = x.length;

    Element e = G1.newOneElement();
    for(int i = 0; i < n; i++){
        e = e.mul(text.getE()[i].powZn(x[i]));
    }
    Element p1 = e.getImmutable();

    Element p2 = text.getC().powZn(s_x).mul(text.getD().powZn(t_x)).getImmutable();
    Element left = p1.div(p2).getImmutable(); // Ex

    //        Element[] y = text.getY();
    Element right = g.powZn(innerProduct(Zr, x, x)).getImmutable();

    log.info("IPFE Match:\nleft:{}\nright:{}", left, right);
    return left.isEqual(right);
}

// 内积计算
public static Element innerProduct(Field Zr, Element[] x1, Element[] x2){
    Element product = Zr.newZeroElement();
    int n = x1.length;
    for(int i = 0; i < n; i++){
        product = product.add(x1[i].mul(x2[i]));
    }
    return product.getImmutable();
}
```

### 加密流程

无论是加密 enc 还是陷门 trap，用户的核心输入是一个字符串数组，包含当前插入数据的所有字段，例如

```java
String[] str1 = new String[]{"nmsl", "wcnm", "wdnmd"};
String[] str2 = new String[]{"nmsl", "test", "sad"};
String[] str3 = new String[]{"nmsl", "test", "sad", "wdnmd"};
```

可以发现字段个数是灵活的，如上分别是`2, 3, 4`，他们分别对应了三种树，即四叉树、八叉树和十六叉树（为什么会这样具体可以看下一节的`索引构建-前缀编码`部分）

用户的关键输入是一个变长的字符串数组，来表示即将插入的数据

```java
public TreeNode insert(String[] cur){
    // 将明文哈希，将用于前缀比较和 x 生成
    Element[] curX = HashUtil.hashStrArr2ZrArr(Zr, cur);
    if(root == null){
        String[] initPrefix = new String[n];
        // 初始化一个前缀，这会浪费 n 长度的前缀
        Arrays.fill(initPrefix, "0");
        root = IPFEUtil.enc(Zr, initPrefix, curX);
        height++;
        return root;
    }
    return insert(root.getPrefix(), curX, root, 1);
}
```

加密其实就是用的上面的 IPFEUtil.enc，公式中的 x 数组来自于用户输入的`String[]`哈希，有这样一个小细节

当第一次插入时，由于没有根节点，需要手动构造前缀，这里的处理是浪费一层全 0 的前缀，例如三维数据第一次插入的前缀将会是`000`，而后的插入将在这个前缀基础上叠加为`010101, 000001`等等

## 索引构建

### 前缀编码

对于`String[]`中的单个字段

1. 进行 hash，得到一个 Zr 群上元素
2. 而后与已有字段进行比较（根），若小于则前缀添 0，大于等于则添 1

举一个例子：我现在有一个数据`["nmsl", "wcnm", "wdnmd"]`，我要把它插入到树中，那么，对于这个三维数据

- 首先会对每个字段进行哈希，将每个字符串都映射为一个 Zr 群元素，得到一个`Element[] m`，假设为`[213892, 213213, 897891]`
- 而后进行插入，假设当前的根节点的哈希值为`[312333, 321333, 531211]`，其前缀为`[10, 01, 10]`，那么这个新插入数据由于哈希值
  - 第一个字段小于根
  - 第二个字段小于根
  - 第三个字段大于根

于是新添加前缀为`001`，这个新节点的前缀码就会为`[100, 010, 101]`

子树的排布问题：还是以上述例子为例，由于是一个三维数据，所以每个节点都会有 8 个子树

- 这由前缀码的长度决定，由于是 3 维所以每次比较会多出 3 位前缀，相应的，二维数据将多出 2 位前缀

前缀均为 1/0 串，视为二进制数，进而三位 2 进制数表示 8 个十进制数，四位 2 进制数表示 16 个十进制数，即子树的个数

再回到刚刚的例子，由于添加的前缀码为 001，故这个新节点应放在根的第一个子树位置（因为 001 的十进制为 1）

代码实现

```java
public class EncodeUtil {
    /*
        一维编码，对单个字段进行简单的大小编码，大于则为 1，小于则为 0
     */
    public static String singleDimensionDec(Element[] m, Element[] w, int n){
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < n; i++){
            BigInteger a = m[i].toBigInteger();
            BigInteger b = w[i].toBigInteger();
            if(a.compareTo(b) < 0 || a.compareTo(b) == 0){ // 当 w 大于等于 m 添 1
                sb.append("1");
            } else { // 当 w 小于 m 添 0
                sb.append("0");
            }
        }
        return sb.toString();
    }

    // 根据原有前缀和新添的前缀构造新的前缀
    public static String[] superposePrefix(String[] prefix, String cur, int n){
        String[] newPrefix = new String[n];
        for(int i = 0; i < n; i++){
            newPrefix[i] = prefix[i] + cur.charAt(i);
        }
        return newPrefix;
    }
}
```

### 数据结构

树节点 TreeNode，其中

- `n`是维度
- `x`是明文的哈希值
- `prefix`是前缀码
- `subtree`是子树
- 其余是 IPFE 的密文

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TreeNode {

    private int n; // 长度
    private String[] prefix; // 前缀
    private TreeNode[] subtree; // 子树

    // 密文
    private Element[] x; // 这个 x 是哈希后的明文，用于比较生成前缀，同时用来加密
    private Element s_x, t_x;


    public String getPrefixStr(){
        StringBuilder sb = new StringBuilder();
        for(String s : prefix){
            sb.append(s);
        }
        return sb.toString();
    }


    public void setSubtree(TreeNode t, int i){
        this.subtree[i] = t;
    }
}
```

陷门密文结构 Ciphertext

```java
@Data
@AllArgsConstructor
public class Ciphertext {
    Element[] y;
    Element C;
    Element D;
    Element[] E;
}
```

和上面的公式保持一致

### 多叉树构造

#### 初始化

初始化，维护一个根节点 root，以及加密所需的群和哈希长度，还有树高度

```java
@Getter
@Setter
@Component
public class EncryptedTree {

    TreeNode root;
    Field G1, Zr;
    int height, n; // 这个 n 是字段的个数 → 树的维度

    @Autowired
    public EncryptedTree(Field G1, Field Zr){
        this.G1 = G1;
        this.Zr = Zr;
        height = 0;
    }

    public void init(int dimension){
        setN(dimension);
        IPFEUtil.keygen(G1, Zr, dimension);
    }


    public void clean(){
        root = null;
        height = 0;
    }
}
```

#### 节点插入

构造最关键的实现

```java
public TreeNode insert(String[] cur){
    // 将明文哈希，将用于前缀比较和 x 生成
    Element[] curX = HashUtil.hashStrArr2ZrArr(Zr, cur);
    if(root == null){
        String[] initPrefix = new String[n];
        // 初始化一个前缀，这会浪费 n 长度的前缀
        Arrays.fill(initPrefix, "0");
        root = IPFEUtil.enc(Zr, initPrefix, curX);
        height++;
        return root;
    }
    return insert(root.getPrefix(), curX, root, 1);
}


public TreeNode insert(String[] pre, Element[] curX, TreeNode root, int h){

    int n = root.getN();
    Element[] x = root.getX();

    String z = EncodeUtil.singleDimensionDec(x, curX, n); // 增加的前缀
    String[] newPrefix = EncodeUtil.superposePrefix(pre, z, n); // 构成新的前缀

    TreeNode node = IPFEUtil.enc(Zr, newPrefix, curX); // 根据当前前缀和明文哈希生成节点

    int i = Integer.parseInt(z, 2); // 解析二进制为十进制
    TreeNode child = root.getSubtree()[i];
    h++; // 选取到了孩子，层高 +1

    // 如果这里为空，就直接插入
    if(child == null){
        root.setSubtree(node, i);
        height = Math.max(height, h);
        return node;
    }
    // 否则继续向下找
    return insert(newPrefix, curX, child, h);
}
```

#### 树构造

构造 build，反复的调用 insert 即可

```java
public String randomBuild(int count){
    List<List<String>> data = generateData(count, getN());
    build(data);
    return getTreeStruct();
}


public void build(List<List<String>> list){
    for(List<String> l : list){
        insert(l.toArray(new String[0]));
    }
}
```

## 可加密搜索

### 匹配

但节点密文匹配，真正的 match 逻辑在第一节 IPFE 实现中

```java
public boolean match(TreeNode node, Ciphertext ciphertext){
    Element g = IPFEUtil.getBase();
    return IPFEUtil.match(G1, Zr, node, ciphertext, g);
}
```

### 搜索

从根节点开始进行匹配，若 match 成功则直接返回当前结点，若失败则根据前缀码找到相应子树，继续向下匹配

```java
public TreeNode search(String[] cur){
    // 将明文哈希
    Element[] y = HashUtil.hashStrArr2ZrArr(Zr, cur);

    Ciphertext ciphertext = IPFEUtil.trap(Zr, y);
    return search(root, ciphertext);
}


public TreeNode search(TreeNode node, Ciphertext ciphertext){
    if(node == null || ciphertext == null){
        return null;
    }
    if(match(node, ciphertext)) {
        return node;
    }

    String z = EncodeUtil.singleDimensionDec(node.getX(), ciphertext.getY(), n); // 增加的前缀
    int i = Integer.parseInt(z, 2);

    return search(node.getSubtree()[i], ciphertext);
}
```

## 功能测试

### 数据构造

手搓随机数据

```java
public List<List<String>> generateData(int count, int dimension){
    Set<List<String>> uniqueLists = new HashSet<>();
    while (uniqueLists.size() < count) {
        List<String> innerList = new ArrayList<>();
        for (int j = 0; j < dimension; j++) {
            // 这里用 UUID 或者随机数
            innerList.add(UUID.randomUUID().toString().substring(0, 8));
            // innerList.add("val_" + random.nextInt(10000)); // 也可以用随机数
        }
        uniqueLists.add(innerList); // HashSet 会帮我们去重
    }

    return new ArrayList<>(uniqueLists);
}

```

树的打印，就是一个 DFS 加字符串处理

```java
public String getTreeStruct() {
    StringBuilder sb = new StringBuilder();
    getTreeStruct(root, "", false, sb);
    return sb.toString();
}

// DFS
public void getTreeStruct(TreeNode node, String prefix, boolean isTail, StringBuilder sb) {
    if (node == null) return;

    sb.append(prefix).append(isTail ? "└── " : "├── ");
    sb.append(formatPrefix(node)).append("\n");
    TreeNode[] children = node.getSubtree();
    int childCount = (int) Arrays.stream(children).filter(Objects::nonNull).count();

    int printed = 0;
    for (int i = 0; i < (int)Math.pow(2, n); i++) {
        TreeNode child = children[i];
        if (child != null) {
            printed++;
            boolean last = (printed == childCount);
            getTreeStruct(child, prefix + (isTail ? "    " : "│   "), last, sb);
        }
    }
}

public String formatPrefix(TreeNode node){
    return node.getPrefixStr() != null ? node.getPrefixStr() : "";
}
```

### 接口设计

IPFETreeService.java

```java
public Map<String, Object> buildTree(int count, int dimension){
    Map<String, Object> data = new HashMap<>();

    long s = System.currentTimeMillis();
    encryptedTree.clean();
    String tree = encryptedTree.randomBuild(count, dimension);
    long e = System.currentTimeMillis();
    data.put("time_cost", e-s);


    String htmlTreeStr = tree.replace("\n", "<br>");
    htmlTreeStr = htmlTreeStr.replace(" ", "&nbsp;");
    data.put("tree", htmlTreeStr);

    System.out.println("Tree Height: " + encryptedTree.getHeight());
    data.put("height", encryptedTree.getHeight());

    return data;
}
```

CryptoController.java

```java
@RequestMapping(value = "/buildTree", method = RequestMethod.POST)
public String buildTree(@RequestParam String count, @RequestParam String dimension, Model model) {
    int c = Integer.parseInt(count);
    int d = Integer.parseInt(dimension);
    model.addAttribute("data", ipfeTreeService.buildTree(c, d));
    model.addAttribute("count", count);
    model.addAttribute("dimension", dimension);
    return "/pages/tree";
}
```

构建 200 个节点可搜索加密八叉树

- height: 8
- time_cost: 48 ms

```
tree
├── 000
│   ├── 000000
│   │   ├── 000001000
│   │   ├── 001000000
│   │   │   └── 001000000000
│   │   └── 001001000
│   │       └── 001000110000
│   │           └── 001010011100000
│   ├── 000001
│   │   ├── 000000010
│   │   │   ├── 000100000100
│   │   │   │   └── 000110000001000
│   │   │   │       └── 000110000001010000
│   │   │   ├── 000100010100
│   │   │   │   └── 000110001001001
│   │   │   │       ├── 000110000101010010
│   │   │   │       └── 000111000100010010
│   │   │   └── 000100010101
│   │   ├── 000000011
│   │   │   ├── 000000000110
│   │   │   │   └── 000010000001100
│   │   │   ├── 000000000111
│   │   │   │   ├── 000010000001111
│   │   │   │   │   └── 000011000001011110
│   │   │   │   └── 000010000101111
│   │   │   │       └── 000010000010011111
│   │   │   ├── 000000010110
│   │   │   └── 000000010111
│   │   ├── 001000010
│   │   │   ├── 001000000101
│   │   │   │   ├── 001000000001010
│   │   │   │   ├── 001000000101010
│   │   │   │   │   ├── 001000000011010101
│   │   │   │   │   └── 001001000011010101
│   │   │   │   ├── 001000000101011
│   │   │   │   └── 001010000001010
│   │   │   ├── 001000010101
│   │   │   │   ├── 001000001101010
│   │   │   │   ├── 001000001101011
│   │   │   │   └── 001010001101010
│   │   │   │       └── 001011000111010101
│   │   │   ├── 001100000101
│   │   │   ├── 001100010100
│   │   │   └── 001100010101
│   │   └── 001000011
│   │       ├── 001000000111
│   │       ├── 001100000110
│   │       └── 001100000111
│   │           ├── 001100000001111
│   │           │   └── 001101000001011110
│   │           └── 001110000001111
│   ├── 000100
│   │   ├── 000010000
│   │   │   ├── 000101000000
│   │   │   └── 000101000001
│   │   │       └── 000110100100011
│   │   ├── 000010001
│   │   ├── 000011001
│   │   ├── 001010000
│   │   └── 001011000
│   ├── 000101
│   │   ├── 000010010
│   │   │   └── 000101000100
│   │   ├── 000010011
│   │   │   ├── 000001000110
│   │   │   ├── 000001000111
│   │   │   │   ├── 000000100101110
│   │   │   │   ├── 000000100101111
│   │   │   │   ├── 000010100001110
│   │   │   │   └── 000010100101111
│   │   │   └── 000001010111
│   │   ├── 000011010
│   │   │   ├── 000001100100
│   │   │   ├── 000001100101
│   │   │   ├── 000101100100
│   │   │   │   └── 000100110101000
│   │   │   ├── 000101100101
│   │   │   ├── 000101110100
│   │   │   └── 000101110101
│   │   ├── 000011011
│   │   │   ├── 000001100110
│   │   │   │   ├── 000000110001100
│   │   │   │   └── 000010110101100
│   │   │   ├── 000001110110
│   │   │   │   ├── 000000111101101
│   │   │   │   ├── 000010111001100
│   │   │   │   └── 000010111101101
│   │   │   ├── 000101100110
│   │   │   │   ├── 000100110001101
│   │   │   │   ├── 000100110101101
│   │   │   │   │   ├── 000100011011011011
│   │   │   │   │   └── 000101011011011010
│   │   │   │   └── 000110110001101
│   │   │   ├── 000101100111
│   │   │   ├── 000101110110
│   │   │   │   ├── 000100111001101
│   │   │   │   ├── 000100111101101
│   │   │   │   ├── 000110111001101
│   │   │   │   └── 000110111101100
│   │   │   └── 000101110111
│   │   ├── 001010010
│   │   │   ├── 001101000101
│   │   │   └── 001101010101
│   │   │       ├── 001100101101011
│   │   │       └── 001110101001011
│   │   ├── 001010011
│   │   │   ├── 001001010111
│   │   │   ├── 001101000110
│   │   │   │   └── 001100100101100
│   │   │   ├── 001101000111
│   │   │   │   ├── 001100100001111
│   │   │   │   └── 001100100101111
│   │   │   │       └── 001101010011011110
│   │   │   │           └── 001101101001100111101
│   │   │   ├── 001101010110
│   │   │   └── 001101010111
│   │   │       └── 001100101001111
│   │   │           ├── 001100010100011111
│   │   │           ├── 001101010100011110
│   │   │           │   └── 001101101010010111100
│   │   │           └── 001101010101011111
│   │   ├── 001011010
│   │   └── 001011011
│   │       ├── 001101110110
│   │       └── 001101110111
│   │           ├── 001110111001111
│   │           │   ├── 001111011100011110
│   │           │   └── 001111011100011111
│   │           │       ├── 001111101110000111110
│   │           │       │   └── 001111110111000101111101
│   │           │       └── 001111101110010111110
│   │           ├── 001110111101110
│   │           └── 001110111101111
│   │               ├── 001110011110011110
│   │               └── 001111011110011110
│   ├── 010000
│   │   ├── 010000001
│   │   │   └── 010000000010
│   │   │       └── 010010000100101
│   │   └── 010001001
│   ├── 010001
│   │   ├── 010000010
│   │   ├── 010000011
│   │   │   ├── 010000000110
│   │   │   │   └── 010000000001101
│   │   │   │       └── 010001000000011010
│   │   │   ├── 010000000111
│   │   │   │   ├── 010010000001110
│   │   │   │   └── 010010000101110
│   │   │   └── 010000010111
│   │   ├── 010001011
│   │   ├── 011000011
│   │   │   ├── 011000000111
│   │   │   └── 011000010111
│   │   └── 011001011
│   │       └── 011000100110
│   ├── 010100
│   │   ├── 010011000
│   │   └── 010011001
│   │       └── 010101110010
│   └── 010101
│       ├── 010010010
│       │   ├── 010001000101
│       │   ├── 010001010100
│       │   ├── 010001010101
│       │   ├── 010101010100
│       │   └── 010101010101
│       │       └── 010100101001011
│       ├── 010010011
│       │   └── 010001010110
│       │       └── 010000101001100
│       ├── 010011010
│       ├── 011010010
│       │   ├── 011001000101
│       │   │   └── 011000100101011
│       │   │       └── 011000010010010111
│       │   ├── 011001010101
│       │   │   └── 011010101001011
│       │   ├── 011101000101
│       │   │   ├── 011110100001010
│       │   │   ├── 011110100001011
│       │   │   │   ├── 011110010000010111
│       │   │   │   └── 011111010000010110
│       │   │   └── 011110100101010
│       │   ├── 011101010100
│       │   │   └── 011100101101001
│       │   └── 011101010101
│       ├── 011010011
│       │   ├── 011001000110
│       │   │   ├── 011000100101100
│       │   │   └── 011010100101101
│       │   ├── 011001000111
│       │   ├── 011101000110
│       │   │   └── 011100100001101
│       │   ├── 011101000111
│       │   └── 011101010110
│       ├── 011011010
│       │   └── 011001100101
│       └── 011011011
│           └── 011101110111
```

## 性能测试

这样几个测试因素

- 数据维度：这决定了树的维度（2 的指数关系），加密数组 x / y 的维度（保持一致）
- 数据量：树的节点数量，如`5000, 10000, 20000`

这样几个测试的关键开销

- 索引构建时间
- 陷门计算时间
- 匹配时间

存储开销测试，引入 JOL 依赖，此事在 Winter Framework 的第十步亦有记载

```xml
<dependency>
    <groupId>org.openjdk.jol</groupId>
    <artifactId>jol-core</artifactId>
    <version>0.16</version>
</dependency>
```

测试对象 Object 的内存占用

```java
String[] str1 = new String[]{"nmsl", "test", "wcnm"};
TreeNode t1 = TREE.insert(str1);

String[] str2 = new String[]{"nmsl", "test", "sad"};
TreeNode t2 = TREE.insert(str2);

System.out.println(t1);
System.out.println(t2);

System.out.println(TREE.getTreeStruct());
System.out.println(ClassLayout.parseInstance(t1).toPrintable());
System.out.println(ClassLayout.parseInstance(t2).toPrintable());
```

打印结果

```java
cia.northboat.se.crypto.tree.model.TreeNode object internals:
OFF  SZ                                            TYPE DESCRIPTION               VALUE
  0   8                                                 (object header: mark)     0x0000000000000001 (non-biasable; age: 0)
  8   4                                                 (object header: class)    0x00fe6448
 12   4                                             int TreeNode.n                3
 16   4                              java.lang.String[] TreeNode.prefix           [(object), (object), (object)]
 20   4   cia.northboat.se.crypto.tree.model.TreeNode[] TreeNode.subtree          [null, null, null, null, null, null, null, null]
 24   4                 it.unisa.dia.gas.jpbc.Element[] TreeNode.x                [(object), (object), (object)]
 28   4                   it.unisa.dia.gas.jpbc.Element TreeNode.s_x              (object)
 32   4                   it.unisa.dia.gas.jpbc.Element TreeNode.t_x              (object)
 36   4                                                 (object alignment gap)    
Instance size: 40 bytes
Space losses: 0 bytes internal + 4 bytes external = 4 bytes total
```

其中

- `Instance size`表示该对象的实际内存占用
- `Space losses`表示存储该对象浪费的内存大小（主要是为了内存对齐）
