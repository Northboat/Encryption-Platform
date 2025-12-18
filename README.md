# Ark Encryption Platform

加密仿真平台，可以看见设计模式的变迁

- `arch` → `pairing` → `tree` → `auth`，从朴素的实现，到策略模式 / 工厂模式的运用

环境

- Win 10
- JDK 17
- JPBC 2.0.0
- IDEA 2022.3
- Maven 3.9.1
- Spring Boot 3.0.x

## 基于 Pairing 的 SE 算法仿真

实现：`src/main/java/cia/northboat/encryption/crypto/pairing`

```
interface SearchableEncryption
↓ implements
abstract class PairingSystem
↓ extends
class ...
```

测试：`src/test/java/cia/northboat/encryption/test/PairingTest`

数据：`src/test/resources/data/*.txt`

算法清单

| 序号 | 算法     | 实现情况 |
| ---- | -------- | -------- |
| 1    | SPWSE Ⅰ  | √        |
| 2    | SPWSE Ⅱ  | √        |
| 3    | PAUKS    | √        |
| 4    | SA-PAEKS | √        |
| 5    | dIBAEKS  | √        |
| 6    | DuMSE    | ×        |
| 7    | pMatch   | √        |
| 8    | CR-IMA   | √        |
| 9    | TuCR     | ⍻        |
| 10   | Tu2CKS   | ⍻        |
| 11   | PAEKS    | √        |
| 12   | TMS      | √        |
| 13   | TBEKS    | √        |
| 14   | Gu2CKS   | √        |
| 15   | FIPECK   | √        |
| 16   | SCF      | √        |
| 17   | PECKS    | √        |
| 18   | AP       | √        |
| 19   | PAKS     | √        |
| 20   | DPREKS   | √        |
| 21   | PREKS    | √        |
| 22   | HVE      | √        |

## 基于 BM25 算法的范围可搜索加密系统原型

实现：`src/main/java/cia/northboat/encryption/crypto/arch/RangedSEArchetype`

数据：`src/resources/data/*`

## 基于属性加密的可搜索加密四叉树构建与检索

实现：`src/main/java/cia/northboat/encryption/crypto/arch/tree/EncryptedTreeTest`

测试：`src/test/java/cia/northboat/encryption/test/EncryptedTreeTest`

数据：`src/test/resources/data/hi.csv`

## 签名算法仿真

算法清单

| 序号 | 算法    | 实现情况 |
| ---- | ------- | -------- |
| 1    | RSA     | √        |
| 2    | Schnorr | √        |
| 3    | Elgamal | √        |

## 简单的挖矿程序

`src/main/java/cia/northboat/encryption/crypto/arch/SimpleMinerArchetype`
