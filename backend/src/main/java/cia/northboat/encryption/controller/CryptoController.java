package cia.northboat.encryption.controller;

import cia.northboat.encryption.crypto.auth.model.CryptoMap;
import cia.northboat.encryption.crypto.auth.model.KeyPair;
import cia.northboat.encryption.service.*;
import cia.northboat.encryption.utils.ResultCode;
import cia.northboat.encryption.utils.ResultUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@Slf4j
@Controller
public class CryptoController {
    private final AuthService authService;
    private final BlockChainService blockChainService;
    private final IPFETreeService ipfeTreeService;
    private final PairingService pairingService;
    private final RangedSEService rangedSEService;
    @Autowired
    public CryptoController(AuthService authService, BlockChainService blockChainService,
                            IPFETreeService ipfeTreeService, PairingService pairingService,
                            RangedSEService rangedSEService){
        this.authService = authService;
        this.blockChainService = blockChainService;
        this.ipfeTreeService = ipfeTreeService;
        this.pairingService = pairingService;
        this.rangedSEService = rangedSEService;
    }

    @RequestMapping(value = "/test", method = RequestMethod.POST)
//    @ResponseBody → return Map<String, Object> data
    public String test(@RequestParam Map<String, String> params, Model model) {
        String algo = params.get("algo");
        String word = params.get("word");

        List<String> words = Collections.singletonList(word);

        int round = Integer.parseInt(params.get("round"));
        Map<String, Object> data = pairingService.test(algo, word, words, round);
        data.put("Msg", "If round > 1, the params showing on the page are the last round's");


        model.addAttribute("algo", algo);
        model.addAttribute("data", data);
        model.addAttribute("word", word);
        model.addAttribute("round", Integer.toString(round));
        return "/pages/pairing";
    }

    @GetMapping("/arch")
    public String arch(Model model) {
        model.addAttribute("params", rangedSEService.params());
        return "/pages/arch";  // 返回 templates/login.html 页面
    }

    @RequestMapping(value = "/auth", method = RequestMethod.GET)
    public String auth(Model model) {
        model.addAttribute("params", rangedSEService.params());
        model.addAttribute("data", rangedSEService.auth());
        return "/pages/arch";
    }

    @RequestMapping(value = "/buildMatrix", method = RequestMethod.GET)
    public String buildMatrix(Model model) {
        model.addAttribute("params", rangedSEService.params());
        model.addAttribute("data", rangedSEService.buildMatrix());
        return "/pages/arch";
    }


    @RequestMapping(value = "/query", method = RequestMethod.GET)
    public String query(Model model) {
        model.addAttribute("params", rangedSEService.params());
        model.addAttribute("data", rangedSEService.query());
        return "/pages/arch";
    }


    @RequestMapping(value = "/buildTree", method = RequestMethod.POST)
    public String buildTree(@RequestParam String count, @RequestParam String dimension, Model model) {
        int c = Integer.parseInt(count);
        int d = Integer.parseInt(dimension);
        model.addAttribute("data", ipfeTreeService.buildTree(c, d));
        model.addAttribute("count", count);
        model.addAttribute("dimension", dimension);
        return "/pages/tree";
    }

    @RequestMapping(value = "/search", method = RequestMethod.POST)
    public String search(@RequestParam String query, Model model) {

        String[] queryData = query.trim().split(",");
        for(int i = 0; i < queryData.length; i++){
            queryData[i] = queryData[i].trim();
        }
        List<String> q = List.of(queryData);
        log.info("Search data: {}", q);

        Map<String, Object> data = ipfeTreeService.search(q);
        data.put("query", q);

        model.addAttribute("data", data);
        return "/pages/tree";
    }

    @GetMapping("/signer")
    public String signer(@RequestParam("algo") String algo, Model model) {
        KeyPair keyPair = authService.keygen(algo);
        if(Objects.isNull(keyPair)){
            model.addAttribute("result", Map.of("error", "algo invalid"));
            return "/pages/sign";
        }

        CryptoMap signature = authService.sign(algo, "test", keyPair.sk);
        Boolean flag = authService.verify(algo, keyPair.pk, signature);

        model.addAttribute("algo", algo);
        model.addAttribute("data", Map.of(
                "pk", keyPair.pk,
                "sk", keyPair.sk,
                "signature", signature,
                "flag", flag
        ));

        return "/pages/sign";
    }

    // 密钥生成
    @RequestMapping("/keygen")
    @ResponseBody
    public ResultUtil keygen(@RequestParam Map<String, String> params){
        String algo = params.get("algo");
        KeyPair keyPair = authService.keygen(algo);
        if(keyPair == null){
            return ResultUtil.failure(ResultCode.PARAM_IS_INVALID);
        }
        return ResultUtil.success(keyPair);
    }

    // 签名
    @RequestMapping("/sign")
    @ResponseBody
    public ResultUtil sign(@RequestParam Map<String, Object> params){
        String algo = (String)params.get("algo");
        String message = (String)params.get("message");
        CryptoMap sk = (CryptoMap) params.get("sk");

        CryptoMap signature = authService.sign(algo, message, sk);
        if(signature == null){
            return ResultUtil.failure(ResultCode.INTERNAL_SERVER_ERROR);
        }

        return ResultUtil.success(signature);
    }


    // 认证
    @RequestMapping("/verify")
    @ResponseBody
    public ResultUtil verify(@RequestParam Map<String, Object> params){
        String algo = (String)params.get("algo");
        CryptoMap pk = (CryptoMap)params.get("pk");
        CryptoMap signature = (CryptoMap)params.get("signature");


        return ResultUtil.success(authService.verify(algo, pk, signature));
    }

    @RequestMapping(value = "/mine", method = RequestMethod.GET)
    public String mine(Model model) {
        int difficulty = 5;
        model.addAttribute("data", blockChainService.mine(difficulty));
        return "/pages/sign";
    }
}
