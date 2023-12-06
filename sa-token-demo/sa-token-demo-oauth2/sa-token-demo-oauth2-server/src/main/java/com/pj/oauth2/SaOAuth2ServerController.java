package com.pj.oauth2;

import java.security.*;
import java.util.*;

import cn.dev33.satoken.context.model.SaRequest;
import cn.dev33.satoken.oauth2.logic.SaOAuth2Consts;
import cn.dev33.satoken.oauth2.logic.SaOAuth2Template;
import cn.dev33.satoken.oauth2.model.AccessTokenModel;
import cn.dev33.satoken.util.SaFoxUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.AsymmetricAlgorithm;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTValidator;
import cn.hutool.jwt.signers.JWTSigner;
import cn.hutool.jwt.signers.JWTSignerUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import cn.dev33.satoken.context.SaHolder;
import cn.dev33.satoken.oauth2.config.SaOAuth2Config;
import cn.dev33.satoken.oauth2.logic.SaOAuth2Handle;
import cn.dev33.satoken.oauth2.logic.SaOAuth2Util;
import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.util.SaResult;

import javax.crypto.SecretKey;

import static cn.dev33.satoken.oauth2.logic.SaOAuth2Handle.token;

/**
 * Sa-OAuth2 Server端 控制器
 * @author click33
 * 
 */
@RestController
public class SaOAuth2ServerController {

	@Autowired
	private SaOAuth2Template template;
	private static PrivateKey privateKey;
	private static PublicKey publicKey;

	static {
		// 创建 KeyPairGenerator 对象，指定算法为 RSA
		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			// 设置密钥长度（单位为位）
			int keySize = 2048;
			keyPairGenerator.initialize(keySize);

			// 生成密钥对
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			// 获取私钥和公钥
			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();

			// 打印私钥和公钥
			System.out.println("Private Key: " + privateKey);
			System.out.println("Public Key: " + publicKey);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}


	}

	// 处理所有OAuth相关请求 
	@RequestMapping("/oauth2/*")
	public Object request() {
		System.out.println("------- 进入请求: " + SaHolder.getRequest().getUrl());
		Object response = SaOAuth2Handle.serverRequest();
		SaResult result = null;
		if(response instanceof SaResult){
			result = (SaResult) response;
			response = result.getData();
		}

		SaRequest req = SaHolder.getRequest();
		if(req.isPath(SaOAuth2Consts.Api.token) && req.isParam(SaOAuth2Consts.Param.grant_type, SaOAuth2Consts.GrantType.authorization_code)) {
			if(result.getData() instanceof Map){
				Map<String, Object> token = (Map<String, Object>) result.getData();
				String accessToken = (String) token.get("accessToken");
				AccessTokenModel at = template.checkAccessToken(accessToken);
				List<String> scopeList = SaFoxUtil.convertStringToList(at.scope);
				boolean hasOpenidScope = scopeList.stream().anyMatch(s -> "openid".equals(s));
				if(hasOpenidScope) {
					JWTSigner rs256 = JWTSignerUtil.rs256(privateKey);
					Map<String, Object> payloads = new HashMap<>();
					long currentTimeMillis = System.currentTimeMillis();
					// idtoken办法的服务器
					payloads.put("iss", "http://sa-oauth-server.com:8001");
					// 用户id
					payloads.put("sub", "zhangsan");
					// 请求获取idtoken的客户端的clientId
					payloads.put("aud", "http://sa-oauth-server.com:8001");
					// idtoken办法的服务器
					payloads.put("nonce", "http://sa-oauth-server.com:8001");
					// 认证时间
					payloads.put("auth_time", "http://sa-oauth-server.com:8001");
					// idtoken的签发时间
					payloads.put("iat", currentTimeMillis);
					// idtoken的过期时间，默认为10分钟
					payloads.put("exp", currentTimeMillis + 1000 * 60 * 10);
					String idtoken = JWT.create().setIssuedAt(new Date(currentTimeMillis))
							.setExpiresAt(new Date(currentTimeMillis + 1000 * 60 * 10))
							.setSigner(rs256).addPayloads(payloads)
							.sign();
					token.put("idtoken", idtoken);
					JWTValidator.of(idtoken).validateAlgorithm(JWTSignerUtil.rs256(publicKey));

				}
				return token;
			}
		}
		return response;
	}
	
	// Sa-OAuth2 定制化配置 
	@Autowired
	public void setSaOAuth2Config(SaOAuth2Config cfg) {
		cfg.
			// 未登录的视图 
			setNotLoginView(()->{
				return new ModelAndView("login.html");	
			}).
			// 登录处理函数 
			setDoLoginHandle((name, pwd) -> {
				if("sa".equals(name) && "123456".equals(pwd)) {
					StpUtil.login(10001);
					return SaResult.ok();
				}
				return SaResult.error("账号名或密码错误");
			}).
			// 授权确认视图 
			setConfirmView((clientId, scope)->{
				Map<String, Object> map = new HashMap<>();
				map.put("clientId", clientId);
				map.put("scope", scope);
				return new ModelAndView("confirm.html", map); 
			})
			;
	}

	// 全局异常拦截  
	@ExceptionHandler
	public SaResult handlerException(Exception e) {
		e.printStackTrace(); 
		return SaResult.error(e.getMessage());
	}
	
	
	// ---------- 开放相关资源接口： Client端根据 Access-Token ，置换相关资源 ------------ 
	
	// 获取Userinfo信息：昵称、头像、性别等等
	@RequestMapping("/oauth2/userinfo")
	public SaResult userinfo() {
		// 获取 Access-Token 对应的账号id 
		String accessToken = SaHolder.getRequest().getParamNotNull("access_token");
		Object loginId = SaOAuth2Util.getLoginIdByAccessToken(accessToken);
		System.out.println("-------- 此Access-Token对应的账号id: " + loginId);
		
		// 校验 Access-Token 是否具有权限: userinfo
		SaOAuth2Util.checkScope(accessToken, "userinfo");
		
		// 模拟账号信息 （真实环境需要查询数据库获取信息）
		Map<String, Object> map = new LinkedHashMap<String, Object>();
		map.put("nickname", "shengzhang_");
		map.put("avatar", "http://xxx.com/1.jpg");
		map.put("age", "18");
		map.put("sex", "男");
		map.put("address", "山东省 青岛市 城阳区");
		return SaResult.data(map);
	}
	
}
