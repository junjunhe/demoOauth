package com.baeldung.config;

import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class CustomTokenEnhancer implements TokenEnhancer {

	/*
	 * This method is used to generate MWT token for oauth/token endpoint
	 * 
	 * @see org.springframework.security.oauth2.provider.token.TokenEnhancer#enhance(org.springframework.security.oauth2.common.OAuth2AccessToken, org.springframework.security.oauth2.provider.OAuth2Authentication)
	 */
	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

		final Map<String, Object> additionalInfo = new HashMap<>();

		// junjun: get the current HTTP request object so that we can get CAT token
		HttpServletRequest curRequest = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
				.getRequest();
		
		// junjun: customize access token to mwt
		additionalInfo.put("tenant", "spectre");
		additionalInfo.put("user", "mwt junjun");
		additionalInfo.put("persona", "provider");
		additionalInfo.put("client", "fed id service");
		additionalInfo.put("client_id", "1234");
		additionalInfo.put("idsp", "spectre");
		
		additionalInfo.put("organization", authentication.getName() + randomAlphabetic(4));
		((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
		return accessToken;
	}
	
}
