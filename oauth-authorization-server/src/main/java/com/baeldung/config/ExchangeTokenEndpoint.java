package com.baeldung.config;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.endpoint.AbstractEndpoint;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * <p>
 * New authorization server endpoint to convert a CAT or MOAuth token into MWT token
 * </p>
 * 
 * @author Junjun He
 * 
 */
// junjun:
@FrameworkEndpoint
public class ExchangeTokenEndpoint extends AbstractEndpoint {

	private OAuth2RequestValidator oAuth2RequestValidator = new DefaultOAuth2RequestValidator();

	private Set<HttpMethod> allowedRequestMethods = new HashSet<HttpMethod>(Arrays.asList(HttpMethod.POST));
	
	// this will autowired the JwtTokenStore object here
    @Autowired
    TokenStore tokenStore;
    
	// create a new constructor which initializes all data needed for the end point
	public ExchangeTokenEndpoint() {
		
		AuthorizationServerEndpointsConfigurer authorizationServerEndpointsConfigurer = 
				new AuthorizationServerEndpointsConfigurer();
		
		this.setProviderExceptionHandler(authorizationServerEndpointsConfigurer.getExceptionTranslator());
		this.setTokenGranter(authorizationServerEndpointsConfigurer.getTokenGranter());
		this.setClientDetailsService(authorizationServerEndpointsConfigurer.getClientDetailsService());
		this.setOAuth2RequestFactory(authorizationServerEndpointsConfigurer.getOAuth2RequestFactory());
		this.setOAuth2RequestValidator(authorizationServerEndpointsConfigurer.getOAuth2RequestValidator());
		this.setAllowedRequestMethods(authorizationServerEndpointsConfigurer.getAllowedTokenEndpointRequestMethods());
	}
	
	@RequestMapping(value = "/oauth/exchange_token", method=RequestMethod.GET)
	public ResponseEntity<OAuth2AccessToken> getAccessToken(Principal principal, 
			@RequestHeader("Authorization") String header,
			@RequestParam Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
		if (!allowedRequestMethods.contains(HttpMethod.GET)) {
			throw new HttpRequestMethodNotSupportedException("GET");
		}
		return postAccessToken(principal, header, parameters);
	}
	
	@RequestMapping(value = "/oauth/exchange_token", method=RequestMethod.POST)
	public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal, 
			@RequestHeader("Authorization") String header,
			@RequestParam Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {

		System.out.println(header);
		String origTokenString = header;

		OAuth2AccessToken origToken = null;
		if (origTokenString != null) {
			
			// convert JWT token string to access token
			origToken = tokenStore.readAccessToken(origTokenString);
			System.out.println(origToken);
		}

		final Map<String, Object> additionalInfo = new HashMap<>();

		/* don't create new access token, only change original token
		OAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(tokenStr);

		additionalInfo.put("tenant", "spectre");
		additionalInfo.put("user", "exchanged junjun");
		additionalInfo.put("persona", "provider");
		additionalInfo.put("client", "fed id service");
		additionalInfo.put("client_id", "1234");
		additionalInfo.put("idsp", "spectre");
		*/
		
		additionalInfo.put("user", "exchanged junjun");
		additionalInfo.put("organization", "superior hospital");
		((DefaultOAuth2AccessToken) origToken).setAdditionalInformation(additionalInfo);
		
		return getResponse(origToken);
	}
	
	/**
	 * @param principal the currently authentication principal
	 * @return a client id if there is one in the principal
	 */
	protected String getClientId(Principal principal) {
		Authentication client = (Authentication) principal;
		if (!client.isAuthenticated()) {
			throw new InsufficientAuthenticationException("The client is not authenticated.");
		}
		String clientId = client.getName();
		if (client instanceof OAuth2Authentication) {
			// Might be a client and user combined authentication
			clientId = ((OAuth2Authentication) client).getOAuth2Request().getClientId();
		}
		return clientId;
	}

	@ExceptionHandler(HttpRequestMethodNotSupportedException.class)
	public ResponseEntity<OAuth2Exception> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException e) throws Exception {
		if (logger.isInfoEnabled()) {
			logger.info("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
		}
	    return getExceptionTranslator().translate(e);
	}
	
	@ExceptionHandler(Exception.class)
	public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
		if (logger.isWarnEnabled()) {
			logger.warn("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
		}
		return getExceptionTranslator().translate(e);
	}
	
	@ExceptionHandler(ClientRegistrationException.class)
	public ResponseEntity<OAuth2Exception> handleClientRegistrationException(Exception e) throws Exception {
		if (logger.isWarnEnabled()) {
			logger.warn("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
		}
		return getExceptionTranslator().translate(new BadClientCredentialsException());
	}

	@ExceptionHandler(OAuth2Exception.class)
	public ResponseEntity<OAuth2Exception> handleException(OAuth2Exception e) throws Exception {
		if (logger.isWarnEnabled()) {
			logger.warn("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
		}
		return getExceptionTranslator().translate(e);
	}

	private ResponseEntity<OAuth2AccessToken> getResponse(OAuth2AccessToken accessToken) {
		HttpHeaders headers = new HttpHeaders();
		headers.set("Cache-Control", "no-store");
		headers.set("Pragma", "no-cache");
		headers.set("Content-Type", "application/json;charset=UTF-8");
		return new ResponseEntity<OAuth2AccessToken>(accessToken, headers, HttpStatus.OK);
	}

	private boolean isRefreshTokenRequest(Map<String, String> parameters) {
		return "refresh_token".equals(parameters.get("grant_type")) && parameters.get("refresh_token") != null;
	}

	private boolean isAuthCodeRequest(Map<String, String> parameters) {
		return "authorization_code".equals(parameters.get("grant_type")) && parameters.get("code") != null;
	}

	public void setOAuth2RequestValidator(OAuth2RequestValidator oAuth2RequestValidator) {
		this.oAuth2RequestValidator = oAuth2RequestValidator;
	}

	public void setAllowedRequestMethods(Set<HttpMethod> allowedRequestMethods) {
		this.allowedRequestMethods = allowedRequestMethods;
	}
}
