package com.baeldung.config;

import java.security.Principal;
import java.util.Map;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;

/**
 * OAuth2 token services that produces JWT encoded token values.
 * modify to use Jersey instead of Spring MVC to fit Alva requirement
 * 
 * Junjun He
 * 
 */
@Component
@Path("/oauth/new_token_key")
public class NewTokenKeyEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());

    private JwtAccessTokenConverter converter;

 	public NewTokenKeyEndpoint(JwtAccessTokenConverter converter) {
		super();
		this.converter = converter;
	}

    /**
     * Get the verification key for the token signatures. The principal has to
     * be provided only if the key is secret
     * (shared not public).
     * 
     * @param principal the currently authenticated user if there is one
     * @return the key used to verify tokens
     */
    //@RequestMapping(value = "/oauth/token_key", method = RequestMethod.GET)
    //@ResponseBody
    @GET
    @Produces("application/json")
    public Map<String, String> getKey(Principal principal) {
        if ((principal == null || principal instanceof AnonymousAuthenticationToken) && !converter.isPublic()) {
            throw new AccessDeniedException("You need to authenticate to see a shared key");
        }
        Map<String, String> result = converter.getKey();
        return result;
    }

}

