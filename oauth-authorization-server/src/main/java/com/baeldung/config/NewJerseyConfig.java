package com.baeldung.config;

import javax.ws.rs.ApplicationPath;

/**
 * 
 * Junjun He
 */
import org.glassfish.jersey.server.ResourceConfig;
import org.springframework.stereotype.Component;

@Component
@ApplicationPath("/")
public class NewJerseyConfig extends ResourceConfig {
	public NewJerseyConfig() {
		register(NewTokenKeyEndpoint.class);
	}
}
