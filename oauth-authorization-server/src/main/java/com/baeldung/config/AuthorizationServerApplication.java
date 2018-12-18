package com.baeldung.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication
public class AuthorizationServerApplication extends SpringBootServletInitializer {

	// junjun:
	// we need to override this method so that we can generate WAR file for deployment.
	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
		return application.sources(AuthorizationServerApplication.class);
	}
	
    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }

}