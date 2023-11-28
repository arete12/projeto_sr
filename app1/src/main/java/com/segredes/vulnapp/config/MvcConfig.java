package com.segredes.vulnapp.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MvcConfig implements WebMvcConfigurer {
	private static Logger logger = LoggerFactory.getLogger(MvcConfig.class);

	public void addViewControllers(ViewControllerRegistry registry) {
		logger.info("addViewControllers() - Mapping routes to view templates");
		//registry.addViewController("/").setViewName("index");
		//registry.addViewController("/login").setViewName("login");
	}

}
