/*
 * Copyright (c) 2020 Audacious Inquiry, LLC
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.ainq.mockidp.config;

import com.ainq.mockidp.util.VelocityEngineFactory;
import java.security.Security;
import org.apache.velocity.app.VelocityEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.PropertySource;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;

@Configuration
@Slf4j
@PropertySource("config.properties")
public class ApplicationContextConfig {
    
    //@Value("${db.connect.url}")
    //private String dbConnectUrl;


	@Bean(name="openSamlConfig")
	@DependsOn("parserPool")
	public OpenSamlConfig openSamlConfig() {

		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {

			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		}

		OpenSamlConfig config = new OpenSamlConfig();
		config.init();
		return config;
	}
	
	@Bean(name="parserPool")
	public ParserPool parserPool() {
		BasicParserPool parserPool =  new BasicParserPool();
		parserPool.setMaxPoolSize(100);
		parserPool.setCoalescing(true);
		parserPool.setIgnoreComments(true);
		parserPool.setIgnoreElementContentWhitespace(true);
		parserPool.setNamespaceAware(true);
		
		try {
			parserPool.initialize();
		} catch (ComponentInitializationException e) {
			log.error("Could not initialize the OpenSAML Parser Pool.", e);
		}
		
		return parserPool;
		
	}
	
	@Bean(name="builderFactory")
	public XMLObjectBuilderFactory builderFactory() {
		return XMLObjectProviderRegistrySupport.getBuilderFactory();
	}
	
	@Bean(name="marshallerFactory")
	public MarshallerFactory marshallerFactory() {
		return XMLObjectProviderRegistrySupport.getMarshallerFactory();
	}
	
	@Bean(name="unmarshallerFactory")
	@DependsOn("openSamlConfig")
	public UnmarshallerFactory unmarshallerFactory() {
		return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
	}

 
	@Bean(name="velocityEngine")
	public VelocityEngine velocityEngine() {
		VelocityEngine engine = VelocityEngineFactory.getVelocityEngine();
		
		return engine;
	}
	
}
