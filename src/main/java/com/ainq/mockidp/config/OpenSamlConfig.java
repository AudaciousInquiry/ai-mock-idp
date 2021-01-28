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

import java.security.Provider;
import java.security.Security;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.springframework.beans.factory.annotation.Autowired;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.ParserPool;



@Slf4j
public class OpenSamlConfig {

	@Autowired
	private ParserPool parserPool;
	
	public void init() {
		
		JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
		try {
			javaCryptoValidationInitializer.init();
		} catch (InitializationException e) {
			log.warn("Could not Initialize Java Crytography", e);
		}

		for (Provider jceProvider : Security.getProviders()) {
			log.info(jceProvider.getInfo());
		}

		try {
			log.info("Initializing OpenSAML...");
			InitializationService.initialize();
		} catch (final InitializationException e) {
			throw new RuntimeException("Initialization of OpenSAML failed", e);
		}
		
		
		XMLObjectProviderRegistry registry;
		synchronized (ConfigurationService.class) {
			registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
			if (registry == null) {
				log.debug("XMLObjectProviderRegistry did not exist in ConfigurationService, will be created");
				registry = new XMLObjectProviderRegistry();
				ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
			}
		}
		
		//try {
			log.debug("Attempting to override the default OpenSAML Parser Pool with Spring bean.");
			/*BasicParserPool parserPool = new BasicParserPool();
			parserPool.setMaxPoolSize(100);
			parserPool.setCoalescing(true);
			parserPool.setIgnoreComments(true);
			parserPool.setIgnoreElementContentWhitespace(true);
			parserPool.setNamespaceAware(true);

			parserPool.initialize();
			*/
			if (parserPool != null) {
				
				registry.setParserPool(parserPool);
				log.debug("Overrode the default OpenSAML Parser Pool with Spring bean.");
			}
		//} catch (ComponentInitializationException e) {
		//	log.debug("Could not override the OpenSAML Parser Pool with Spring bean.", e);
		//}
	}

}