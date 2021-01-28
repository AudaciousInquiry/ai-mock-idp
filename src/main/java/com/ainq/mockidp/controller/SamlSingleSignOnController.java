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

package com.ainq.mockidp.controller;

import com.ainq.mockidp.util.OpenSamlUtils;
import com.ainq.mockidp.model.PatientContext;
import com.ainq.mockidp.controller.request.SamlSingleSignOnRequest;
import com.ainq.mockidp.util.SamlSpAssertionUtil;
import com.ainq.mockidp.model.SamlSpConnectionInfo;
import com.ainq.mockidp.service.SamlSpMetadataService;
import com.ainq.mockidp.model.User;
import com.ainq.mockidp.controller.response.UserResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ainq.mockidp.util.ReadUsers;

import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.ParserPool;

@RestController
@Slf4j
public class SamlSingleSignOnController {
	
	private static Map<String, User> userMap;

	@Autowired
	private ReadUsers readUsers;

	@Autowired
	private SamlSpMetadataService samlSpMetadataService;

	@PostConstruct
	public void init(){

		userMap = new HashMap<String,User>();

		int count = 1;
		try {
			for ( User user : readUsers.getUsers()) {
				if (user != null) {
					userMap.put(String.valueOf(count++), user);
				}
			}
		} catch (IOException e) {
			log.error("Error:", e);
		}
	}

	
	@Autowired
	private ParserPool parserPool;
	
	@Autowired
	private VelocityEngine velocityEngine;
	
	
	@RequestMapping(value = "/users", method = RequestMethod.GET)
	public List<UserResponse> getUsers() {
		List<UserResponse> pairs = new ArrayList<UserResponse>();


		for (Entry<String, User> entry : userMap.entrySet()) {
			UserResponse resp = new UserResponse();
			resp.setKey(entry.getKey());
			resp.setUser(entry.getValue());
			
			pairs.add(resp);
		}
		
		return pairs;
	}
	

	@RequestMapping(value = "/sso/{id}", method = RequestMethod.POST,
			headers="Accept=application/x-www-form-urlencoded")
	public void processSingleSignOnRedirect(@PathVariable(name="id",required=true) String id, SamlSingleSignOnRequest ssoRequest, HttpServletRequest req, HttpServletResponse resp) throws IOException {
    
		User user = userMap.get(id);

		SamlSpConnectionInfo info = convertRequest(ssoRequest);


		log.debug("meta data : " + info.getMetadataXml());

		try {
			samlSpMetadataService.parse(info);

			log.debug("Metadata parsed! " + info.getSamlSpMetadata().getEntityId());

		} catch (Exception e) {
			log.error("Could not Parse the Metadata", e);
		}
		
		Response samlResponse = SamlSpAssertionUtil.buildResponse(user, null, info);
				
		log.debug("SamlResponse:");
		OpenSamlUtils.logSAMLObject(samlResponse);
				
				
		SamlSpAssertionUtil.postSamlResponse(resp, info, samlResponse, null, velocityEngine, null);
			
	}

	@RequestMapping(value = "/sso/{id}/{patientIndex}", method = RequestMethod.POST)
	public void processSingleSignOnRedirect(@PathVariable(name="id",required=true) String id, @PathVariable(name="patientIndex",required=true) Integer patientIndex, SamlSingleSignOnRequest ssoRequest, HttpServletRequest req, HttpServletResponse resp) throws IOException {

		User user = userMap.get(id);

		SamlSpConnectionInfo info = convertRequest(ssoRequest);

		log.debug("meta data : " + info.getMetadataXml());

		try {
			samlSpMetadataService.parse(info);

			log.debug("Metadata parsed! " + info.getSamlSpMetadata().getEntityId());

		} catch (Exception e) {
			log.error("Could not Parse the Metadata", e);
		}

		PatientContext patient = user.getPatients().get(patientIndex);

		Response samlResponse = SamlSpAssertionUtil.buildResponse(user, patient, info);

		log.debug("SamlResponse:");
		OpenSamlUtils.logSAMLObject(samlResponse);


		SamlSpAssertionUtil.postSamlResponse(resp, info, samlResponse, null, velocityEngine, patient);


	}

	private SamlSpConnectionInfo convertRequest (SamlSingleSignOnRequest ssoRequest) {
		SamlSpConnectionInfo info = new SamlSpConnectionInfo();
		info.setMetadataXml(ssoRequest.getSpMetadataXml());
		info.setMetadataUrl(ssoRequest.getSpMetadataUrl());

		if (ssoRequest.getSpOption().equalsIgnoreCase(SamlSingleSignOnRequest.SP_OPTION_URL))
			info.setParseXml(new Boolean(false));
		else
			info.setParseXml(new Boolean(true));

		info.setPrivateSigningPemKey(ssoRequest.getLocalPemKey());
		info.setPublicSigningCert(ssoRequest.getPublicSigningCert());
		info.setEncryptAssertion(ssoRequest.getEncryptAssertion());
		info.setSignAssertion(ssoRequest.getSignAssertion());
		info.setSignResponse(ssoRequest.getSignResponse());
		log.info("Conditions Validity: " + ssoRequest.getSamlConditionsValidity());
		info.setSamlConditionsValidity(ssoRequest.getSamlConditionsValidity());

		log.info("Subject Confirmation Validity: " + ssoRequest.getSubjectConfirmationValidity());
		info.setSubjectConfirmationValidity(ssoRequest.getSubjectConfirmationValidity());
		info.setDebugMode(ssoRequest.getDebugMode());

		if (ssoRequest.getPatientContextOption().equalsIgnoreCase(SamlSingleSignOnRequest.PC_OPTION_REQUEST))
			info.setPatientContextInRequest(new Boolean(true));
		else
			info.setPatientContextInRequest(new Boolean(false));

		return info;
	}

	
}
