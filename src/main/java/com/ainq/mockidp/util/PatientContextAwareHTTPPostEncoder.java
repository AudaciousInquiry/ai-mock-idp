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

package com.ainq.mockidp.util;

import java.io.UnsupportedEncodingException;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.codec.HTMLEncoder;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.velocity.VelocityContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

public class PatientContextAwareHTTPPostEncoder extends HTTPPostEncoder {

  private final Logger log = LoggerFactory.getLogger(HTTPPostEncoder.class);



  private String patientSourceCode;
  private String patientAccountNumber;
  private String externalMrn;
  private String oid;
  private Boolean debugMode;

  public Boolean getDebugMode() {
    return debugMode;
  }

  public void setDebugMode(Boolean debugMode) {
    this.debugMode = debugMode;
  }

  public String getPatientSourceCode() {
    return patientSourceCode;
  }

  public void setPatientSourceCode(String patientSourceCode) {
    this.patientSourceCode = patientSourceCode;
  }

  public String getPatientAccountNumber() {
    return patientAccountNumber;
  }

  public void setPatientAccountNumber(String patientAccountNumber) {
    this.patientAccountNumber = patientAccountNumber;
  }

  public String getExternalMrn() {
    return externalMrn;
  }

  public void setExternalMrn(String externalMrn) {
    this.externalMrn = externalMrn;
  }

  public String getOid() {
    return oid;
  }

  public void setOid(String oid) {
    this.oid = oid;
  }

  /**
   * Populate the Velocity context instance which will be used to render the POST body.
   *
   * @param velocityContext the Velocity context instance to populate with data
   * @param messageContext the SAML message context source of data
   * @param endpointURL endpoint URL to which to encode message
   * @throws MessageEncodingException thrown if there is a problem encoding the message
   */
  @Override
  protected void populateVelocityContext(VelocityContext velocityContext, MessageContext<SAMLObject> messageContext,
      String endpointURL) throws MessageEncodingException {

    String encodedEndpointURL = HTMLEncoder.encodeForHTMLAttribute(endpointURL);
    log.debug("Encoding action url of '{}' with encoded value '{}'", endpointURL, encodedEndpointURL);
    velocityContext.put("action", encodedEndpointURL);
    velocityContext.put("binding", getBindingURI());
    velocityContext.put("patientSourceCode", patientSourceCode);
    velocityContext.put("patientAccountNumber", patientAccountNumber);
    velocityContext.put("externalMrn", externalMrn);
    velocityContext.put("oid", oid);
    log.info("Building Template with Debug Mode: " + debugMode);
    velocityContext.put("DEBUG", debugMode);


    SAMLObject outboundMessage = messageContext.getMessage();

    log.debug("Marshalling and Base64 encoding SAML message");
    Element domMessage = marshallMessage(outboundMessage);

    try {
      String messageXML = SerializeSupport.nodeToString(domMessage);
      String encodedMessage = Base64Support.encode(messageXML.getBytes("UTF-8"), Base64Support.UNCHUNKED);
      if (outboundMessage instanceof RequestAbstractType) {
        velocityContext.put("SAMLRequest", encodedMessage);
      } else if (outboundMessage instanceof StatusResponseType) {
        velocityContext.put("SAMLResponse", encodedMessage);
      } else {
        throw new MessageEncodingException(
            "SAML message is neither a SAML RequestAbstractType or StatusResponseType");
      }
    } catch (UnsupportedEncodingException e) {
      log.error("UTF-8 encoding is not supported, this VM is not Java compliant.");
      throw new MessageEncodingException("Unable to encode message, UTF-8 encoding is not supported");
    }

    String relayState = SAMLBindingSupport.getRelayState(messageContext);
    if (SAMLBindingSupport.checkRelayState(relayState)) {
      String encodedRelayState = HTMLEncoder.encodeForHTMLAttribute(relayState);
      log.debug("Setting RelayState parameter to: '{}', encoded as '{}'", relayState, encodedRelayState);
      velocityContext.put("RelayState", encodedRelayState);
    }
  }

}
