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

package com.ainq.mockidp.model;

import lombok.Data;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.NameIDType;

@Data
public class SamlSpConnectionInfo {

  protected Boolean ignoreInvalidCerts = true;
  protected Long clockSkew;
  protected Boolean parseXml = true;
  protected String metadataUrl;
  protected String metadataXml;
  protected String metadataProtocol = SAMLConstants.SAML20P_NS;
  protected String nameIdFormat = NameIDType.EMAIL;

  private String publicSigningCert;
  private String privateSigningPemKey;
  private Boolean encryptAssertion = false;
  private Boolean signAssertion = false;
  private Boolean signResponse = false;
  private Boolean patientContextInRequest = true;
  private Boolean debugMode = false;

  private String samlConditionsValidity;
  private String subjectConfirmationValidity;

  private SamlSpMetadata samlSpMetadata;

}
