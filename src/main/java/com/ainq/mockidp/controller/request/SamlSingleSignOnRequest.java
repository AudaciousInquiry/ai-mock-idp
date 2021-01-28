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

package com.ainq.mockidp.controller.request;

import lombok.Data;

@Data
public class SamlSingleSignOnRequest {

  public static final String SP_OPTION_XML = "xml";
  public static final String SP_OPTION_URL = "url";

  public static final String PC_OPTION_SAML_ASSERTION = "assertion";
  public static final String PC_OPTION_REQUEST = "request";

  private String spOption;
  private String spMetadataUrl;
  private String spMetadataXml;
  private String localPemKey;
  private String publicSigningCert;
  private Boolean encryptAssertion = false;
  private Boolean signAssertion = false;
  private Boolean signResponse = false;
  private Boolean debugMode = false;
  private String patientContextOption;

  private String samlConditionsValidity;
  private String subjectConfirmationValidity;
}
