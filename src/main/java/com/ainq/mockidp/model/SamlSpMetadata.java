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

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import org.opensaml.security.credential.Credential;

public class SamlSpMetadata implements Serializable {

  /**
   * Comment for <code>serialVersionUID</code>
   */
  private static final long serialVersionUID = 1L;

  // the entity id on the xml
  private final String entityId;

  // the error url
  private final String errorURL;

  // list of single sign on location indexed by binding name
  private final Map<String, String> assertionConsumerBidingLocationMap;

  // list of single logout on location indexed by binding name
  private final Map<String, String> singleLogoutBindingLocationMap;

  // credential signing list
  private final List<Credential> credentialSigningList;

  private final List<Credential> credentialEncryptionList;

  public SamlSpMetadata(
      final String entityId,
      final String errorURL,
      final Map<String, String> assertionConsumerBidingLocationMap,
      final Map<String, String> singleLogoutBindingLocationMap,
      final List<Credential> credentialSigningList,
      final List<Credential> credentialEncryptionList) {

    this.entityId = entityId;
    this.errorURL = errorURL;
    this.assertionConsumerBidingLocationMap = assertionConsumerBidingLocationMap;
    this.credentialSigningList = credentialSigningList;
    this.credentialEncryptionList = credentialEncryptionList;
    this.singleLogoutBindingLocationMap = singleLogoutBindingLocationMap;
  }

  public String getEntityId() {
    return this.entityId;
  }

  public String getErrorURL() {
    return this.errorURL;
  }

  public Map<String, String> getAssertionConsumerBindingLocationMap() {
    return this.assertionConsumerBidingLocationMap;
  }

  public List<Credential> getCredentialSigningList() {
    return this.credentialSigningList;
  }

  public List<Credential> getCredentialEncryptionList() {
    return this.credentialEncryptionList;
  }

  public Map<String, String> getSingleLogoutBindingLocationMap() {
    return this.singleLogoutBindingLocationMap;
  }
}