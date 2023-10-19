package com.oidc.core.auth;

import com.google.gson.JsonObject;
import java.util.Map;
import javax.jcr.RepositoryException;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.UserManager;

public interface OpenIdConnectAuthService {

  /**
   * Takes authorization code and retrieves access_token from Okta
   *
   * @param code authorization code
   * @return Map with access_token and id_token to be used in communication
   */
  Map<String, String> exchangeTokenForCode(String code);

  /**
   * Returns the response from the user endpoint of the OIDC provider
   *
   * @param accessToken access token
   * @return JsonObject with userData
   */
  JsonObject getUserData(String accessToken);

  /**
   * Updates the given user with provided attributes and tokens
   *
   * @param user       user
   * @param attributes attributes
   * @param tokens     tokens
   * @throws RepositoryException RepositoryException
   */
  void updateAndSyncUser(Authorizable user, Map<String, String> attributes,
      Map<String, String> tokens) throws RepositoryException;

  /**
   * Creates a Map of attributes from given userData JsonObject
   *
   * @param userData userData JsonObject
   * @return Map of attributes
   */
  Map<String, String> createUserAttributes(JsonObject userData);

  /**
   * Creates a new user in the repository and adds attributes and tokens to it
   *
   * @param userManager userManager
   * @param attributes  attributes
   * @param tokens      tokens
   * @throws RepositoryException RepositoryException
   * @return Authorizable user
   */
  Authorizable createNewUser(UserManager userManager, Map<String, String> attributes,
      Map<String, String> tokens) throws RepositoryException;
}
