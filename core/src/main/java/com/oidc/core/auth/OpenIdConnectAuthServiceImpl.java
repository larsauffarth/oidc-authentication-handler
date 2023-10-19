package com.oidc.core.auth;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.jcr.RepositoryException;
import javax.jcr.Value;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.value.ValueFactoryImpl;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.joda.time.Instant;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(service = OpenIdConnectAuthService.class, immediate = true)
public class OpenIdConnectAuthServiceImpl implements OpenIdConnectAuthService {

  private final Logger log = LoggerFactory.getLogger(OpenIdConnectAuthServiceImpl.class);
  private static final String TOKEN_ENDPOINT = "/oauth2/default/v1/token";
  private static final String USER_ENDPOINT = "/oauth2/default/v1/userinfo";
  private static final String REFRESH_TOKEN = "refresh_token";
  private static final String ACCESS_TOKEN = "access_token";
  private static final String ID_TOKEN = "id_token";
  private static final String EXPIRY = "expires_in";
  private static final String USER_ID_KEY = "preferredUsername";

  @Reference
  private OktaConfigService oktaConfigService;
  @Reference
  private ResourceResolverFactory resourceResolverFactory;

  @Override
  public Map<String, String> exchangeTokenForCode(String authorizationCode) {
    Map<String, String> tokens = new HashMap<>();
    try (CloseableHttpClient httpClient = HttpClients.custom().setProxy(null)
        .build()) {
      HttpPost httpPost = getHttpPost(authorizationCode);
      JsonObject tokenResponse = getTokenAsJsonObject(httpClient, httpPost);
      if (tokenResponse == null) {
        return tokens;
      }
      JsonElement accessTokenJson = tokenResponse.get(ACCESS_TOKEN);
      JsonElement idTokenJson = tokenResponse.get(ID_TOKEN);
      JsonElement refreshTokenJson = tokenResponse.get(REFRESH_TOKEN);
      JsonElement expiryIn = tokenResponse.get(EXPIRY);
      if (accessTokenJson != null) {
        tokens.put(ACCESS_TOKEN, transformToString(accessTokenJson));
      }
      if (idTokenJson != null) {
        tokens.put(ID_TOKEN, transformToString(idTokenJson));
      }
      if (refreshTokenJson != null) {
        tokens.put(REFRESH_TOKEN, transformToString(refreshTokenJson));
      }
      if (expiryIn != null) {
        long now = Instant.now().getMillis();
        int expiryMs = (expiryIn.getAsInt() - 60)
            * 1000; // subtract 60 seconds to expire before actual expiry time
        long expiryTime = now + expiryMs;
        tokens.put(EXPIRY, String.valueOf(expiryTime));
      }
    } catch (IOException e) {
      // handle Exception
      log.error("Error while exchanging token for code: {}", e.getMessage());
    }
    return tokens;
  }

  @Override
  public JsonObject getUserData(String accessToken) {
    if (accessToken == null || accessToken.isEmpty()) {
      return null;
    }
    String userUri = oktaConfigService.getIssuer() + USER_ENDPOINT;
    try (CloseableHttpClient httpClient = HttpClients.custom().setProxy(null)
        .build()) {
      HttpGet httpGet = new HttpGet(userUri);
      httpGet.addHeader("Authorization",
          "Bearer " + accessToken);
      try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
        String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        return transformStringToJsonObject(responseBody);
      }
    } catch (IOException e) {
      // handle Exception
      log.error("Error while getting user data: {}", e.getMessage());
    }
    return null;
  }

  @Override
  public void updateAndSyncUser(Authorizable user, Map<String, String> attributes,
      Map<String, String> tokens) throws RepositoryException {
    if (attributes != null && attributes.size() > 0) {
      addAttributesToUser(attributes, user, false);
    }
    if (tokens != null && tokens.size() > 0) {
      addAttributesToUser(tokens, user, true);
    }
  }

  @Override
  public Authorizable createNewUser(UserManager userManager, Map<String, String> attributes,
      Map<String, String> tokens) throws RepositoryException {
    String userId = attributes.get(USER_ID_KEY);
    Authorizable user;
    user = userManager.createUser(userId, userId);
    // add available attributes
    addAttributesToUser(attributes, user, false);
    // add tokens
    for (Map.Entry<String, String> set :
        tokens.entrySet()) {
      String key = set.getKey();
      String value = set.getValue();
      Value valueObj = ValueFactoryImpl.getInstance().createValue(value);
      // store tokens under user/oidcTokens/token-key
      user.setProperty("oidcTokens/" + key, valueObj);
    }
    return user;
  }

  @Override
  public Map<String, String> createUserAttributes(JsonObject userData) {
    String preferredUsername = String.valueOf(userData.get("preferred_username"));
    String firstName = String.valueOf(userData.get("given_name"));
    String lastName = String.valueOf(userData.get("family_name"));
    String preferredLanguage = String.valueOf(userData.get("locale"));

    // prepare attributes for user storage
    return Stream.of(
            new AbstractMap.SimpleEntry<>(USER_ID_KEY, preferredUsername),
            new AbstractMap.SimpleEntry<>("lastName", lastName),
            new AbstractMap.SimpleEntry<>("firstName", firstName),
            new AbstractMap.SimpleEntry<>("preferredLanguage", preferredLanguage))
        .filter(entry -> entry.getValue() != null)
        .collect(Collectors.toMap(
            Map.Entry::getKey,
            entry -> entry.getValue().replace("\"", "")));
  }

  /**
   * Adds attributes to user
   *
   * @param attributes attributes
   * @param user       user
   * @param areTokens  areTokens
   * @throws RepositoryException RepositoryException
   */
  private void addAttributesToUser(Map<String, String> attributes, Authorizable user,
      boolean areTokens)
      throws RepositoryException {
    for (Map.Entry<String, String> set :
        attributes.entrySet()) {
      String key = areTokens ? "oidcTokens/" : "profile/" + set.getKey();
      String value = set.getValue();
      if (value != null) {
        Value valueObj = ValueFactoryImpl.getInstance().createValue(value);
        user.setProperty(key, valueObj);
      }
    }
  }

  /**
   * Prepares HttpPost for token exchange
   *
   * @param authorizationCode authorization code
   * @return HttpPost
   * @throws IOException IOException
   */
  private HttpPost getHttpPost(String authorizationCode) throws IOException {
    if (authorizationCode == null || authorizationCode.isEmpty()) {
      return null;
    }
    HttpPost httpPost = new HttpPost(oktaConfigService.getIssuer() + TOKEN_ENDPOINT);
    String clientIdSecretPair =
        oktaConfigService.getClientId() + ":" + oktaConfigService.getClientSecret();
    byte[] encodedAuth = Base64.getEncoder().encode(clientIdSecretPair.getBytes(
        StandardCharsets.ISO_8859_1));
    String authHeader = "Basic " + new String(encodedAuth);
    httpPost.addHeader(HttpHeaders.AUTHORIZATION, authHeader);
    httpPost.addHeader("Accept", "application/json");
    List<NameValuePair> params = new ArrayList<>();
    httpPost.addHeader("Content-Type", "application/x-www-form-urlencoded");
    params.add(new BasicNameValuePair("grant_type", "authorization_code"));
    params.add(new BasicNameValuePair("redirect_uri", oktaConfigService.getAuthCallback()));
    params.add(new BasicNameValuePair("code", authorizationCode));
    HttpEntity entity = new UrlEncodedFormEntity(params, "UTF-8");
    httpPost.setEntity(entity);
    return httpPost;
  }

  /**
   * Executes HttpPost and returns token response as JsonObject
   *
   * @param httpClient httpClient
   * @param httpPost   httpPost to token endpoint
   * @return JsonObject with token response
   * @throws IOException IOException
   */
  private JsonObject getTokenAsJsonObject(CloseableHttpClient httpClient, HttpPost httpPost)
      throws IOException {
    if (httpPost == null || httpClient == null) {
      return null;
    }
    try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
      if (response.getStatusLine().getStatusCode() != 200) {
        return null;
      }
      String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
      return transformStringToJsonObject(responseBody);
    }
  }

  /**
   * Transforms JsonElement to String
   *
   * @param jsonString JsonElement
   * @return String
   */
  private String transformToString(JsonElement jsonString) {
    String stringValue = String.valueOf(jsonString);
    return stringValue == null || stringValue.isEmpty() ? null : stringValue.replace("\"", "");
  }

  /**
   * Transforms String to JsonObject
   * @param jsonString String
   * @return JsonObject
   */
  private JsonObject transformStringToJsonObject(String jsonString) {
    if (jsonString == null || jsonString.isEmpty()) {
      return null;
    }
    Gson gson = new Gson();
    return gson.fromJson(jsonString, JsonObject.class);
  }
}
