package it.geosolutions.geostore.services.rest.security.keycloak;

import com.google.gson.Gson;
import com.google.gson.internal.LinkedTreeMap;
import it.geosolutions.geostore.services.rest.security.GroupsRolesService;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class GeoStoreKeycloakAuthoritiesPopulator implements GroupsRolesService {

    private String serverURL = "http://keycloak:8080";
    private String realm = "master";
    private String clientID = "geostore-client";
    private String idOfClient = "36faa8da-ac12-4349-be94-7e55be5c9279";
    private String clientSecret = "2c4847b7-7aa9-4a51-ba4f-b1a698539992";
    private String baseURL = this.serverURL + "/auth/admin/realms/" + this.realm;
    private String rolesURL = this.baseURL + "/clients/" + this.idOfClient + "/roles";
    private String groupsURL = this.baseURL + "/groups";

    @Override
    public Set<GrantedAuthority> getAllGroups() {
        return getAllGroupsOrRoles(true, false);
    }

    @Override
    public Set<GrantedAuthority> getAllRoles() {
        return getAllGroupsOrRoles(false, true);
    }

    /**
     * Extract the message (body) from the given HTTP response.
     *
     * @param response the CloseableHttpResponse to retrieve the message from
     * @return the content of the response entity, as a String
     * @throws Exception
     */
    private String getStringResponseMessage(CloseableHttpResponse response) throws Exception {
        HttpEntity responseEntity = response.getEntity();
        if (responseEntity == null) {
            throw new NullPointerException("HTTP response from Keycloak contained no message");
        }

        try (InputStream contentStream = responseEntity.getContent()) {
            return IOUtils.toString(contentStream, String.valueOf(StandardCharsets.UTF_8));
        }
    }

    /**
     * Obtain an access token from Keycloak, using the server URL, realm name, and client secret
     * from the config. Returns null if an error occurs.
     *
     * @param httpClient a CloseableHttpClient to send the request through
     * @return a String access token on success, null on error.
     */
    public String getAccessToken(CloseableHttpClient httpClient, Gson gson) {
        HttpPost httpPost =
                new HttpPost(
                        this.serverURL
                                + "/auth/realms/"
                                + this.realm
                                + "/protocol/openid-connect/token");
        String body =
                "client_id="
                        + this.clientID
                        + "&client_secret="
                        + this.clientSecret
                        + "&grant_type=client_credentials";
        HttpEntity entity = new StringEntity(body, ContentType.APPLICATION_FORM_URLENCODED);
        httpPost.setEntity(entity);

        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            StatusLine statusLine = response.getStatusLine();
            if (statusLine == null || statusLine.getStatusCode() != 200) {
                System.out.println();
                System.out.println(statusLine);
                System.out.println();
                return null;
            }
            String jsonString = getStringResponseMessage(response);
            Map<?, ?> map = gson.fromJson(jsonString, Map.class);
            return map.get("access_token").toString();
        } catch (Exception exception) {
            System.out.println();
            System.out.println(exception.getMessage());
            System.out.println();
            return null;
        }
    }

    /**
     * Retrieve all groups or roles from Keycloak. Returns an empty set on error.
     *
     * @param getGroups true if retrieving groups, false if retrieving roles
     * @param getRoles  true if retrieving roles, false if retrieving groups
     * @return a Set of GrantedAuthorities representing the retrieved groups/roles
     */
    public Set<GrantedAuthority> getAllGroupsOrRoles(boolean getGroups, boolean getRoles) {
        Gson gson = new Gson();
        Set<GrantedAuthority> authorities = new HashSet<>();
        String url;
        String prefix;

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            String accessToken = getAccessToken(httpClient, gson);
            if (accessToken == null) {
                System.out.println("Could not retrieve access token");
                // Cannot retrieve access token, return empty set
                return authorities;
            }

            if (getGroups && !getRoles) {
                url = this.groupsURL;
                prefix = "";
            } else if (getRoles && !getGroups) {
                url = this.rolesURL;
                prefix = "ROLE_";
            } else {
                // Cannot determine whether to retrieve groups or roles, return empty set
                return authorities;
            }

            HttpGet httpGet = new HttpGet(url);
            httpGet.setHeader("Authorization", "Bearer " + accessToken);
            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                StatusLine statusLine = response.getStatusLine();
                if (statusLine == null || statusLine.getStatusCode() != 200) {
                    return authorities;
                }
                String jsonString = getStringResponseMessage(response);
                for (Object obj : gson.fromJson(jsonString, List.class)) {
                    LinkedTreeMap<?, ?> authority = (LinkedTreeMap<?, ?>) obj;
                    authorities.add(new GrantedAuthorityImpl(prefix + authority.get("name").toString()));
                }
                return authorities;
            }
        } catch (Exception exception) {
            System.out.println();
            System.out.println(exception.getMessage());
            System.out.println();
        }

        return new HashSet<>();
    }
}
