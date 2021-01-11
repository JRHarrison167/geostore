/* ====================================================================
 *
 * Copyright (C) 2015 GeoSolutions S.A.S.
 * http://www.geo-solutions.it
 *
 * GPLv3 + Classpath exception
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.
 *
 * ====================================================================
 *
 * This software consists of voluntary contributions made by developers
 * of GeoSolutions.  For more information on GeoSolutions, please see
 * <http://www.geo-solutions.it/>.
 *
 */
package it.geosolutions.geostore.services.rest.security;

import io.jsonwebtoken.*;
import it.geosolutions.geostore.core.model.User;
import it.geosolutions.geostore.core.model.UserAttribute;
import it.geosolutions.geostore.core.model.UserGroup;
import it.geosolutions.geostore.core.model.enums.Role;
import it.geosolutions.geostore.services.UserGroupService;
import it.geosolutions.geostore.services.exception.BadRequestServiceEx;
import it.geosolutions.geostore.services.exception.NotFoundServiceEx;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class KeycloakTokenAuthenticationFilter extends TokenAuthenticationFilter {

    private static final Logger LOGGER = Logger.getLogger(KeycloakTokenAuthenticationFilter.class);

    @Autowired
    protected UserGroupService userGroupService;

    private static final String rolePrefix = "ROLE_";

    private final String attributeName = "KeycloakUUID";

    private String publicKeyString;

    private Key publicKey;

    public KeycloakTokenAuthenticationFilter(String publicKeyString) {
        this.publicKeyString = publicKeyString;
    }

    /**
     * Convert a String public key into a Key object, and assign the Key to the publicKey attribute.
     *
     * @param keyString a public key in String format
     * @throws GeneralSecurityException when given an invalid key, or if the key factory cannot get an RSA instance
     */
    private void derivePublicKey(String keyString) throws GeneralSecurityException {
        byte[] data = Base64.getDecoder().decode(keyString.getBytes());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.publicKey = keyFactory.generatePublic(spec);
    }

    /**
     * Determine the user's highest role (admin, user, or guest) from a given list of role names.
     * If no role matches admin, user, or guest, then returns null.
     *
     * @param roles A List of String role names
     * @return A Role object or null
     */
    public Role getHighestRole(List<String> roles) {
        Role role = null;
        for (String retrievedRole : roles) {
            String roleName = retrievedRole.toUpperCase();
            if (roleName.startsWith(rolePrefix)) {
                roleName = roleName.substring(rolePrefix.length());
            }

            if (roleName.equals(Role.ADMIN.toString())) {
                role = Role.ADMIN;
                break;  // Admin is the highest authority, no need to continue checking
            }

            if (roleName.equals(Role.USER.toString())) {
                role = Role.USER;
            } else if (roleName.equals(Role.GUEST.toString()) && role != Role.USER) {
                role = Role.GUEST;
            }
        }
        return role;
    }

    /**
     * For a given list of group names, retrieve the Group or create a new one.
     * If an error occurs when trying to save a new Group, it is skipped.
     *
     * @param groupNames A List of group names to get or create groups with
     * @return A Set of UserGroup objects
     */
    public Set<UserGroup> getOrCreateGroups(List<String> groupNames) {
        Set<UserGroup> groups = new HashSet<>();
        for (String name : groupNames) {
            try {
                UserGroup group = userGroupService.get(name);
                if (group == null) {
                    group = new UserGroup();
                    group.setGroupName(name);
                    userGroupService.insert(group);
                }
                groups.add(group);
            } catch (BadRequestServiceEx ex) {
                LOGGER.error(ex.getMessage());
            }
        }
        return groups;
    }

    @Override
    protected Authentication checkToken(String token) {
        try {
            if (publicKey == null) derivePublicKey(this.publicKeyString);
        } catch (GeneralSecurityException exception) {
            LOGGER.error(exception.getMessage());
            return null;
        }

        Jws<Claims> jws;
        Claims claims;
        try {
            jws = Jwts.parser()
                    .setSigningKey(this.publicKey)
                    .parseClaimsJws(token);
            claims = jws.getBody();
        } catch (JwtException exception) {
            LOGGER.error(exception.getMessage());
            return null;
        }

        String issuer;
        String keycloakUUID;
        String username;
        List<String> roles;
        List<String> groupNames;
        try {
            issuer = (String) claims.get("iss");
            keycloakUUID = (String) claims.get("sub");
            username = (String) claims.get("preferred_username");
            Map<String, Object> resourceAccess = (Map<String, Object>) claims.get("resource_access");
            Map<String, List<String>> geostoreClient = (Map<String, List<String>>) resourceAccess.get("geostore-client");
            roles = geostoreClient.get("roles");
            groupNames = (List<String>) claims.get("groups");
        } catch (NullPointerException exception) {
            LOGGER.error("Unable to retrieve required user details from token");
            return null;
        }

        Role role = getHighestRole(roles);
        if (role == null) {
            LOGGER.error("No role found for the given user's token");
            return null;
        }

        Set<UserGroup> groups = getOrCreateGroups(groupNames);

        // Assumes issuer is of the format: {base url}/auth/realms/{realm name}
        List<String> address = Arrays.asList(issuer.split("/"));
        String realm = address.get(address.size() - 1);

        // Check for an existing user
        String namePrefix = "";
        try {
            User user = userService.get(username);
            List<UserAttribute> userAttributes = user.getAttribute();
            // If retrieved user was created via Keycloak and UUID matches token, authenticate to that account
            for (UserAttribute attribute : userAttributes) {
                if (attribute.getName().equals(attributeName) && attribute.getValue().equals(keycloakUUID)) {
                    user.setGroups(groups);
                    user.setRole(role);
                    userService.update(user);
                    return createAuthenticationForUser(user);
                }
            }
            namePrefix = realm + "_";
        } catch (NotFoundServiceEx exception) {
            // No user found for given name
            LOGGER.info(exception.getMessage() + ". Creating new Keycloak user.");
        } catch (BadRequestServiceEx ex) {
            LOGGER.error(ex.getMessage());
            return null;
        }

        try {
            List<UserAttribute> attributes = new ArrayList<>();
            UserAttribute attribute = new UserAttribute();
            attribute.setName(attributeName);
            attribute.setValue(keycloakUUID);
            attributes.add(attribute);

            User user = new User();
            user.setName(namePrefix + username);
            user.setRole(role);
            user.setEnabled(true);
            user.setAttribute(attributes);
            user.setGroups(groups);

            Set<GrantedAuthority> roleSet = new HashSet<>();
            roleSet.add(new GrantedAuthorityImpl(rolePrefix + role.toString()));
            userService.insert(user);
            return new UsernamePasswordAuthenticationToken(user, "", roleSet);
        } catch (Exception exception) {
            LOGGER.error(exception.getMessage());
            return null;
        }
    }
}
