package it.geosolutions.geostore.rest.security;

import it.geosolutions.geostore.core.model.enums.Role;
import it.geosolutions.geostore.services.rest.security.KeycloakTokenAuthenticationFilter;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class KeycloakTokenAuthenticationFilterTest {

    private KeycloakTokenAuthenticationFilter filter;

    private static final String rolePrefix = "ROLE_";

    @Before
    public void setup() {
        filter = new KeycloakTokenAuthenticationFilter("");
    }

    @Test
    public void testGetRoleNoneMatch() {
        List<String> roles = new ArrayList<>();
        roles.add("Role1");
        roles.add("Role2");
        Role result = filter.getHighestRole(roles);
        assertNull(result);
    }

    @Test
    public void testGetRoleGuest() {
        List<String> roles = new ArrayList<>();
        roles.add("Role1");
        roles.add(Role.GUEST.toString());
        Role result = filter.getHighestRole(roles);
        assertEquals(result, Role.GUEST);
    }

    @Test
    public void testGetRoleUser() {
        List<String> roles = new ArrayList<>();
        roles.add("Role1");
        roles.add(Role.USER.toString());
        roles.add(Role.GUEST.toString());
        Role result = filter.getHighestRole(roles);
        assertEquals(result, Role.USER);
    }

    @Test
    public void testGetRoleAdmin() {
        List<String> roles = new ArrayList<>();
        roles.add("Role1");
        roles.add(Role.GUEST.toString());
        roles.add(Role.USER.toString());
        roles.add(Role.ADMIN.toString());
        Role result = filter.getHighestRole(roles);
        assertEquals(result, Role.ADMIN);
    }

    @Test
    public void testGetRoleWithPrefix() {
        List<String> roles = new ArrayList<>();
        roles.add(rolePrefix + Role.ADMIN.toString());
        Role result = filter.getHighestRole(roles);
        assertEquals(result, Role.ADMIN);
    }
}
