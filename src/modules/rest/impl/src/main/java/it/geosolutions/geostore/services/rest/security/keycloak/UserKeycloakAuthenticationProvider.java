package it.geosolutions.geostore.services.rest.security.keycloak;

import it.geosolutions.geostore.core.model.User;
import it.geosolutions.geostore.services.UserGroupService;
import it.geosolutions.geostore.services.UserService;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.internal.LinkedTreeMap;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;


public class UserKeycloakAuthenticationProvider implements AuthenticationProvider {

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    @Autowired
    UserService userService;

    @Autowired
    UserGroupService userGroupService;

    public void setUserService(UserService userService) {
        this.userService = userService;
    }
    public void setUserGroupService(UserGroupService userGroupService) {
        this.userGroupService = userGroupService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {


//        String pw = (String) authentication.getCredentials();
//        String us = (String) authentication.getPrincipal();
//        Collection<GrantedAuthority> authorities = null;
//        User user = null;

//        if (!StringUtils.hasLength(username)) {
//            throw new BadCredentialsException(this.messages.getMessage("LdapAuthenticationProvider.emptyUsername",
//                    "Empty Username"));
//        } else {
//            Assert.notNull(password, "Null password was supplied in authentication token");
//            try {
//                DirContextOperations userData = this.getAuthenticator().authenticate(authentication);
//                Collection<GrantedAuthority> extraAuthorities = this.loadUserAuthorities(userData, username, password);
//                UserDetails user = this.userDetailsContextMapper.mapUserFromContext(userData, username, extraAuthorities);
//                return this.createSuccessfulAuthentication(userToken, user);
//            } catch (PasswordPolicyException var8) {
//                throw new LockedException(this.messages.getMessage(var8.getStatus().getErrorCode(), var8.getStatus().getDefaultMessage()));
//            } catch (UsernameNotFoundException var9) {
//                if (this.hideUserNotFoundExceptions) {
//                    throw new BadCredentialsException(this.messages.getMessage("LdapAuthenticationProvider.badCredentials", "Bad credentials"));
//                } else {
//                    throw var9;
//                }
//            } catch (NamingException var10) {
//                throw new AuthenticationServiceException(var10.getMessage(), var10);
//            }
//        }

        return null;
    }


    @Override
    public boolean supports(Class<? extends Object> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
