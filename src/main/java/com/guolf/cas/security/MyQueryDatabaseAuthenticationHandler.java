package com.guolf.cas.security;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.QueryDatabaseAuthenticationHandler;
import org.apereo.cas.authentication.HandlerResult;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.exceptions.AccountDisabledException;
import org.apereo.cas.authentication.exceptions.AccountPasswordMustChangeException;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.sql.DataSource;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by guolf on 17/9/11.
 */
public class MyQueryDatabaseAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(QueryDatabaseAuthenticationHandler.class);

    private final String sql;
    private final String fieldPassword;
    private final String fieldExpired;
    private final String fieldDisabled;
    private Map<String, String> principalAttributeMap = Collections.emptyMap();

    public MyQueryDatabaseAuthenticationHandler(final String name, final ServicesManager servicesManager,
                                                final PrincipalFactory principalFactory,
                                                final Integer order, final DataSource dataSource, final String sql,
                                                final String fieldPassword, final String fieldExpired, final String fieldDisabled,
                                                final Map<String, String> attributes) {
        super(name, servicesManager, principalFactory, order, dataSource);
        this.sql = sql;
        this.fieldPassword = fieldPassword;
        this.fieldExpired = fieldExpired;
        this.fieldDisabled = fieldDisabled;
        this.principalAttributeMap = attributes;
    }

    @Override
    protected HandlerResult authenticateUsernamePasswordInternal(final UsernamePasswordCredential credential, final String originalPassword)
            throws GeneralSecurityException, PreventedException {

        if (StringUtils.isBlank(this.sql) || getJdbcTemplate() == null) {
            throw new GeneralSecurityException("Authentication handler is not configured correctly. "
                    + "No SQL statement or JDBC template is found.");
        }

        final Map<String, Object> attributes = new LinkedHashMap<>(this.principalAttributeMap.size());
        final String username = credential.getUsername();
        final String password = credential.getPassword();
        try {
            final Map<String, Object> dbFields = getJdbcTemplate().queryForMap(this.sql, username);
            final String dbPassword = (String) dbFields.get(this.fieldPassword);

            if (StringUtils.isNotBlank(originalPassword) && !matches(originalPassword, dbPassword)
                    || StringUtils.isBlank(originalPassword) && !StringUtils.equals(password, dbPassword)) {
                throw new FailedLoginException("Password does not match value on record.");
            }
            if (StringUtils.isNotBlank(this.fieldDisabled)) {
                final Object dbDisabled = dbFields.get(this.fieldDisabled);
                if (dbDisabled != null && (Boolean.TRUE.equals(BooleanUtils.toBoolean(dbDisabled.toString())) || dbDisabled.equals(Integer.valueOf(1)))) {
                    throw new AccountDisabledException("Account has been disabled");
                }
            }
            if (StringUtils.isNotBlank(this.fieldExpired)) {
                final Object dbExpired = dbFields.get(this.fieldExpired);
                if (dbExpired != null && (Boolean.TRUE.equals(BooleanUtils.toBoolean(dbExpired.toString())) || dbExpired.equals(Integer.valueOf(1)))) {
                    throw new AccountPasswordMustChangeException("Password has expired");
                }
            }

            this.principalAttributeMap.entrySet().forEach(a -> {
                final Object attribute = dbFields.get(a.getKey());
                if (attribute != null) {
                    LOGGER.debug("Found attribute [{}] from the query results", a);

                    if (attribute != null) {
                        LOGGER.debug("Found attribute [{}] from the query results", a);
                        final String principalAttrName = a.getValue();
                        attributes.put(principalAttrName, attribute.toString());
                    } else {
                        LOGGER.warn("Requested attribute [{}] could not be found in the query results", a.getKey());
                    }
                }
            });

        } catch (final IncorrectResultSizeDataAccessException e) {
            if (e.getActualSize() == 0) {
                throw new AccountNotFoundException(username + " not found with SQL query");
            }
            throw new FailedLoginException("Multiple records found for " + username);
        } catch (final DataAccessException e) {
            throw new PreventedException("SQL exception while executing query for " + username, e);
        }
        return createHandlerResult(credential, this.principalFactory.createPrincipal(username, attributes), null);
    }
}
