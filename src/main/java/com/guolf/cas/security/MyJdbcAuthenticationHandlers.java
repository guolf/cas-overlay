package com.guolf.cas.security;

import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.adaptors.jdbc.BindModeSearchDatabaseAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.QueryAndEncodeDatabaseAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.SearchModeSearchDatabaseAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.config.CasJdbcAuthenticationConfiguration;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.authentication.support.password.PasswordPolicyConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.jdbc.JdbcAuthenticationProperties;
import org.apereo.cas.configuration.support.Beans;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;

/**
 * Created by guolf on 17/9/11.
 */
@Configuration("MyCasJdbcAuthenticationConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class MyJdbcAuthenticationHandlers {

    private static final Logger LOGGER = LoggerFactory.getLogger(CasJdbcAuthenticationConfiguration.class);
    @Autowired(
            required = false
    )
    @Qualifier("queryAndEncodePasswordPolicyConfiguration")
    private PasswordPolicyConfiguration queryAndEncodePasswordPolicyConfiguration;
    @Autowired(
            required = false
    )
    @Qualifier("searchModePasswordPolicyConfiguration")
    private PasswordPolicyConfiguration searchModePasswordPolicyConfiguration;
    @Autowired(
            required = false
    )
    @Qualifier("queryPasswordPolicyConfiguration")
    private PasswordPolicyConfiguration queryPasswordPolicyConfiguration;
    @Autowired(
            required = false
    )
    @Qualifier("bindSearchPasswordPolicyConfiguration")
    private PasswordPolicyConfiguration bindSearchPasswordPolicyConfiguration;
    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;
    @Autowired
    private CasConfigurationProperties casProperties;

    public MyJdbcAuthenticationHandlers() {
        LOGGER.info("hahaha...运行木有！");
    }

    @ConditionalOnMissingBean(
            name = {"jdbcAuthenticationHandlers"}
    )
    @Bean
    @RefreshScope
    public Collection<AuthenticationHandler> jdbcAuthenticationHandlers() {
        HashSet handlers = new HashSet();
        JdbcAuthenticationProperties jdbc = this.casProperties.getAuthn().getJdbc();
        jdbc.getBind().forEach((b) -> {
            handlers.add(this.bindModeSearchDatabaseAuthenticationHandler(b));
        });
        jdbc.getEncode().forEach((b) -> {
            handlers.add(this.queryAndEncodeDatabaseAuthenticationHandler(b));
        });
        jdbc.getQuery().forEach((b) -> {
            handlers.add(this.queryDatabaseAuthenticationHandler(b));
        });
        jdbc.getSearch().forEach((b) -> {
            handlers.add(this.searchModeSearchDatabaseAuthenticationHandler(b));
        });
        return handlers;
    }

    private AuthenticationHandler bindModeSearchDatabaseAuthenticationHandler(JdbcAuthenticationProperties.Bind b) {
        BindModeSearchDatabaseAuthenticationHandler h = new BindModeSearchDatabaseAuthenticationHandler(b.getName(), this.servicesManager, this.jdbcPrincipalFactory(), b.getOrder(), Beans.newDataSource(b));
        h.setPasswordEncoder(Beans.newPasswordEncoder(b.getPasswordEncoder()));
        h.setPrincipalNameTransformer(Beans.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (this.bindSearchPasswordPolicyConfiguration != null) {
            h.setPasswordPolicyConfiguration(this.bindSearchPasswordPolicyConfiguration);
        }

        h.setPrincipalNameTransformer(Beans.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (StringUtils.isNotBlank(b.getCredentialCriteria())) {
            h.setCredentialSelectionPredicate(Beans.newCredentialSelectionPredicate(b.getCredentialCriteria()));
        }

        LOGGER.debug("Created authentication handler [{}] to handle database url at [{}]", h.getName(), b.getUrl());
        return h;
    }

    private AuthenticationHandler queryAndEncodeDatabaseAuthenticationHandler(JdbcAuthenticationProperties.Encode b) {
        QueryAndEncodeDatabaseAuthenticationHandler h = new QueryAndEncodeDatabaseAuthenticationHandler(b.getName(), this.servicesManager, this.jdbcPrincipalFactory(), Integer.valueOf(b.getOrder()), Beans.newDataSource(b), b.getAlgorithmName(), b.getSql(), b.getPasswordFieldName(), b.getSaltFieldName(), b.getExpiredFieldName(), b.getDisabledFieldName(), b.getNumberOfIterationsFieldName(), b.getNumberOfIterations(), b.getStaticSalt());
        h.setPasswordEncoder(Beans.newPasswordEncoder(b.getPasswordEncoder()));
        h.setPrincipalNameTransformer(Beans.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (this.queryAndEncodePasswordPolicyConfiguration != null) {
            h.setPasswordPolicyConfiguration(this.queryAndEncodePasswordPolicyConfiguration);
        }

        h.setPrincipalNameTransformer(Beans.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (StringUtils.isNotBlank(b.getCredentialCriteria())) {
            h.setCredentialSelectionPredicate(Beans.newCredentialSelectionPredicate(b.getCredentialCriteria()));
        }

        LOGGER.debug("Created authentication handler [{}] to handle database url at [{}]", h.getName(), b.getUrl());
        return h;
    }

    private AuthenticationHandler queryDatabaseAuthenticationHandler(JdbcAuthenticationProperties.Query b) {
        Map attributes = Beans.transformPrincipalAttributesListIntoMap(b.getPrincipalAttributeList());
        LOGGER.debug("Created and mapped principal attributes [{}] for [{}]...", attributes, b.getUrl());
        MyQueryDatabaseAuthenticationHandler h = new MyQueryDatabaseAuthenticationHandler(b.getName(), this.servicesManager, this.jdbcPrincipalFactory(), Integer.valueOf(b.getOrder()), Beans.newDataSource(b), b.getSql(), b.getFieldPassword(), b.getFieldExpired(), b.getFieldDisabled(), attributes);
        h.setPasswordEncoder(Beans.newPasswordEncoder(b.getPasswordEncoder()));
        h.setPrincipalNameTransformer(Beans.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (this.queryPasswordPolicyConfiguration != null) {
            h.setPasswordPolicyConfiguration(this.queryPasswordPolicyConfiguration);
        }

        h.setPrincipalNameTransformer(Beans.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (StringUtils.isNotBlank(b.getCredentialCriteria())) {
            h.setCredentialSelectionPredicate(Beans.newCredentialSelectionPredicate(b.getCredentialCriteria()));
        }

        LOGGER.debug("Created authentication handler [{}] to handle database url at [{}]", h.getName(), b.getUrl());
        return h;
    }

    private AuthenticationHandler searchModeSearchDatabaseAuthenticationHandler(JdbcAuthenticationProperties.Search b) {
        SearchModeSearchDatabaseAuthenticationHandler h = new SearchModeSearchDatabaseAuthenticationHandler(b.getName(), this.servicesManager, this.jdbcPrincipalFactory(), Integer.valueOf(b.getOrder()), Beans.newDataSource(b), b.getFieldUser(), b.getFieldPassword(), b.getTableUsers());
        h.setPasswordEncoder(Beans.newPasswordEncoder(b.getPasswordEncoder()));
        h.setPrincipalNameTransformer(Beans.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        h.setPrincipalNameTransformer(Beans.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (this.searchModePasswordPolicyConfiguration != null) {
            h.setPasswordPolicyConfiguration(this.searchModePasswordPolicyConfiguration);
        }

        if (StringUtils.isNotBlank(b.getCredentialCriteria())) {
            h.setCredentialSelectionPredicate(Beans.newCredentialSelectionPredicate(b.getCredentialCriteria()));
        }

        LOGGER.debug("Created authentication handler [{}] to handle database url at [{}]", h.getName(), b.getUrl());
        return h;
    }

    @ConditionalOnMissingBean(
            name = {"jdbcPrincipalFactory"}
    )
    @Bean
    @RefreshScope
    public PrincipalFactory jdbcPrincipalFactory() {
        return new DefaultPrincipalFactory();
    }

    @Configuration("jdbcAuthenticationEventExecutionPlanConfiguration")
    @EnableConfigurationProperties({CasConfigurationProperties.class})
    public class JdbcAuthenticationEventExecutionPlanConfiguration implements AuthenticationEventExecutionPlanConfigurer {
        @Autowired
        @Qualifier("personDirectoryPrincipalResolver")
        private PrincipalResolver personDirectoryPrincipalResolver;

        public JdbcAuthenticationEventExecutionPlanConfiguration() {
        }

        public void configureAuthenticationExecutionPlan(AuthenticationEventExecutionPlan plan) {
            MyJdbcAuthenticationHandlers.this.jdbcAuthenticationHandlers().forEach((h) -> {
                plan.registerAuthenticationHandlerWithPrincipalResolver(h, this.personDirectoryPrincipalResolver);
            });
        }
    }

}
