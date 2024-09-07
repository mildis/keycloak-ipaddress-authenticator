package org.keycloak.authentication.authenticators.conditional;

import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.BOOLEAN_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.MULTIVALUED_STRING_TYPE;

public class ConditionalClientGeoIPAuthenticatorFactory implements ConditionalAuthenticatorFactory {

    public static final String PROVIDER_ID = "conditional-client-geoip-address";

    public static final String CONF_COUNTRIES = "countries";
    public static final String CONF_EXCLUDE = "exclude";
    public static final String CONF_NO_COUNTRY = "no-country";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = new AuthenticationExecutionModel.Requirement[]{
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public void init(Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - Country";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Flow is executed only if the client country is in specified countries list";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        final ProviderConfigProperty countries = new ProviderConfigProperty();
        countries.setType(MULTIVALUED_STRING_TYPE);
        countries.setName(CONF_COUNTRIES);
        countries.setDefaultValue("FR");
        countries.setLabel("Countries");
        countries.setHelpText("A list of country ISO codes. Example: FR,US");

        final ProviderConfigProperty exclude = new ProviderConfigProperty();
        exclude.setType(BOOLEAN_TYPE);
        exclude.setName(CONF_EXCLUDE);
        exclude.setLabel("Exclude specified countries");
        exclude.setHelpText("Match if client country is NOT in specified countries");

        final ProviderConfigProperty nocountry = new ProviderConfigProperty();
        nocountry.setType(BOOLEAN_TYPE);
        nocountry.setName(CONF_NO_COUNTRY);
        nocountry.setLabel("Match if country can not be determined");
        nocountry.setHelpText("Match if country can not be determined");

        return Arrays.asList(countries, exclude, nocountry);
    }

    @Override
    public ConditionalAuthenticator getSingleton() {
        return ConditionalClientGeoIPAuthenticator.SINGLETON;
    }
}
