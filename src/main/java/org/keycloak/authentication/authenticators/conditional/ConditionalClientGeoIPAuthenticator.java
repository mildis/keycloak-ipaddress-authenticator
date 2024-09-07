package org.keycloak.authentication.authenticators.conditional;

import com.maxmind.db.CHMCache;
import com.maxmind.db.Reader.FileMode;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CountryResponse;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddressString;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import java.io.File;

import static java.text.MessageFormat.format;
import static org.keycloak.authentication.authenticators.conditional.ConditionalClientGeoIPAuthenticatorFactory.*;
import static org.keycloak.models.Constants.CFG_DELIMITER_PATTERN;

public class ConditionalClientGeoIPAuthenticator implements ConditionalAuthenticator {

    public static final ConditionalClientGeoIPAuthenticator SINGLETON = new ConditionalClientGeoIPAuthenticator();

    private static final Logger LOG = Logger.getLogger(ConditionalClientGeoIPAuthenticator.class);
    private static final String X_FORWARDED_FOR_HEADER_NAME = "X-Forwarded-For";

    private static File database = new File("/path/to/GeoIP2-City.mmdb");

    private DatabaseReader mmdbReader;

    public ConditionalClientGeoIPAuthenticator() {
        try {
            mmdbReader = new DatabaseReader.Builder(database)
                    .fileMode(FileMode.MEMORY_MAPPED).withCache(new CHMCache()).build();
        } catch (Exception e) {
            LOG.error("Cannot open DB", e);
        }
    }

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        final Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        final boolean exclude = Boolean.parseBoolean(config.get(CONF_EXCLUDE));
        final boolean nocountry = Boolean.parseBoolean(config.get(CONF_NO_COUNTRY));
        final Stream<String> countries = getConfiguredCountries(config);

        final String clientCountry = getClientCountry(context);
        if (clientCountry.isEmpty()) {
            return nocountry;
        }
        if (exclude) {
            return countries.noneMatch(country -> country.contains(clientCountry));
        } else {
            return countries.anyMatch(country -> country.contains(clientCountry));
        }
    }

    private Stream<String> getConfiguredCountries(Map<String, String> config) {

        final String countriesAsString = config.get(CONF_COUNTRIES);
        if (countriesAsString == null) {
            throw new IllegalStateException("No countries configured");
        }

        final String[] countries = CFG_DELIMITER_PATTERN.split(countriesAsString);
        if (countries.length == 0) {
            throw new IllegalStateException("No countries configured");
        }

        return Arrays.stream(countries)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .filter(s -> s.length() == 2)
                .map(String::toUpperCase);
    }

    private String getClientCountry(AuthenticationFlowContext context) {

        if (mmdbReader == null) {
            return "";
        }

        final List<String> xForwardedForHeaders = context.getHttpRequest()
                .getHttpHeaders()
                .getRequestHeader(X_FORWARDED_FOR_HEADER_NAME);

        final Optional<InetAddress> ipAddressFromForwardedHeader = xForwardedForHeaders
                .stream()
                .map(this::parseIpAddress)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .findFirst();


        if (ipAddressFromForwardedHeader.isPresent()) {
            try {
                Optional<CountryResponse> countryResponse = mmdbReader.tryCountry(ipAddressFromForwardedHeader.get());
                if (countryResponse.isPresent()) {
                    CountryResponse cr = countryResponse.get();
                    return cr.getCountry().getIsoCode();
                }
            } catch (Exception e) {
                LOG.warn("Country lookup failed for " + ipAddressFromForwardedHeader, e);
                return "";
            }
        }

        final String ipAddressStringFromClientConnection = context.getConnection().getRemoteAddr();
        final Optional<InetAddress> ipAddressFromConnection = parseIpAddress(ipAddressStringFromClientConnection);
        if (ipAddressFromConnection.isPresent()) {
            try {
                Optional<CountryResponse> countryResponse = mmdbReader.tryCountry(ipAddressFromConnection.get());
                if (countryResponse.isPresent()) {
                    CountryResponse cr = countryResponse.get();
                    return cr.getCountry().getIsoCode();
                }
            } catch (Exception e) {
                LOG.warn("Country lookup failed for " + ipAddressFromForwardedHeader, e);
                return "";
            }
        }

        throw new IllegalStateException(format("No valid ip address found in {0} header ({1}) or in client connection ({2})",
                X_FORWARDED_FOR_HEADER_NAME, xForwardedForHeaders, ipAddressStringFromClientConnection));
    }

    private Optional<InetAddress> parseIpAddress(String text) {
        IPAddressString ipAddressString = new IPAddressString(text);

        if (!ipAddressString.isValid()) {
            LOG.warn("Ignoring invalid IP address " + ipAddressString);
            return Optional.empty();
        }

        try {
            final InetAddress parsedIpAddress = ipAddressString.toAddress().toInetAddress();
            return Optional.of(parsedIpAddress);
        } catch (AddressStringException e) {
            LOG.warn("Ignoring invalid IP address " + ipAddressString, e);
            return Optional.empty();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Not used
    }

    @Override
    public void close() {
        // Does nothing
    }
}