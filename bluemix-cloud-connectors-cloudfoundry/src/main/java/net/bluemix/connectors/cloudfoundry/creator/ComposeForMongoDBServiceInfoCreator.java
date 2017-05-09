package net.bluemix.connectors.cloudfoundry.creator;

import com.mongodb.MongoClientOptions;
import com.mongodb.MongoClientURI;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import net.bluemix.connectors.core.creator.CloudantInstanceCreator;
import net.bluemix.connectors.core.info.ComposeForMongoDBServiceInfo;
import org.apache.commons.codec.binary.Base64;
import org.springframework.cloud.cloudfoundry.CloudFoundryServiceInfoCreator;
import org.springframework.cloud.cloudfoundry.Tags;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Arrays.asList;

/**
 * Creates a new {@link ComposeForMongoDBServiceInfo}.
 *
 * @author Dominik Matta
 */
public class ComposeForMongoDBServiceInfoCreator extends CloudFoundryServiceInfoCreator<ComposeForMongoDBServiceInfo> {
    private static final Logger LOG = Logger.getLogger(CloudantInstanceCreator.class.getName());

    public ComposeForMongoDBServiceInfoCreator() {
        super(new Tags("compose-for-mongodb"), ComposeForMongoDBServiceInfo.SCHEME);
    }

    @Override
    public ComposeForMongoDBServiceInfo createServiceInfo(Map<String, Object> serviceData) {
        LOG.info("Creating MongoDB service info");
        String id = getId(serviceData);
        Map<String, Object> credentials = getCredentials(serviceData);
        MongoClientURI mongoURI = new MongoClientURI(getUriFromCredentials(credentials));
        List<ServerAddress> serverAddresses = createServerAddresses(mongoURI.getHosts());
        List<MongoCredential> credentialList = mongoURI.getCredentials() != null
                ? asList(mongoURI.getCredentials())
                : Collections.<MongoCredential>emptyList();
        MongoClientOptions options = createMongoClientOptions(mongoURI.getOptions(), credentials);
        return new ComposeForMongoDBServiceInfo(id, serverAddresses, credentialList, options);
    }

    protected MongoClientOptions createMongoClientOptions(MongoClientOptions options, Map<String, Object> credentials) {
        MongoClientOptions.Builder optionsBuilder = MongoClientOptions.builder(options);
        String sslCertBase64 = (String) credentials.get("ca_certificate_base64");
        if (options.isSslEnabled() && sslCertBase64 != null) {
            try {
                optionsBuilder.sslEnabled(true).sslInvalidHostNameAllowed(true);
                byte[] caCertBytes = Base64.decodeBase64(sslCertBase64);
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                Certificate caCert = certificateFactory.generateCertificate(new ByteArrayInputStream(caCertBytes));

                KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                trustStore.load(null, null);
                trustStore.setCertificateEntry("bluemix_mongo", caCert);

                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trustStore);

                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, tmf.getTrustManagers(), null);

                SSLSocketFactory socketFactory = sslContext.getSocketFactory();
                optionsBuilder.socketFactory(socketFactory);
            } catch (CertificateException | KeyStoreException | IOException | KeyManagementException | NoSuchAlgorithmException e) {
                LOG.log(Level.WARNING, "Error creating MongoClientOptions with trust store", e);
            }
        }
        return optionsBuilder.build();
    }

    protected List<ServerAddress> createServerAddresses(List<String> hosts) {
        List<ServerAddress> serverAddresses = new ArrayList<>();
        for (String host : hosts) {
            serverAddresses.add(new ServerAddress(host));
        }
        return serverAddresses;
    }
}
