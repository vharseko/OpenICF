/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 3A Systems, LLC.
 */
package org.forgerock.openicf.framework.server;

import static org.forgerock.openicf.framework.AsyncConnectorInfoManagerTestBase.JSK_PASSWORD;
import static org.forgerock.openicf.framework.AsyncConnectorInfoManagerTestBase.KEY_HASH;
import static org.forgerock.openicf.framework.AsyncConnectorInfoManagerTestBase.TEST_CONNECTOR_KEY;
import static org.forgerock.openicf.framework.AsyncConnectorInfoManagerTestBase.buildRemoteWSFrameworkConnectionInfo;
import static org.forgerock.openicf.framework.AsyncConnectorInfoManagerTestBase.findFreePort;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.net.URL;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLHandshakeException;

import org.forgerock.openicf.framework.ConnectorFramework;
import org.forgerock.openicf.framework.ConnectorFrameworkFactory;
import org.forgerock.openicf.framework.client.ClientRemoteConnectorInfoManager;
import org.forgerock.openicf.framework.client.ConnectionManager;
import org.forgerock.openicf.framework.client.ConnectionManagerConfig;
import org.forgerock.openicf.framework.client.RemoteWSFrameworkConnectionInfo;
import org.forgerock.openicf.framework.remote.ReferenceCountedObject;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.ssl.SSLContextConfigurator;
import org.identityconnectors.framework.api.ConnectorInfo;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.testconnector.TstConnector;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * The WebSocket client must check the connector server certificate against
 * the host of the remote URI. {@code serverKeystore.jks} names
 * {@code localhost}, {@code 127.0.0.1} and {@code ::1} as subjectAltName;
 * {@code serverKeystore-cn-only.jks} only has {@code CN=localhost}. Both are
 * trusted by {@code truststore.jks}, which the client picks up through the
 * {@code javax.net.ssl.trustStore} system properties.
 */
public class ClientHostnameVerificationTest {

    private static final long TIMEOUT_SECONDS = 30;

    private final int sanPort = findFreePort();
    private final int cnOnlyPort = findFreePort();

    private ConnectorServer connectorServer;

    /**
     * Like the other tests of this module, the server lives for the whole
     * run: every {@link ConnectorServer} registers with the JVM-wide Grizzly
     * {@code WebSocketEngine}, and unregistering one while other test
     * servers are still in use leaves their WebSocket upgrades unanswered.
     */
    @BeforeTest
    public void startServer() throws Exception {
        String truststore = resourcePath("truststore.jks");
        System.setProperty(SSLContextConfigurator.TRUST_STORE_FILE, truststore);
        System.setProperty(SSLContextConfigurator.TRUST_STORE_PASSWORD, JSK_PASSWORD);

        connectorServer = new ConnectorServer();
        connectorServer.setConnectorFrameworkFactory(new ConnectorFrameworkFactory());
        connectorServer.setConnectorBundleURLs(Arrays.asList(TstConnector.class
                .getProtectionDomain().getCodeSource().getLocation()));
        connectorServer.init();
        connectorServer.addListener("san", NetworkListener.DEFAULT_NETWORK_HOST, sanPort,
                serverSSLContext("serverKeystore.jks", truststore));
        connectorServer.addListener("cn-only", NetworkListener.DEFAULT_NETWORK_HOST, cnOnlyPort,
                serverSSLContext("serverKeystore-cn-only.jks", truststore));
        connectorServer.setKeyHash(KEY_HASH);
        connectorServer.start();
    }

    @AfterTest
    public void stopServer() throws Exception {
        connectorServer.stop();
        connectorServer.destroy();
    }

    @Test
    public void rejectsServerCertificateWithoutMatchingName() throws Exception {
        try (Client client = new Client(new ConnectionManagerConfig())) {
            try {
                client.connect(cnOnlyPort);
                fail("Expected the handshake to fail: certificate has no name matching 127.0.0.1");
            } catch (ConnectorException e) {
                assertHostnameVerificationFailure(e);
            }
        }
    }

    @Test
    public void acceptsServerCertificateWithMatchingSubjectAltName() throws Exception {
        try (Client client = new Client(new ConnectionManagerConfig())) {
            assertNotNull(client.connect(sanPort));
        }
    }

    @Test
    public void connectsToMismatchedCertificateWhenVerificationIsDisabled() throws Exception {
        ConnectionManagerConfig config = new ConnectionManagerConfig();
        config.setHostnameVerification(false);
        try (Client client = new Client(config)) {
            assertNotNull(client.connect(cnOnlyPort));
        }
    }

    // ---- helpers ---------------------------------------------------------

    private static void assertHostnameVerificationFailure(ConnectorException e) {
        Throwable cause = e;
        while (cause != null && !(cause instanceof SSLHandshakeException)) {
            cause = cause.getCause();
        }
        assertNotNull(cause, "Expected an SSLHandshakeException in the cause chain of: " + e);
        String message = String.valueOf(cause.getMessage());
        assertTrue(message.contains("subject alternative") || message.contains("No name matching"),
                "Expected a hostname verification failure, got: " + message);
    }

    private static SSLContextConfigurator serverSSLContext(String keystore, String truststore)
            throws Exception {
        SSLContextConfigurator configurator = new SSLContextConfigurator(false);
        configurator.setKeyStoreFile(resourcePath(keystore));
        configurator.setKeyStorePass(JSK_PASSWORD);
        configurator.setTrustStoreFile(truststore);
        configurator.setTrustStorePass(JSK_PASSWORD);
        configurator.setSecurityProtocol("TLS");
        return configurator;
    }

    private static String resourcePath(String name) throws Exception {
        URL url = ClientHostnameVerificationTest.class.getClassLoader().getResource(name);
        assertNotNull(url, "missing test resource " + name);
        return URLDecoder.decode(url.getFile(), "UTF-8");
    }

    /** A client-side framework with its own connection manager configuration. */
    private static final class Client implements AutoCloseable {
        private final ReferenceCountedObject<ConnectorFramework>.Reference framework;

        Client(ConnectionManagerConfig config) {
            framework = new ConnectorFrameworkFactory().acquire();
            framework.get().setConnectionManagerConfig(config);
        }

        /**
         * Opens the WebSocket to the server on {@code port} and, once it is
         * up, looks up the test connector over it, so that the initial
         * exchange has completed by the time the client is closed.
         */
        ConnectorInfo connect(int port) throws Exception {
            RemoteWSFrameworkConnectionInfo info =
                    buildRemoteWSFrameworkConnectionInfo(true, port, null);
            ConnectionManager connectionManager =
                    (ConnectionManager) framework.get().getRemoteConnectionInfoManagerFactory();
            ClientRemoteConnectorInfoManager manager = connectionManager.connect(info);
            manager.connect().getOrThrow(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            return manager.getAsyncConnectorInfoManager().findConnectorInfoAsync(
                    TEST_CONNECTOR_KEY).getOrThrow(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }

        public void close() {
            framework.release();
        }
    }
}
