package main.java.burp;

import burp.*;
import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.*;

import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;

public class DPoPConfigurator implements IBurpExtender, ITab, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    PrintWriter stdout;
    PrintWriter stderr;
    private JPanel panel;
    private JTextField publicKeyTextField;
    private JTextField privateKeyTextField;
    private JTextField targetTextField;
    private JTextField targetHttpHeaderTextField;
    private JCheckBox regexCheckBox;
    private JLabel resultLabel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName("DPoP Configurator");
        callbacks.registerHttpListener(this);

        SwingUtilities.invokeLater(() -> {
            panel = new JPanel(new GridLayout(30, 3, 5, 5));
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            JLabel infoPublic = new JLabel("Enter Public Key JWK:");
            JLabel infoPrivate = new JLabel("Enter Private Key JWK:");
            JLabel infoTarget = new JLabel("Enter Target URL or Target's regex:");
            JLabel infoRegex = new JLabel("Is Regex:");
            JLabel infoHTTPHeader = new JLabel("DPoP HTTP Header:");

            publicKeyTextField = new JTextField(10);
            privateKeyTextField = new JTextField(10);
            targetTextField = new JTextField(10);
            regexCheckBox = new JCheckBox();
            targetHttpHeaderTextField = new JTextField(10);

            resultLabel = new JLabel("", SwingConstants.CENTER);
            resultLabel.setForeground(Color.BLUE);

            panel.add(infoPublic);        panel.add(publicKeyTextField);
            panel.add(infoPrivate);       panel.add(privateKeyTextField);
            panel.add(infoTarget);        panel.add(targetTextField);
            panel.add(infoRegex);         panel.add(regexCheckBox);
            panel.add(infoHTTPHeader);    panel.add(targetHttpHeaderTextField);

            callbacks.customizeUiComponent(panel);
            callbacks.addSuiteTab(DPoPConfigurator.this);
        });
    }

    @Override public String getTabCaption() { return "DPoP Configurator"; }
    @Override public Component getUiComponent() { return panel; }

    private void log(String msg) {
        stdout.println("[DPoP] " + msg);
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) return;

        IRequestInfo requestInfo = this.callbacks.getHelpers().analyzeRequest(messageInfo);
        String targetUrl = targetTextField.getText();
        boolean isRegex = regexCheckBox.isSelected();

        try {
            if (!targetUrl.isEmpty()) {
                boolean match = isRegex
                        ? requestInfo.getUrl().toString().matches(targetUrl)
                        : requestInfo.getUrl().toString().contains(targetUrl);

                if (match) {
                    log("----- Intercepted matching request: " + requestInfo.getUrl() + " -----");
                    ArrayList<String> headers = editDPopJWT(requestInfo);
                    byte[] message = helpers.buildHttpMessage(
                            headers,
                            Arrays.copyOfRange(messageInfo.getRequest(), requestInfo.getBodyOffset(), messageInfo.getRequest().length));
                    messageInfo.setRequest(message);
                }
            }
        } catch (Exception e) {
            stderr.println("[DPoP] ERROR: " + e);
            e.printStackTrace(stderr);
            throw new RuntimeException(e);
        }
    }

    public ArrayList<String> editDPopJWT(IRequestInfo requestInfo) throws Exception {
        String privateKeyJson = privateKeyTextField.getText();
        String publicKeyJson  = publicKeyTextField.getText();

        RSAPrivateKey privateKey = (RSAPrivateKey) RSAKey.parse(privateKeyJson).toPrivateKey();

        // Preserve the EXACT n/e strings from the supplied JWK (no BigInteger round-trip)
        RSAKey parsedPub = RSAKey.parse(publicKeyJson);
        Base64URL n = parsedPub.getModulus();
        Base64URL e = parsedPub.getPublicExponent();
        String kid = parsedPub.getKeyID();

        String headerName = targetHttpHeaderTextField.getText();

        URL url = requestInfo.getUrl();
        String htu = url.getProtocol() + "://" + url.getHost();
        if (url.getPort() != -1 && url.getPort() != url.getDefaultPort()) {
            htu += ":" + url.getPort();
        }
        htu += url.getPath();
        String htm = requestInfo.getMethod();

        String jwt = generateDPoPJWT(privateKey, n, e, kid, htm, htu);

        ArrayList<String> headers = (ArrayList<String>) requestInfo.getHeaders();
        ArrayList<String> newHeaders = new ArrayList<>();
        for (String h : headers) {
            if (!h.toLowerCase().startsWith(headerName.toLowerCase())) newHeaders.add(h);
        }
        newHeaders.add(headerName + ": " + jwt);
        return newHeaders;
    }

    public String generateDPoPJWT(RSAPrivateKey privateKey, Base64URL n, Base64URL e,
                                  String kid, String htm, String htu) throws Exception {
        String jwtID = UUID.randomUUID().toString();
        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 120_000)) // FIX: 2 min, was +60 ms
                .jwtID(jwtID)
                .claim("htm", htm)
                .claim("htu", htu)
                .build();

        // FIX: build header jwk straight from the Base64URL strings -> n preserved byte-for-byte
        JWK jwk = new RSAKey.Builder(n, e)
                .keyID(kid)
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(jwk)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new RSASSASigner(privateKey));
        String out = signedJWT.serialize();

        // ---- console logging ----
        log("htm = " + htm);
        log("htu = " + htu);
        log("jti = " + jwtID);
        log("iat = " + now.getTime() / 1000 + "  exp = " + (now.getTime() + 120_000) / 1000);
        log("header = " + header.toJSONObject());
        log("claims = " + claimsSet.toJSONObject());
        log("jkt (RFC7638 over embedded n/e) = " + jkt(n, e));
        log("DPoP JWT =\n" + out);
        log("-------------------------------------------------");
        return out;
    }

    // Compute the thumbprint the SERVER will derive from the embedded jwk
    private static String jkt(Base64URL n, Base64URL e) throws Exception {
        String json = "{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}";
        byte[] d = MessageDigest.getInstance("SHA-256").digest(json.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(d);
    }
}