// Example php API script used to query your DB. It is a bridghe between Your Pure AI assistant and your Database data which will be used as RAG.

<?php
// Debug enablement
ini_set('display_errors', 1);
error_reporting(E_ALL);

//ini_set('log_errors', 1);
//ini_set('error_log', __DIR__ . '/error.log');

// Answer always as JSON
header('Content-Type: application/json');

// Set up CORS headers - modify according to your needs.
header('Access-Control-Allow-Origin: *');
//header('Access-Control-Allow-Origin: https://lovable.app');
//header('Access-Control-Allow-Origin: https://lovable.dev');
//header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Process preflight requests for CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Debug mode on / off
$debug_mode = true;

// Function to log errors
function logError($message, $debug_mode = false) {
    error_log($message);
    http_response_code(500);

    if ($debug_mode) {
        // Return real error message in debug mode
        echo json_encode([
            'action' => defined('API_action_type') ? API_action_type : 'error',
            'data' => ['error' => $message]
        ]);
    } else {
        // In production mode, we return a generic error message
        echo json_encode([
            'action' => defined('API_action_type') ? API_action_type : 'error',
            'data' => ['error' => 'Internal server error. Please contact the administrator.']
        ]);
    }
    exit;
}

// Catch all PHP errors
set_error_handler(function($errno, $errstr, $errfile, $errline) use ($debug_mode) {
    $error_message = "PHP Error [$errno]: $errstr in $errfile on line $errline";
    logError($error_message, $debug_mode);
    return true;
});

// Catch-all exception handler
set_exception_handler(function($e) use ($debug_mode) {
    $error_message = "Uncaught Exception: " . $e->getMessage() . " in " . $e->getFile() . " on line " . $e->getLine();
    logError($error_message, $debug_mode);
});

// Check of the method is POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'action' => defined('API_action_type') ? API_action_type : 'error',
        'data' => ['error' => 'Pouze metoda POST je povolena']
    ]);
    exit;
}

try {
    require_once __DIR__ . '/../../protected/config.php'; // Change to your real location of config.php

    // Check of the required constants are defined
    // API key is not defined in config.php
    if (!defined('API_KEY')) {
        throw new Exception('API key is not defined in config.php file');
    }
    if (!defined('API_action_type')) {
        throw new Exception('API_action_type is not defined in config.php file');
    }
    if (!defined('DB_SERVER') || !defined('DB_USERNAME') || !defined('DB_PASSWORD') || !defined('DB_NAME')) {
        throw new Exception('Database connection details are not fully defined in config.php file');
    }

    // Get data from POST request
    $rawInput = file_get_contents('php://input');
    if ($rawInput === false) {
        throw new Exception('Unable to read data');
    }
    if ($debug_mode) {
        error_log("Raw input: " . $rawInput);
    }

    $inputData = json_decode($rawInput, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Error during decoding of JSON: ' . json_last_error_msg());
    }

    // Check API key
    if (!isset($inputData['api_key'])) {
        http_response_code(401);
        echo json_encode(['action' => defined('API_action_type') ? API_action_type : 'error', 'data' => ['error' => 'API is mandatory']]);
        exit;
    }
    if (!hash_equals(API_KEY, $inputData['api_key'])) {
        http_response_code(401);
        echo json_encode(['action' => defined('API_action_type') ? API_action_type : 'error', 'data' => ['error' => 'Invalid API key']]);
        exit;
    }

    // Check SQL query
    if (!isset($inputData['query']) || empty(trim($inputData['query']))) {
        http_response_code(400);
        echo json_encode(['action' => defined('API_action_type') ? API_action_type : 'error', 'data' => ['error' => 'SQL query is mandatory']]);
        exit;
    }

    $query = trim($inputData['query']);
    if ($debug_mode) {
        error_log("SQL query: " . $query);
    }

    // Only SELECT, INSERT, UPDATE are allowed. You can remove INSERT and UPDATE if you want to read only data from the DB.
    $queryType = null;
    if (preg_match('/^\s*SELECT\b/i', $query)) {
        $queryType = 'SELECT';
    } elseif (preg_match('/^\s*INSERT\b/i', $query)) {
        $queryType = 'INSERT';
    } elseif (preg_match('/^\s*UPDATE\b/i', $query)) {
        $queryType = 'UPDATE';
    }

    // Refuse the query if not started with a valid and allowed command
    if ($queryType === null) {
        http_response_code(403);
        echo json_encode([
            'action' => defined('API_action_type') ? API_action_type : 'error',
            'data' => ['error' => 'Only SELECT, INSERT and UPDATE queries are allowed.']
        ]);
        exit;
    }

    // Additional control to prevent unsafe commands
    $disallowedKeywords = ['DROP', 'TRUNCATE', 'DELETE', 'CREATE', 'ALTER', 'GRANT', 'EXEC', 'CALL']; // Přidán EXEC a CALL pro jistotu
    foreach ($disallowedKeywords as $keyword) {
        // Use borders (\b) to prevent false positives (e.g. in column names)
        if (preg_match('/\b' . $keyword . '\b/i', $query)) {
            http_response_code(403);
            echo json_encode([
                'action' => defined('API_action_type') ? API_action_type : 'error',
                'data' => ['error' => "Command '$keyword' not allowed."]
            ]);
            exit;
        }
    }

    // Important notice: Direct running of SQL from input is still dangerous!
    // Use parametrized queries if possible.
    // This script expect, that the queries are safe and valid.

    // Establish connection to the database
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    if ($conn->connect_error) {
        throw new Exception("Error during connecting to the database: " . $conn->connect_error);
    }
    $conn->set_charset("utf8mb4");

    // Execute query
    $result = $conn->query($query);

    // Check errors during query execution
    if ($result === false) {
        throw new Exception("Error during executing SQL query: " . $conn->error . " (Query: $query)");
    }

    // Process results according to it's type
    $responseData = [];
    if ($queryType === 'SELECT') {
        // Process SELECT query
        $data = [];
        // $result is object of type mysqli_result
        if ($result->num_rows > 0) {
            while ($row = $result->fetch_assoc()) {
                $data[] = $row;
            }
        }
        $responseData['results'] = $data; // Insert data to the key 'results'
        $result->free(); // Free the memory for SELECT
    } elseif ($queryType === 'INSERT') {
        // Process result of INSERT query
        // $result is boolean (true for success)
        $responseData['affected_rows'] = $conn->affected_rows;
        $responseData['insert_id'] = $conn->insert_id;
    } elseif ($queryType === 'UPDATE') {
        // Process result of UPDATE query
        // $result is boolean (true for success)
        $responseData['affected_rows'] = $conn->affected_rows;
    }
    // For INSERT a UPDATE there is no need to call free()

    // Close connection
    $conn->close();

    // Return result in correct JSON structure
    echo json_encode([
        'action' => API_action_type,
        'data' => $responseData // Return structured data according to the query
    ]);

} catch (Exception $e) {
    http_response_code(500);
    $error_message = $e->getMessage();

    if ($debug_mode) {
        $error_message .= " in " . $e->getFile() . " on line " . $e->getLine();
        $error_message .= "\nStack trace: " . $e->getTraceAsString();
    }

    echo json_encode([
        'action' => defined('API_action_type') ? API_action_type : 'error',
        'data' => ['error' => $error_message]
    ]);
}
?>
