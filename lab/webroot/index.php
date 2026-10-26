<?php
header('Content-Type: text/html; charset=utf-8');
echo "php_Archangel lab target\n";
echo "PHP Version: " . PHP_VERSION . "\n";
echo "SAPI: " . php_sapi_name() . "\n";
echo "memory_limit: " . ini_get('memory_limit') . "\n";
echo "session.up: " . (ini_get('session.upload_progress.enabled') ? 'On' : 'Off') . "\n";
echo "expose_php: " . (ini_get('expose_php') ? 'On' : 'Off') . "\n";
