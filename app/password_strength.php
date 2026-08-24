<?php
// Item 3: password strength meter + common-password rejection.
// Built-in list (no external API call) of frequently breached/reused
// passwords - checked case-insensitively. Not exhaustive; it's a
// teaching baseline, not a substitute for a real breach-corpus check
// (e.g. k-anonymity against Have I Been Pwned) in a production system.

function common_passwords() {
    static $list = null;
    if ($list !== null) { return $list; }
    $list = array(
        '123456', '123456789', 'qwerty', 'password', '12345678', '111111', '123123',
        '1234567890', '1234567', 'qwerty123', '000000', '1q2w3e', 'aa12345678', 'abc123',
        'password1', '1234', '12345', 'iloveyou', '654321', '666666', 'qwertyuiop',
        '123321', 'letmein', 'admin', 'welcome', 'monkey', 'login', 'princess',
        'dragon', 'passw0rd', 'master', 'hello', 'freedom', 'whatever', 'trustno1',
        'sunshine', 'football', 'baseball', 'shadow', 'superman', 'michael', 'ninja',
        'mustang', 'jennifer', 'access', 'flower', '7777777', 'starwars', 'zaq1zaq1',
        'test123', 'qazwsx', 'chocolate', 'summer', 'winter', 'purple', 'orange',
        'charlie', 'donald', 'george', 'jordan23', 'harley', 'ranger', 'buster',
        'thomas', 'robert', 'soccer', 'hockey', 'killer', 'george', 'andrew',
        'password123', 'admin123', 'root', 'toor', 'changeme', 'letmein123',
        'qwerty1', '1qaz2wsx', 'abcd1234', 'p@ssw0rd', 'p@ssword', 'nigeria123',
        'lagos123', 'nigeria', 'welcome123',
    );
    return $list;
}

function is_common_password($password) {
    return in_array(strtolower($password), common_passwords(), true);
}

// Simple, transparent heuristic (not entropy-perfect, but explainable):
// awards points for length and character-class variety. Returns
// array('score' => 0-5, 'label' => ..., 'reasons' => array of unmet criteria).
function password_strength($password) {
    $score = 0;
    $reasons = array();

    if (strlen($password) >= 8) { $score++; } else { $reasons[] = 'at least 8 characters'; }
    if (strlen($password) >= 12) { $score++; }
    if (preg_match('/[a-z]/', $password) && preg_match('/[A-Z]/', $password)) { $score++; } else { $reasons[] = 'upper and lower case letters'; }
    if (preg_match('/[0-9]/', $password)) { $score++; } else { $reasons[] = 'at least one number'; }
    if (preg_match('/[^A-Za-z0-9]/', $password)) { $score++; } else { $reasons[] = 'at least one symbol'; }

    $labels = array('Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong');
    return array('score' => $score, 'label' => $labels[$score], 'reasons' => $reasons);
}

// Server-side authoritative check used at register/reset time.
// Returns an error string, or null if acceptable.
function password_policy_error($password, $username = null) {
    if (strlen($password) < 8) { return 'Password must be at least 8 characters.'; }
    if (is_common_password($password)) { return 'That password is on a list of commonly breached passwords - choose another.'; }
    if ($username !== null && strtolower($password) === strtolower($username)) { return 'Password cannot be the same as your username.'; }
    return null;
}
