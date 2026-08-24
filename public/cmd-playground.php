<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_login();

// Item 12: OS command injection playground, simulating an
// authenticated network-diagnostics tool ("ping this host").
//
// Deliberate safety choice, same reasoning as this machine's other
// PHP project's upload/command-injection labs: this is a real
// Windows machine, not a disposable container, reachable by anything
// on the same LAN. The vulnerable side shows genuinely vulnerable
// code (string-concatenated into a shell command) but NEVER actually
// calls shell_exec()/exec() with attacker-controlled input - it
// pattern-matches for injection metacharacters and simulates the
// consequence instead. The patched side is real: it validates the
// hostname strictly and, only for a validated safe value, runs a
// real `ping` via properly escaped arguments.

$mode = (isset($_POST['mode']) && $_POST['mode'] === 'vulnerable') ? 'vulnerable' : 'patched';
$host = isset($_POST['host']) ? $_POST['host'] : '';
$output = null;
$vulnerableCode = "shell_exec('ping -n 2 ' . \$_POST['host']);";
$patchedCode = "if (preg_match('/^[a-zA-Z0-9.-]+\$/', \$host)) {\n    shell_exec('ping -n 2 ' . escapeshellarg(\$host));\n}";

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $host !== '') {
    if ($mode === 'vulnerable') {
        $injectionChars = array(';', '&', '|', '`', '$(', '&&', '||', '>', '<');
        $injected = false;
        foreach ($injectionChars as $ch) {
            if (strpos($host, $ch) !== false) { $injected = true; break; }
        }
        if ($injected) {
            audit_log_event('cmd_injection_demo_triggered', current_user_id(), 'host=' . $host);
            $output = "[SIMULATED - no real shell was invoked]\n"
                . "Pinging (unvalidated input passed straight into a shell command)...\n"
                . "Because the input contains a shell metacharacter, on a real vulnerable\n"
                . "system your injected command would have run here with the web server's\n"
                . "privileges. This demo stops at showing that, rather than actually doing it.";
        } else {
            audit_log_event('cmd_injection_demo_query', current_user_id(), 'host=' . $host);
            $output = "[SIMULATED]\nPinging $host (fake output - no real shell_exec runs on this vulnerable path in this demo)...\nReply from $host: time<1ms";
        }
    } else {
        if (!preg_match('/^[a-zA-Z0-9.-]+$/', $host)) {
            $output = "REJECTED: \"$host\" contains characters outside [a-zA-Z0-9.-] - never passed to a shell.";
            audit_log_event('cmd_injection_demo_blocked', current_user_id(), 'host=' . $host);
        } else {
            $cmd = 'ping -n 2 ' . escapeshellarg($host);
            $output = shell_exec($cmd);
            if ($output === null) { $output = '(no output / host unreachable)'; }
            audit_log_event('cmd_injection_demo_real_ping', current_user_id(), 'host=' . $host);
        }
    }
}

render_header('Command injection playground');
?>
<h1>OS command injection playground</h1>
<p class="lead">Try a hostname like <code>127.0.0.1 &amp; whoami</code> in vulnerable mode. In patched mode, only a strictly validated hostname is ever passed to a real (properly escaped) <code>ping</code>.</p>

<div class="card" style="max-width:520px">
  <form method="post" action="<?php echo e(base_url('cmd-playground')); ?>">
    <?php echo csrf_field(); ?>
    <label for="host">Host to ping</label>
    <input type="text" id="host" name="host" value="<?php echo e($host); ?>" required>
    <label style="display:flex;align-items:center;gap:8px;margin-top:10px">
      <input type="radio" name="mode" value="patched" <?php echo $mode === 'patched' ? 'checked' : ''; ?> style="width:auto"> Patched (validated, real ping)
    </label>
    <label style="display:flex;align-items:center;gap:8px">
      <input type="radio" name="mode" value="vulnerable" <?php echo $mode === 'vulnerable' ? 'checked' : ''; ?> style="width:auto"> Vulnerable (simulated, not real)
    </label>
    <button type="submit">Run</button>
  </form>
</div>

<div class="card">
  <p><small class="hint">Code for this mode:</small></p>
  <code class="mono" style="display:block;white-space:pre-wrap"><?php echo e($mode === 'vulnerable' ? $vulnerableCode : $patchedCode); ?></code>
</div>

<?php if ($output !== null) : ?>
  <div class="card">
    <p><small class="hint">Output:</small></p>
    <code class="mono" style="display:block;white-space:pre-wrap"><?php echo e($output); ?></code>
  </div>
<?php endif; ?>

<?php render_footer(); ?>
