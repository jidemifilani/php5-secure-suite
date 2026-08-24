<?php
require_once __DIR__ . '/../app/bootstrap.php';

$mode = (isset($_POST['mode']) && $_POST['mode'] === 'vulnerable') ? 'vulnerable' : 'patched';
$data = isset($_POST['data']) ? $_POST['data'] : '';
$result = null;
$gadgetFired = false;

function build_example_gadget_payload() {
    $g = new DemoGadget();
    $g->message = 'this ran because you unserialized attacker-controlled data';
    return serialize($g);
}

$examplePayloadCustom = build_example_gadget_payload();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $data !== '') {
    if ($mode === 'vulnerable') {
        // VULNERABLE ON PURPOSE: unserialize() on raw user input. PHP
        // 5 has no way to restrict which classes this can instantiate
        // - unserialize()'s $options / allowed_classes parameter was
        // only added in PHP 7.0. Any magic method (__wakeup,
        // __destruct, __toString, ...) on any class the app has
        // loaded fires as a side effect, with no call site in sight.
        $before = @filesize(LOGS_PATH . DIRECTORY_SEPARATOR . 'deserialize_demo.log');
        $obj = @unserialize($data);
        $after = @filesize(LOGS_PATH . DIRECTORY_SEPARATOR . 'deserialize_demo.log');
        $gadgetFired = ($obj instanceof DemoGadget) && $after > (int) $before;
        $result = $obj === false && $data !== serialize(false)
            ? 'unserialize() returned false - not valid serialized data.'
            : 'unserialize() succeeded. Result type: ' . gettype($obj) . ($obj instanceof DemoGadget ? ' (DemoGadget instance - __wakeup already ran as a side effect of the line above, not because anything called it)' : '');
        audit_log_event('deserialize_demo_vulnerable', current_user_id(), 'gadget_fired=' . ($gadgetFired ? '1' : '0'));
    } else {
        // PATCHED: never call unserialize() on external input at all.
        // Accept JSON instead - json_decode() can only ever produce
        // plain scalars/arrays, never an object with executable magic
        // methods.
        $decoded = json_decode($data, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $result = 'Rejected: not valid JSON (' . json_last_error_msg() . '). No object was ever instantiated.';
        } else {
            $result = 'Safely decoded as: ' . var_export($decoded, true);
        }
        audit_log_event('deserialize_demo_patched', current_user_id(), '');
    }
}

$logTail = '';
$logPath = LOGS_PATH . DIRECTORY_SEPARATOR . 'deserialize_demo.log';
if (is_file($logPath)) {
    $lines = file($logPath);
    $logTail = implode('', array_slice($lines, -5));
}

render_header('Insecure deserialization playground');
?>
<h1>Insecure deserialization playground</h1>
<p class="lead">PHP's <code>unserialize()</code> can instantiate arbitrary classes from attacker-controlled data and will call their magic methods (<code>__wakeup</code>, <code>__destruct</code>, ...) automatically. PHP 7.0 added an <code>allowed_classes</code> option to restrict this - <strong>PHP 5 has no such option</strong>, so on PHP 5 the only real fix is to never call <code>unserialize()</code> on external input at all (use <code>json_decode()</code> instead). This app already has a <code>DemoGadget</code> class loaded (<code>app/demo_gadget.php</code>) whose <code>__wakeup()</code> writes a contained log line - standing in for a real "gadget chain".</p>

<div class="card">
  <p><small class="hint">Example vulnerable payload (paste into the vulnerable textarea):</small></p>
  <code class="mono" style="display:block;word-break:break-all"><?php echo e($examplePayloadCustom); ?></code>
</div>

<div class="card" style="max-width:600px">
  <form method="post" action="<?php echo e(base_url('deserialize-playground')); ?>">
    <?php echo csrf_field(); ?>
    <label for="data">Data to decode</label>
    <textarea id="data" name="data"><?php echo e($data); ?></textarea>
    <label style="display:flex;align-items:center;gap:8px;margin-top:10px">
      <input type="radio" name="mode" value="patched" <?php echo $mode === 'patched' ? 'checked' : ''; ?> style="width:auto"> Patched (json_decode)
    </label>
    <label style="display:flex;align-items:center;gap:8px">
      <input type="radio" name="mode" value="vulnerable" <?php echo $mode === 'vulnerable' ? 'checked' : ''; ?> style="width:auto"> Vulnerable (unserialize)
    </label>
    <button type="submit">Decode</button>
  </form>
</div>

<?php if ($result !== null) : ?>
  <div class="card">
    <?php if ($gadgetFired) : ?>
      <div class="flash flash-error">Gadget fired: DemoGadget::__wakeup() executed, purely as a side effect of unserialize(). See the log below.</div>
    <?php endif; ?>
    <p><small class="hint">Result:</small></p>
    <code class="mono" style="display:block;white-space:pre-wrap;word-break:break-all"><?php echo e($result); ?></code>
  </div>
<?php endif; ?>

<?php if ($logTail) : ?>
  <div class="card">
    <p><small class="hint">Contained gadget log (storage/logs/deserialize_demo.log, last 5 lines):</small></p>
    <code class="mono" style="display:block;white-space:pre-wrap"><?php echo e($logTail); ?></code>
  </div>
<?php endif; ?>

<?php render_footer(); ?>
