<?php
// Item 13: a stand-in "gadget" class for the insecure-deserialization
// demo. In a real PHP object-injection exploit, the attacker doesn't
// need to define new code - they craft serialized data matching a
// class the vulnerable app already has loaded (a "gadget chain").
// This class simply models that: some class, already present in the
// app, with a magic method that runs as a side effect of
// unserialize() itself - no explicit call needed. Its side effect is
// deliberately benign and fully contained (a log line), matching this
// project's convention of never letting a "vulnerable" demo actually
// do anything dangerous on this real machine.

class DemoGadget {
    public $message = 'default';

    public function __wakeup() {
        $line = date('Y-m-d H:i:s') . ' - DemoGadget::__wakeup() executed via unserialize(). message=' . $this->message . "\n";
        @file_put_contents(LOGS_PATH . DIRECTORY_SEPARATOR . 'deserialize_demo.log', $line, FILE_APPEND);
    }
}
