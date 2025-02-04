<?php

class AuditTrail
{
    private $actions = [];

    public function logAction($action)
    {
        $timestamp = date('Y-m-d H:i:s');
        $this->actions[] = ['action' => $action, 'timestamp' => $timestamp];
    }

    public function log($data)
    {
        $timestamp = date('Y-m-d H:i:s');
        $data['timestamp'] = $timestamp;
        $this->actions[] = $data;
    }

    public function getActions()
    {
        return $this->actions;
    }

    public function printActions()
    {
        foreach ($this->actions as $entry) {
            echo $entry['timestamp'] . ' - ' . $entry['action_type'] . ' - ' . $entry['entity_type'] . ' - ' . $entry['entity_id'] . ' - ' . json_encode($entry['additional_info']) . PHP_EOL;
        }
    }
}

class RFIDAuditTrail extends AuditTrail
{
    private $actions = [];
    public function logRFIDAction($rfid, $action)
    {
        $timestamp = date('Y-m-d H:i:s');
        $this->actions[] = ['rfid' => $rfid, 'action' => $action, 'timestamp' => $timestamp];
    }

    public function getRFIDActions()
    {
        return $this->actions;
    }

    public function printRFIDActions()
    {
        foreach ($this->actions as $entry) {
            echo $entry['timestamp'] . ' - RFID: ' . $entry['rfid'] . ' - ' . $entry['action'] . PHP_EOL;
        }
    }
}
?>