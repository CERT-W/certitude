DELETE FROM iocdetections;
DELETE FROM yaradetections;
DELETE FROM resultats;
UPDATE queue SET iocscanned=0, hashscanned=0, yarascanned=0, priority_ioc=10, priority_hash=10, priority_yara=10, reserved_ioc=0, reserved_hash=0, reserved_yara=0, retries_left_ioc=10, retries_left_hash=10, retries_left_yara=10, last_retry_ioc=NULL, last_retry_hash=NULL, last_retry_yara=NULL;