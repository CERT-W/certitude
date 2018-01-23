--Table creation
CREATE TABLE dns
(
	did INT PRIMARY KEY NOT NULL,
	`RecordName` VARCHAR(255),
	`RecordType` INT,
	`TimeToLive` INT,
	`DataLength` INT,
	`RecordData/Host` VARCHAR(255),
	`RecordData/IPv4Address` VARCHAR(255)
);

.separator '	'
.import dns.list dns