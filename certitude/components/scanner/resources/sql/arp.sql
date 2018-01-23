--Table creation
CREATE TABLE arp
(
	aid INT PRIMARY KEY NOT NULL,
	`Interface` VARCHAR(15),
	IPv4Address VARCHAR(15),
	PhysicalAddress VARCHAR(17),
	CacheType VARCHAR(7)
);

.separator '	'
.import arp.list arp