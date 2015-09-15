--Table creation
CREATE TABLE port
(
	portid INT PRIMARY KEY NOT NULL,
	`Protocol` VARCHAR(3),
	`LocalIP` VARCHAR(255),
	`LocalPort` INT,
	`RemoteIP` VARCHAR(255),
	`RemotePort` INT,
	`State` VARCHAR(255),
	`PID` INT
);

.separator '	'
.import port.list port