--Table creation
CREATE TABLE memory
(
	mid INT PRIMARY KEY NOT NULL,
	`pid` INT,
	`parentpid` INT,
	`name` VARCHAR(384),
	`page_addr` VARCHAR(16),
	`page_size` VARCHAR(16),
	`access_read` TINYINT,
	`access_write` TINYINT,
	`access_execute` TINYINT,
	`access_copy_on_write` TINYINT
);

.separator '	'
.import memory.list memory
