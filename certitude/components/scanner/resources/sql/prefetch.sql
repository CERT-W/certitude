--Table creation
CREATE TABLE prefetch
(
	pid INT PRIMARY KEY NOT NULL,
	`PrefetchHash` VARCHAR(100),
	`ApplicationFileName` VARCHAR(255),
	`ReportedSizeInBytes` INT,
	`SizeInBytes` INT,
	`TimesExecuted` INT,
	`FullPath` VARCHAR(512)
);

.separator '	'
.import prefetch.list prefetch