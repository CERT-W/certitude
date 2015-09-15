-- Table creation
CREATE TABLE services
(
	sid INT PRIMARY KEY NOT NULL, 	-- Service UID
	descriptive_name VARCHAR(255), 	-- Service descriptive name
	mode TINYINT,					-- Service start type
	path TEXT,						-- Service binary path
	pathmd5sum VARCHAR(32),			-- MD5 checksum of associated binary
	status TINYINT,					-- Service current status
	name VARCHAR(255)				-- Service short name
);

.separator '	'
.import services.list services