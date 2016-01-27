-- Table creation
CREATE TABLE files
(
	FilePath TEXT,					-- File full path
	Md5sum VARCHAR(255),
	'StringList/string' TEXT
);

.separator '|'
.import files.list files

ALTER TABLE files ADD COLUMN FullPath TEXT;
ALTER TABLE files ADD COLUMN FileExtension VARCHAR(255);		-- File extension
ALTER TABLE files ADD COLUMN FileName VARCHAR(255);			-- File name

-- Load string functions extension
SELECT 1 WHERE load_extension('strings.so') is not null;

UPDATE files SET FullPath = FilePath;
UPDATE files SET FileName = LTRIM(RTRIM(REVERSE(SUBSTR(REVERSE(FullPath),0,CHARINDEX('\', REVERSE(FullPath),0)))));
UPDATE files SET FileExtension = LTRIM(RTRIM(REVERSE(SUBSTR(REVERSE(FullPath),0,CHARINDEX('.', REVERSE(FullPath),0)))));