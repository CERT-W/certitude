-- Table creation
CREATE TABLE files
(
	fid INT PRIMARY KEY NOT NULL ,	-- File UID
	FilePath TEXT,					-- File full path
	FullPath TEXT,
	FileExtension VARCHAR(255),		-- File extension
	FileName VARCHAR(255)			-- File name
);

.separator '	'
.import files.list files

-- Load string functions extension
SELECT 1 WHERE load_extension('strings.so') is not null;

UPDATE files SET FullPath = FilePath;
UPDATE files SET FileName = LTRIM(RTRIM(REVERSE(SUBSTR(REVERSE(FilePath),0,CHARINDEX('\', REVERSE(FilePath),0)))));
UPDATE files SET FileExtension = LTRIM(RTRIM(REVERSE(SUBSTR(REVERSE(FilePath),0,CHARINDEX('.', REVERSE(FileName),0)))));