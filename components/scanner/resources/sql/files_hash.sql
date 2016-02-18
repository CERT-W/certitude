-- Table creation
-- 'FilePath', 'Md5sum', 'Sha1sum', 'Sha256sum'
CREATE TABLE files_hash
(
	FilePath TEXT,					-- File full path
	Md5Sum VARCHAR(32),					-- File MD5
	Sha1Sum VARCHAR(40),					-- File SHA-1
	Sha256Sum Varchar(64)					-- File SHA-256
);

.separator '	'
.import files_hash.list files_hash