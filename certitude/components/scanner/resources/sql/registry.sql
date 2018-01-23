--Table creation
CREATE TABLE registry
(
	rid INT PRIMARY KEY NOT NULL,	-- Registry UID
	KeyPath VARCHAR(255),			-- Registry KeyPath (e.g: HKCU\...\...)
	ValueName TEXT					-- Registry ValueName (e.g: ShellExtRunOnce)
);

.separator '	'
.import registry.list registry