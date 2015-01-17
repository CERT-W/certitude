CERTitude
==============
Remote Python IOC scanner for Windows targets


### Ajouter un module

1. Créer le script d'extraction et le placer dans `ressources/`. Celui-ci doit respecter les conditions suivantes :
	- Être écrit en Batch ou Bash.
	- Restituer les données extraites dans un fichier TSV (Tab Separated Value).
2. Créer le fichier .sql associé réalisant l'importation
3. Créer le contrôleur associé dans les répertoires `flatevaluators/` et/ou `logicevaluators`.
4. Lier le contrôleur à CERTitude dans le fichier `targethandler.py` (evaluator list, drop list...)

### Modules existants

- RegistryItem
	- KeyPath
	- ValueName	
- FileItem
	- FilePath
	- FullPath
	- FileName
	- FileExtension	
- Services
	- name
	- descriptiveName
	- path
	- pathMD5Sum
	- status (i.e running / stopped)
	- mode (ie auto / on demand / delayed …)	
- ArpEntryItem
	- IPv4
	- PhysicalAddress
	- Interface
	- CacheType (static|dynamic)
	
### TODO

#### Probabilité ++

- DnsEntryItem
	- Host
	- record_name / record_type
	- TTL
	- Data_Length
	- section
	- A_record
	- Cname
- PortItem (connexion réseaux)
	- Local IP : Port
	- Remote IP : Port
	- State
	- Process
	- Protocol	
- PrefetchItem (si on y arrive) :
	- ApplicationFilename / FullPath
	- Hash
	- TimesExecuted	
- ProcessItem
	- Name
	- Path + MD5SUM + Strings
	- PPID
	- DLL Importées + peut-être un peu d’infos sur le PE si on trouve
	- User	
- RouteEntryItem
	- Pour l’IPv4 : Destination réseau    Masque réseau  Adr. passerelle   Adr. interface Métrique


#### Probabilité -

- EventLog ==> pas sûr du tout, il faut passer par WMIC, et que ça plante avec CERTitude
- Peut être des infos sur les UserItem

(c) Jean MARSAULT @ Solucom 2014
