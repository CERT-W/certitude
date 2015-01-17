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

### Utilisation

Après avoir clôné le dépôt :
$ python.bat
$ python web.py

Ouvrir un navigateur sur http://127.0.0.1:5000/

Login / mot de passe à modifier dans le fichier web.py :
app.config.update(dict(
	USERNAME='seeker',
	PASSWORD='certitude'))


###

--
CERT-Solucom
cert@solucom.fr
