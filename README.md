# Harbor Jev Exceptions

## Français

Ce service évalue **la qualité d'une demande d'exception** pour une image Harbor, jamais la sûreté de l'image. La décision Jev est `supported`, `weak` ou `review` ; un humain décide ensuite. Le service ne modifie aucune liste d'exceptions CVE et n'autorise aucun déploiement. SQLite garde l'empreinte du dossier et la décision, pas la justification libre. Les tentatives identiques sont dédupliquées.

Configurez le webhook Harbor `SCANNING_COMPLETED` avec `Authorization: Bearer <HARBOR_WEBHOOK_TOKEN>` vers `POST /scan`. Le service vérifie le digest SHA-256 et le statut du scan, puis conserve seulement le dépôt, le digest, la sévérité et le nombre de vulnérabilités. Un humain lit `GET /scans`, puis envoie `POST /review` avec `{"scan_id":"scan:...","exception":{"workload":"...","justification":"...","mitigations":["..."]}}`. `POST /decide` accepte également un dossier combiné `{"scan":<événement Harbor>,"exception":{...}}`. Harbor décrit le [format du webhook et les nouvelles tentatives](https://goharbor.io/docs/edge/working-with-projects/project-configuration/configure-webhooks/). Exposez le service derrière TLS et un contrôle d'accès adaptés à votre réseau.

Installez `python3 -m pip install -r requirements.txt`, définissez en privé `TYPESAFE_API_KEY`, `HARBOR_WEBHOOK_TOKEN` et `JEV_REVIEW_TOKEN` (jetons d'au moins 16 caractères), puis lancez `python3 app.py --serve`. Le service écoute sur `127.0.0.1:8098`. Le jeton webhook protège `POST /scan` ; le jeton de revue protège `GET /scans`, `POST /review`, `POST /decide` et `GET /decisions`. Démo : `python3 app.py --demo`. Tests : `python3 -m unittest discover -s tests -v`. L'API Jev est testée avec des données synthétiques ; aucune instance Harbor réelle n'a été connectée.

## English

This service assesses **the quality of an exception request** for a Harbor image, never whether the image is safe. Jev returns `supported`, `weak`, or `review`; a human decides next. It changes no CVE allowlist and authorizes no deployment. SQLite keeps a dossier digest and decision, not the free-text justification. Identical submissions are deduplicated.

Configure Harbor's `SCANNING_COMPLETED` webhook with `Authorization: Bearer <HARBOR_WEBHOOK_TOKEN>` pointing to `POST /scan`. The service validates the SHA-256 digest and scan status, then keeps only the repository, digest, severity, and vulnerability count. A person reads `GET /scans`, then sends `POST /review` with `{"scan_id":"scan:...","exception":{"workload":"...","justification":"...","mitigations":["..."]}}`. `POST /decide` also accepts a combined `{"scan":<Harbor event>,"exception":{...}}` dossier. Harbor documents the [webhook format and delivery retries](https://goharbor.io/docs/edge/working-with-projects/project-configuration/configure-webhooks/). Expose this service behind suitable TLS and network access controls.

Install with `python3 -m pip install -r requirements.txt`, set private `TYPESAFE_API_KEY`, `HARBOR_WEBHOOK_TOKEN`, and `JEV_REVIEW_TOKEN` (tokens at least 16 characters long), then run `python3 app.py --serve`. The service binds to `127.0.0.1:8098`. The webhook token protects `POST /scan`; the review token protects `GET /scans`, `POST /review`, `POST /decide`, and `GET /decisions`. Demo: `python3 app.py --demo`. Tests: `python3 -m unittest discover -s tests -v`. The Jev API was tested with synthetic input; no live Harbor instance was connected.

## Español

Este servicio evalúa **la calidad de una solicitud de excepción** para una imagen Harbor, nunca si la imagen es segura. Jev devuelve `supported`, `weak` o `review`; después decide una persona. No modifica listas de excepciones CVE ni autoriza despliegues. SQLite conserva una huella del expediente y la decisión, pero no la justificación libre. Las solicitudes idénticas se deduplican.

Configure el webhook `SCANNING_COMPLETED` de Harbor con `Authorization: Bearer <HARBOR_WEBHOOK_TOKEN>` hacia `POST /scan`. El servicio verifica el digest SHA-256 y el estado del análisis; conserva solo el repositorio, el digest, la gravedad y el número de vulnerabilidades. Una persona consulta `GET /scans` y envía `POST /review` con `{"scan_id":"scan:...","exception":{"workload":"...","justification":"...","mitigations":["..."]}}`. `POST /decide` también acepta un expediente combinado `{"scan":<evento Harbor>,"exception":{...}}`. Harbor documenta el [formato del webhook y los reintentos](https://goharbor.io/docs/edge/working-with-projects/project-configuration/configure-webhooks/). Exponga el servicio detrás de TLS y controles de acceso de red adecuados.

Instale con `python3 -m pip install -r requirements.txt`, defina en privado `TYPESAFE_API_KEY`, `HARBOR_WEBHOOK_TOKEN` y `JEV_REVIEW_TOKEN` (tokens de al menos 16 caracteres), y ejecute `python3 app.py --serve`. El servidor escucha en `127.0.0.1:8098`. El token del webhook protege `POST /scan`; el token de revisión protege `GET /scans`, `POST /review`, `POST /decide` y `GET /decisions`. Demostración: `python3 app.py --demo`. Pruebas: `python3 -m unittest discover -s tests -v`. La API Jev se probó con datos sintéticos; no se conectó una instancia Harbor real.

MIT. Tag: `v0.1.0`.
