<?php
declare(strict_types=1);

/**
 * Script Name:       Outil de Vérification E-mail & Sécurité DNS
 * Script URI:        https://thierrylaval.dev
 * Description:       Audit complet et autonome de la configuration e-mail, de la délivrabilité et de la sécurité DNS d'un nom de domaine (MX, SPF, DKIM, DMARC, RBL, DNSSEC, BIMI, DANE, MTA-STS, TLS-RPT).
 * Version:           1.0.0
 * Author:            Thierry Laval
 * Author URI:        https://thierrylaval.dev
 * License:           Academic Free License 3.0 (AFL-3.0)
 * License URI:       https://opensource.org/licenses/AFL-3.0
 *
 * ============================================================================
 * ANALYSEUR COMPLET ET AUTONOME DE SÉCURITÉ EMAIL
 * MX · SPF · DKIM · DMARC · RBL · DNSSEC · BIMI · DANE · MTA-STS · TLS-RPT
 * ============================================================================
 *
 * Fichier unique autonome (Moteur PHP + Interface Web).
 * À déposer à la racine de votre hébergement web (ex: https://monsite.com/verifier-spf-dkim-dmarc.php).
 *
 * Aucune dépendance externe - Aucun Composer - Aucune base de données.
 * Compatible hébergement PHP classique 7.4+ et PHP 8.x (testé jusqu'à PHP 8.5+).
 *
 * Fonctionnalités couvertes (10 contrôles complets) :
 * - MX & Reverse DNS (PTR) + FCrDNS + CNAME racine (RFC 1034) + détection 17 messageries
 * - SPF récursif RFC 7208 (arbre d’inclusions, limite 10 requêtes DNS, void lookups, +all, ptr)
 * - DKIM (18 sélecteurs testés automatiquement, taille de clé RSA 1024 vs 2048+ bits, révocation)
 * - DMARC complet (tags, héritage, vérification des rapports externes RFC 7489)
 * - Listes Noires Anti-Spam RBL (Spamcop, Barracuda, PSBL, UCEPROTECT)
 * - DNSSEC (détection des enregistrements DS via DoH)
 * - BIMI (logo SVG Tiny P.S., certificat VMC, compatibilité DMARC)
 * - DANE / TLSA (port 25)
 * - MTA-STS (DNS + validation du fichier HTTPS .well-known/mta-sts.txt)
 * - TLS-RPT (DNS + balise rua=)
 * - Score de sécurité email sur 100 points
 * - Export PDF isolé et autonome (aucun élément parasite)
 * - Lancement automatique via paramètres URL (?domain=...)
 */

if (session_status() === PHP_SESSION_NONE) {
    if (!headers_sent()) {
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
                   (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443) ||
                   (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
        @session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $isHttps,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }
    @session_start();
}

if (empty($_SESSION['dmc_csrf_token'])) {
    try {
        $_SESSION['dmc_csrf_token'] = bin2hex(random_bytes(32));
    } catch (\Throwable $e) {
        $_SESSION['dmc_csrf_token'] = md5(uniqid((string)mt_rand(), true));
    }
}
$csrfToken = (string)$_SESSION['dmc_csrf_token'];

const MAX_SPF_DNS_LOOKUPS = 10;
const HTTP_TIMEOUT = 5;
const DEFAULT_DKIM_SELECTORS = [
    'default', 'mail', 'email', 'dkim',
    'selector1', 'selector2', 'google',
    'k1', 'k2', 's1', 's2', 'smtp',
    'mailjet', 'sparkpost', 'sendgrid',
    'mg', 'mandrill', 'pm'
];

/**
 * Nettoyage et assainissement d’un nom de domaine.
 */
function sanitizeDomain(string $input): string
{
    $domain = strtolower(trim($input));
    if ($domain === '') {
        return '';
    }
    if (strpos($domain, '@') !== false) {
        $parts = explode('@', $domain);
        $domain = end($parts);
    }
    $domain = preg_replace('#^https?://#i', '', $domain);
    $domain = preg_replace('#/.*$#', '', $domain);
    $domain = preg_replace('#:\d+$#', '', $domain);
    $domain = trim($domain, " \t\n\r\0\x0B.");

    if (function_exists('idn_to_ascii')) {
        $idn = @idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($idn !== false && $idn !== '') {
            $domain = $idn;
        }
    }
    return $domain;
}

/**
 * Nettoyage et assainissement du sélecteur DKIM.
 */
function sanitizeSelector(string $input): string
{
    $selector = trim($input);
    return preg_replace('/[^a-zA-Z0-9._-]/', '', $selector);
}

function dnsRecords(string $host, int $type): array
{
    $records = @dns_get_record($host, $type);
    return is_array($records) ? $records : [];
}

/**
 * Retourne tous les enregistrements TXT d'un hôte sous forme de chaînes simples.
 *
 * Les enregistrements TXT DNS peuvent être fragmentés en plusieurs "chunks" (morceaux)
 * de 255 caractères max par la norme DNS. PHP retourne ces morceaux dans le tableau
 * 'entries'. Cette fonction les concatène pour obtenir la valeur TXT complète.
 * Elle gère aussi l'ancien format où la valeur est directement dans 'txt'.
 *
 * @param string $host Hôte à interroger.
 * @return array       Tableau de chaînes TXT (une entrée par enregistrement TXT).
 */
function txtRecords(string $host): array
{
    $records = dnsRecords($host, DNS_TXT);
    $result  = [];

    foreach ($records as $record) {
        $txt = '';
        if (isset($record['entries']) && is_array($record['entries'])) {
            // Concatène les morceaux de 255 caractères en une seule chaîne.
            $txt = implode('', $record['entries']);
        } elseif (isset($record['txt'])) {
            $txt = (string)$record['txt'];
        }
        $txt = trim($txt);
        if ($txt !== '') {
            $result[] = $txt;
        }
    }

    return $result;
}

/**
 * Retourne les enregistrements MX d'un domaine, triés par priorité croissante.
 *
 * En DNS MX, une priorité plus faible signifie une préférence plus haute.
 * Le serveur MX avec priorité 10 est essayé avant celui avec priorité 20.
 * Le tri est important pour l'affichage et pour la détection du fournisseur.
 *
 * @param string $domain Domaine à interroger.
 * @return array         Tableau d'enregistrements MX triés par priorité.
 */
function mxRecords(string $domain): array
{
    $records = dnsRecords($domain, DNS_MX);

    usort(
        $records,
        static function ($a, $b) {
            return ((int)($a['pri'] ?? 0))
                <=> ((int)($b['pri'] ?? 0));
        }
    );

    return $records;
}

/**
 * Retourne toutes les adresses IP (IPv4 + IPv6) associées à un hôte.
 *
 * Interroge séparément les enregistrements A (IPv4) et AAAA (IPv6).
 * La constante DNS_AAAA n'est pas disponible sur toutes les versions de PHP,
 * d'où la vérification avec defined('DNS_AAAA').
 * Les doublons sont supprimés et les indices réindexés.
 *
 * @param string $host Nom d'hôte à résoudre (ex: "mx1.ovh.net").
 * @return array       Tableau d'adresses IP uniques.
 */
function hostIPs(string $host): array
{
    $ips = [];

    foreach (dnsRecords($host, DNS_A) as $record) {
        if (!empty($record['ip'])) {
            $ips[] = $record['ip'];
        }
    }

    if (defined('DNS_AAAA')) {
        foreach (dnsRecords($host, DNS_AAAA) as $record) {
            if (!empty($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }
    }

    return array_values(array_unique($ips));
}

/**
 * Retourne le nom d'hôte associé à une adresse IP via le DNS inverse (Reverse DNS / PTR).
 *
 * Le Reverse DNS (PTR) permet de vérifier qu'une IP "se présente" bien avec un nom.
 * C'est une mesure anti-spam basique : un serveur sans PTR est souvent rejeté ou
 * mis en spam par les grandes messageries.
 *
 * gethostbyaddr() est utilisé à la place de dns_get_record(DNS_PTR) car il gère
 * automatiquement l'inversion de l'IP (ex: 1.2.3.4 → 4.3.2.1.in-addr.arpa).
 *
 * @param string $ip Adresse IP à résoudre (IPv4 ou IPv6).
 * @return string    Nom d'hôte trouvé, ou chaîne vide si absent/identique à l'IP.
 */
function ptrRecord(string $ip): string
{
    $ptr = @gethostbyaddr($ip);

    // gethostbyaddr() retourne l'IP elle-même si aucun PTR n'est trouvé.
    if (!$ptr || $ptr === $ip) {
        return '';
    }

    return $ptr;
}


/**
 * Retourne tous les enregistrements TXT commençant par "v=spf1" pour un domaine.
 *
 * Un domaine valide ne doit avoir QU'UN SEUL enregistrement SPF (RFC 7208 §3.2).
 * Cette fonction retourne un tableau — si ce tableau contient plus d'un élément,
 * c'est une erreur de configuration (PermError garanti chez les récepteurs).
 *
 * @param string $domain Domaine à interroger.
 * @return array         Tableau des enregistrements SPF trouvés (idéalement 1 seul).
 */
function getSpfRecords(string $domain): array
{
    $result = [];

    foreach (txtRecords($domain) as $txt) {
        if (preg_match('/^v=spf1(?:\s|$)/i', trim($txt))) {
            $result[] = trim($txt);
        }
    }

    return $result;
}

/**
 * Analyse récursive d'un enregistrement SPF selon la RFC 7208.
 *
 * SPF peut contenir des directives "include:" qui pointent vers d'autres SPF,
 * eux-mêmes pouvant contenir d'autres "include:", formant une arborescence.
 * Chaque mécanisme qui génère une requête DNS (a, mx, include:, exists:, ptr)
 * incrémente le compteur $lookups. La RFC 7208 impose une limite stricte de 10.
 *
 * Cette fonction est appelée récursivement sur chaque "include:" rencontré.
 * Elle détecte les boucles d'inclusion et la profondeur excessive (>10 niveaux).
 *
 * Paramètres passés par référence pour accumuler les données sur toute l'arborescence :
 *   &$lookups     : compteur total de requêtes DNS (partagé sur toute la récursion)
 *   &$voidLookups : compteur de requêtes DNS qui n'ont rien retourné (void lookups)
 *   &$visited     : tableau des domaines déjà visités (anti-boucle)
 *   &$tree        : arbre des inclusions pour l'affichage dans l'interface
 *   &$errors      : erreurs bloquantes accumulées
 *   &$warnings    : avertissements non bloquants accumulés
 *
 * @param string $currentDomain Domaine dont on analyse le SPF (pour les messages d'erreur).
 * @param string $record        L'enregistrement SPF brut à analyser (ex: "v=spf1 include:x ~all").
 * @param int    $lookups       Compteur de lookups DNS (passé par référence).
 * @param int    $voidLookups   Compteur de lookups vides (passé par référence).
 * @param array  $visited       Domaines déjà analysés pour détecter les boucles (passé par référence).
 * @param array  $tree          Arbre des inclusions pour visualisation (passé par référence).
 * @param array  $errors        Erreurs bloquantes accumulées (passé par référence).
 * @param array  $warnings      Avertissements non bloquants (passé par référence).
 * @param int    $depth         Profondeur de récursion actuelle (0 = niveau racine).
 * @return array                Mécanismes analysés, directive "all" et "redirect".
 */
function parseSpfRecursive(
    string $currentDomain,
    string $record,
    int &$lookups,
    int &$voidLookups,
    array &$visited,
    array &$tree,
    array &$errors,
    array &$warnings,
    int $depth = 0
): array {
    $parts = preg_split('/\s+/', trim($record));

    $mechanisms = [];
    $all        = null;
    $redirect   = null;

    // Vérifie que l'enregistrement commence bien par "v=spf1".
    if (!$parts || strtolower($parts[0]) !== 'v=spf1') {
        $errors[] = "Le SPF de '$currentDomain' ne commence pas par v=spf1.";
        return [
            'mechanisms' => [],
            'all'        => null,
            'redirect'   => null
        ];
    }

    // Analyse chaque mécanisme SPF (on saute le premier élément "v=spf1").
    foreach (array_slice($parts ?: [], 1) as $part) {
        if ($part === '') {
            continue;
        }

        // Extraction du qualificateur : + (pass), - (fail), ~ (softfail), ? (neutral).
        // Par défaut (sans qualificateur) c'est + (pass).
        $qualifier = '+';
        if (in_array($part[0], ['+', '-', '~', '?'], true)) {
            $qualifier = $part[0];
            $part      = substr($part, 1);
        }

        $lower = strtolower($part);

        // Mécanisme "all" : s'applique à tous les expéditeurs non couverts par les règles précédentes.
        if ($lower === 'all') {
            $all          = $qualifier;
            $mechanisms[] = [
                'name'      => 'all',
                'value'     => '',
                'qualifier' => $qualifier,
                'lookups'   => 0
            ];
            continue;
        }

        // Mécanisme "redirect=" : délègue l'évaluation SPF à un autre domaine.
        // Compte comme 1 lookup DNS. Récurse dans le domaine cible.
        if (strpos($lower, 'redirect=') === 0) {
            $redirect = substr($part, 9);
            $lookups++;
            $mechanisms[] = [
                'name'      => 'redirect',
                'value'     => $redirect,
                'qualifier' => $qualifier,
                'lookups'   => 1
            ];

            $redLower = strtolower($redirect);
            if (isset($visited[$redLower])) {
                // Boucle infinie détectée : le redirect pointe vers un domaine déjà visité.
                $errors[] = "Boucle infinie détectée dans SPF via redirect=$redirect.";
            } elseif ($depth < 10) {
                $visited[$redLower] = true;
                $subRecords = getSpfRecords($redirect);
                if (!empty($subRecords)) {
                    parseSpfRecursive(
                        $redirect,
                        $subRecords[0],
                        $lookups,
                        $voidLookups,
                        $visited,
                        $tree,
                        $errors,
                        $warnings,
                        $depth + 1
                    );
                } else {
                    // La cible du redirect n'a pas de SPF valide : lookup "void".
                    $voidLookups++;
                    $warnings[] = "La redirection redirect=$redirect ne renvoie aucun enregistrement SPF valide.";
                }
            }
            continue;
        }

        $name  = $part;
        $value = '';

        // Séparation nom:valeur (ex: "include:spf.exemple.fr") ou nom=valeur (ex: "exists=%{d}").
        if (strpos($part, ':') !== false) {
            [$name, $value] = explode(':', $part, 2);
        } elseif (strpos($part, '=') !== false) {
            [$name, $value] = explode('=', $part, 2);
        }

        $name = strtolower($name);
        $cost = 0;

        // Ces mécanismes génèrent chacun une requête DNS → ils incrémentent le compteur.
        // ip4:, ip6:, all et exp ne génèrent pas de requête DNS (pas de coût).
        if (in_array($name, ['a', 'mx', 'include', 'exists', 'ptr'], true)) {
            $cost = 1;
            $lookups++;
        }

        // Le mécanisme "ptr" est explicitement déconseillé par la RFC 7208 §5.5
        // car il génère beaucoup de requêtes DNS et est lent.
        if ($name === 'ptr') {
            $warnings[] = 'Le mécanisme ptr est déconseillé dans SPF par la RFC 7208.';
        }

        // Détecte les mécanismes inconnus ou mal formés.
        if (!in_array($name, [
            'a', 'mx', 'ip4', 'ip6', 'include', 'exists', 'ptr', 'all', 'exp'
        ], true)) {
            $errors[] = 'Mécanisme SPF inconnu ou syntaxe invalide : ' . $name;
        }

        // Récursion sur les directives "include:" pour analyser l'arborescence complète.
        if ($name === 'include') {
            $incDomain = strtolower($value);
            $node      = [
                'parent'  => $currentDomain,
                'include' => $incDomain,
                'status'  => 'ok'
            ];

            if (isset($visited[$incDomain])) {
                // Ce domaine a déjà été inclus dans la chaîne → boucle d'inclusion.
                $errors[]       = "Boucle d'inclusion SPF détectée : $incDomain a déjà été exploré.";
                $node['status'] = 'loop';
            } elseif ($depth >= 10) {
                // RFC 7208 §4.6.4 : la profondeur d'imbrication ne doit pas dépasser 10.
                $errors[]       = "Profondeur maximale d'inclusion SPF dépassée (> 10 niveaux).";
                $node['status'] = 'max_depth';
            } else {
                $visited[$incDomain] = true;
                $incRecords          = getSpfRecords($incDomain);
                if (!empty($incRecords)) {
                    parseSpfRecursive(
                        $incDomain,
                        $incRecords[0],
                        $lookups,
                        $voidLookups,
                        $visited,
                        $tree,
                        $errors,
                        $warnings,
                        $depth + 1
                    );
                } else {
                    // L'include pointe vers un domaine sans enregistrement SPF valide.
                    $voidLookups++;
                    $warnings[]     = "L’include include:$incDomain n'a renvoyé aucun enregistrement SPF valide.";
                    $node['status'] = 'void';
                }
            }
            // Ajoute ce nœud à l'arbre des inclusions (pour visualisation dans l'interface).
            $tree[] = $node;
        }

        $mechanisms[] = [
            'name'      => $name,
            'value'     => $value,
            'qualifier' => $qualifier,
            'lookups'   => $cost
        ];
    }

    return [
        'mechanisms' => $mechanisms,
        'all'        => $all,
        'redirect'   => $redirect
    ];
}

/**
 * Vérifie la configuration SPF complète d'un domaine.
 *
 * Orchestration de l'analyse SPF :
 *   1. Récupère le ou les enregistrements SPF du domaine.
 *   2. Détecte les configurations invalides d'emblée (absent, multiples).
 *   3. Lance l'analyse récursive complète (parseSpfRecursive).
 *   4. Évalue les résultats : +all dangereux, ?all neutre, dépassement de lookups.
 *   5. Propose une correction DNS si +all est détecté.
 *
 * @param string $domain Domaine à analyser.
 * @return array         Résultat structuré avec status, message, record, details.
 */
function checkSpf(string $domain): array
{
    $records = getSpfRecords($domain);

    // Cas 1 : Aucun enregistrement SPF — les emails peuvent être usurpés librement.
    if (!$records) {
        return [
            'status'        => 'error',
            'title'         => 'SPF',
            'message'       => 'Aucun enregistrement SPF n’a été trouvé.',
            'record'        => '',
            'suggested_dns' => [
                'name'  => '@',
                'type'  => 'TXT',
                'value' => 'v=spf1 mx ~all',
                'note'  => 'Enregistrement SPF initial autorisant vos serveurs MX.'
            ],
            'details'       => [
                'lookups' => 0,
                'limit'   => MAX_SPF_DNS_LOOKUPS
            ]
        ];
    }

    // Cas 2 : Plusieurs enregistrements SPF — interdit par la RFC 7208 §3.2.
    // Les serveurs récepteurs renverront systématiquement PermError, rendant SPF inutile.
    if (count($records) > 1) {
        return [
            'status'        => 'error',
            'title'         => 'SPF',
            'message'       => 'Plusieurs enregistrements SPF ont été détectés. La norme RFC 7208 impose STRICTEMENT un seul SPF par domaine (PermError sinon).',
            'record'        => implode("\n", $records),
            'suggested_dns' => [
                'name'  => '@',
                'type'  => 'TXT',
                'value' => 'v=spf1 [fusionnez vos mécanismes ici] ~all',
                'note'  => 'Regroupez tous vos ip4 et includes dans une seule ligne TXT unique.'
            ],
            'details'       => [
                'records' => $records
            ]
        ];
    }

    // Initialisation des compteurs et accumulateurs pour l'analyse récursive.
    $lookups     = 0;
    $voidLookups = 0;
    $visited     = [strtolower($domain) => true]; // Le domaine racine est marqué comme visité.
    $tree        = [];
    $errors      = [];
    $warnings    = [];

    // Lancement de l'analyse récursive sur l'enregistrement SPF unique.
    $parsed = parseSpfRecursive(
        $domain,
        $records[0],
        $lookups,
        $voidLookups,
        $visited,
        $tree,
        $errors,
        $warnings,
        0
    );

    $all      = $parsed['all'];
    $redirect = $parsed['redirect'];

    // Un SPF sans "all" ni "redirect" à la fin est ambiguë et déconseillé.
    if ($all === null && $redirect === null) {
        $warnings[] = 'Aucun mécanisme all ou redirect n’a été trouvé en fin d’enregistrement.';
    }

    // "+all" autorise TOUT le monde à envoyer des emails pour le domaine → danger critique.
    if ($all === '+') {
        $errors[] = 'Le SPF contient +all et autorise n’importe quel serveur dans le monde à envoyer des emails pour votre domaine !';
    } elseif ($all === '?') {
        // "?all" (neutre) n'offre aucune protection active contre l'usurpation d'identité.
        $warnings[] = 'Le SPF utilise ?all (Neutre) : cela n\'offre aucune protection active contre l\'usurpation.';
    }

    // RFC 7208 §4.6.4 : limite de 10 lookups DNS. Au-delà → PermError.
    if ($lookups > MAX_SPF_DNS_LOOKUPS) {
        $errors[] = "Dépassement de la limite RFC 7208 : $lookups recherches DNS requises (limite maximale : 10). Vos emails risquent d'être rejetés en PermError.";
    } elseif ($lookups >= 8) {
        // Alerte préventive : proche de la limite, un include supplémentaire peut tout casser.
        $warnings[] = "Attention : $lookups recherches DNS utilisées sur un maximum de 10. Votre SPF approche du quota maximum.";
    }

    // Trop de lookups vides peut indiquer des includes pointant vers des domaines inexistants.
    if ($voidLookups > 2) {
        $warnings[] = "Nombre de requêtes DNS vides élevé ($voidLookups).";
    }

    $status = 'ok';
    if ($errors) {
        $status = 'error';
    } elseif ($warnings) {
        $status = 'warning';
    }

    // Si +all est détecté, on propose directement le correctif : remplacer par ~all (SoftFail).
    $suggestedDns = null;
    if ($all === '+') {
        $suggestedDns = [
            'name'  => '@',
            'type'  => 'TXT',
            'value' => preg_replace('/\+all/', '~all', $records[0]),
            'note'  => 'Remplacement du +all par ~all pour bloquer les usurpateurs.'
        ];
    }

    return [
        'status'        => $status,
        'title'         => 'SPF',
        'message'       => $errors
            ? implode(' ', $errors)
            : ($warnings ? implode(' ', $warnings) : "Configuration SPF valide ($lookups/10 recherches DNS utilisées)."),
        'record'        => $records[0],
        'suggested_dns' => $suggestedDns,
        'details'       => [
            'lookups'       => $lookups,
            'limit'         => MAX_SPF_DNS_LOOKUPS,
            'void_lookups'  => $voidLookups,
            'mechanisms'    => $parsed['mechanisms'],
            'includes_tree' => $tree,
            'all'           => $all,
            'redirect'      => $redirect,
            'errors'        => $errors,
            'warnings'      => $warnings
        ]
    ];
}


/**
 * Analyse les tags d'un enregistrement DKIM brut et estime la taille de la clé RSA.
 *
 * Un enregistrement DKIM est une liste de paires clé=valeur séparées par des points-virgules.
 * Tags importants :
 *   - v= : version (doit être DKIM1)
 *   - k= : type de clé (rsa par défaut, ed25519 pour les clés modernes)
 *   - p= : clé publique encodée en Base64 (vide = clé révoquée)
 *
 * Estimation de la taille de clé RSA par décodage Base64 de p= :
 *   La taille en octets de la clé décodée permet d'estimer les bits :
 *   - ≤ 170 octets → ~1024 bits (déprécié, recommandé de migrer vers 2048)
 *   - ≤ 320 octets → ~2048 bits (standard actuel recommandé)
 *   - > 320 octets → ~4096 bits (haute sécurité)
 *   Note : c'est une estimation basée sur la taille, pas un décodage ASN.1 complet.
 *
 * @param string $record Enregistrement DKIM brut (ex: "v=DKIM1; k=rsa; p=MIGfMA0…").
 * @return array         Tags analysés, type et taille de clé, erreurs et avertissements.
 */
function parseDkim(string $record): array
{
    $tags = [];

    // Découpe en paires clé=valeur séparées par des points-virgules.
    foreach (explode(';', $record) as $part) {
        $part = trim($part);
        if ($part === '' || strpos($part, '=') === false) {
            continue;
        }
        [$key, $value]              = explode('=', $part, 2);
        $tags[strtolower(trim($key))] = trim($value);
    }

    $errors   = [];
    $warnings = [];
    $keyBits  = null;
    $keyType  = strtolower($tags['k'] ?? 'rsa');

    // Vérification de la version DKIM (tag v=).
    if (
        isset($tags['v']) &&
        strtoupper($tags['v']) !== 'DKIM1'
    ) {
        $errors[] = 'Version DKIM incorrecte (attendu: DKIM1).';
    }

    // Vérification de la présence et de la validité de la clé publique (tag p=).
    if (!isset($tags['p'])) {
        $errors[] = 'Clé publique p= absente.';
    } elseif ($tags['p'] === '') {
        // Un p= vide signifie que la clé a été révoquée intentionnellement.
        $warnings[] = 'La clé DKIM est révoquée (p= vide).';
    } else {
        // Estimation de la taille de la clé RSA par décodage Base64 et mesure en octets.
        $decoded = @base64_decode($tags['p'], true);
        if ($decoded !== false) {
            $byteLen = strlen($decoded);
            if ($byteLen <= 170) {
                // 1024 bits : dépréciée par les standards modernes (NIST, RFC 8301).
                $keyBits    = 1024;
                $warnings[] = 'Clé RSA 1024 bits détectée : dépréciée par les standards modernes. Une clé de 2048 bits est recommandée.';
            } elseif ($byteLen <= 320) {
                // 2048 bits : taille recommandée, bonne sécurité actuelle.
                $keyBits = 2048;
            } else {
                // 4096 bits : haute sécurité, moins courant.
                $keyBits = 4096;
            }
        }
    }

    return [
        'tags'     => $tags,
        'key_type' => $keyType,
        'key_bits' => $keyBits,
        'errors'   => $errors,
        'warnings' => $warnings
    ];
}

/**
 * Vérifie un sélecteur DKIM spécifique pour un domaine.
 *
 * L'enregistrement DKIM se trouve à l'hôte DNS : {sélecteur}._domainkey.{domaine}
 * Si aucun enregistrement TXT n'est trouvé à cet hôte, retourne null.
 * Si un enregistrement existe mais ne ressemble pas à un DKIM valide (ni v=DKIM1 ni p=),
 * il est ignoré (pourrait être un autre enregistrement TXT au même hôte).
 *
 * @param string $domain   Domaine à vérifier (ex: "exemple.fr").
 * @param string $selector Sélecteur DKIM à tester (ex: "google", "selector1").
 * @return array|null      Résultat d'analyse du sélecteur, ou null si non trouvé.
 */
function checkDkimSelector(
    string $domain,
    string $selector
): ?array {

    $host = $selector . '._domainkey.' . $domain;

    $records = txtRecords($host);

    if (!$records) {
        return null; // Aucun enregistrement TXT à cet hôte.
    }

    // Concatène tous les morceaux TXT en un seul enregistrement.
    $record = implode('', $records);

    // Vérifie que l'enregistrement ressemble bien à un DKIM (contient v=DKIM1 ou p=).
    if (
        stripos($record, 'v=DKIM1') === false &&
        stripos($record, 'p=') === false
    ) {
        return null;
    }

    $parsed = parseDkim($record);

    $status = 'ok';
    if ($parsed['errors']) {
        $status = 'error';
    } elseif ($parsed['warnings']) {
        $status = 'warning';
    }

    return [
        'selector' => $selector,
        'host'     => $host,
        'record'   => $record,
        'status'   => $status,
        'tags'     => $parsed['tags'],
        'key_type' => $parsed['key_type'],
        'key_bits' => $parsed['key_bits'],
        'errors'   => $parsed['errors'],
        'warnings' => $parsed['warnings']
    ];
}

/**
 * Vérifie la configuration DKIM d'un domaine.
 *
 * Deux modes de fonctionnement selon que l'utilisateur a fourni un sélecteur ou non :
 *
 *   Mode sélecteur fourni :
 *     Vérifie uniquement ce sélecteur précis. Si absent → erreur avec suggestion DNS.
 *
 *   Mode découverte automatique (aucun sélecteur fourni) :
 *     Teste les 18 sélecteurs de DEFAULT_DKIM_SELECTORS un par un.
 *     Si au moins un est trouvé, retourne tous les sélecteurs valides.
 *     Si aucun n'est trouvé, retourne un avertissement (le sélecteur est probablement personnalisé).
 *
 * Note : il est techniquement impossible de découvrir un sélecteur arbitraire
 * via DNS public — le DNS ne permet pas d'interroger "tous les sous-domaines de _domainkey.*".
 *
 * @param string $domain   Domaine à vérifier.
 * @param string $selector Sélecteur DKIM fourni par l'utilisateur (ou chaîne vide).
 * @return array           Résultat structuré avec status, message, record, details.
 */
function checkDkim(
    string $domain,
    string $selector
): array {

    // Mode 1 : sélecteur fourni explicitement par l'utilisateur.
    if ($selector !== '') {
        $result = checkDkimSelector($domain, $selector);

        if (!$result) {
            return [
                'status'        => 'error',
                'title'         => 'DKIM',
                'message'       => 'Aucune clé DKIM n’a été trouvée pour le sélecteur « ' . $selector . ' ».',
                'record'        => '',
                'suggested_dns' => [
                    'name'  => $selector . '._domainkey.' . $domain,
                    'type'  => 'TXT',
                    'value' => 'v=DKIM1; k=rsa; p=VOTRE_CLE_PUBLIQUE_ICI',
                    'note'  => 'Activez DKIM chez votre fournisseur email et publiez la clé publique fournie.'
                ],
                'details'       => [
                    'selector' => $selector
                ]
            ];
        }

        return [
            'status'        => $result['status'],
            'title'         => 'DKIM',
            'message'       => 'Clé DKIM trouvée avec le sélecteur « ' . $selector . ' »' . ($result['key_bits'] ? " ({$result['key_bits']} bits)." : '.'),
            'record'        => $result['record'],
            'suggested_dns' => null,
            'details'       => $result
        ];
    }

    // Mode 2 : aucun sélecteur fourni → découverte automatique parmi 18 sélecteurs courants.
    $selectors = DEFAULT_DKIM_SELECTORS;
    $found     = [];

    foreach ($selectors as $candidate) {
        $result = checkDkimSelector($domain, $candidate);
        if ($result) {
            $found[] = $result;
        }
    }

    // Aucun sélecteur connu trouvé : le domaine utilise probablement un sélecteur personnalisé.
    if (!$found) {
        return [
            'status'        => 'warning',
            'title'         => 'DKIM',
            'message'       => 'Aucun sélecteur DKIM courant n’a été trouvé parmi les 18 sélecteurs testés. Votre messagerie utilise probablement un sélecteur personnalisé.',
            'record'        => '',
            'suggested_dns' => null,
            'details'       => [
                'tested' => $selectors
            ]
        ];
    }

    // Détermine le statut global : si l'un des sélecteurs est en erreur, le statut global est erreur.
    $status = 'ok';
    foreach ($found as $item) {
        if ($item['status'] === 'error') {
            $status = 'error';
            break;
        }
        if ($item['status'] === 'warning') {
            $status = 'warning';
        }
    }

    return [
        'status'        => $status,
        'title'         => 'DKIM',
        'message'       => count($found) . ' sélecteur(s) DKIM trouvé(s) (' . implode(', ', array_column($found, 'selector')) . ').',
        'record'        => implode("\n---\n", array_column($found, 'record')),
        'suggested_dns' => null,
        'details'       => [
            'selectors' => $found
        ]
    ];
}


/**
 * Analyse les tags d'un enregistrement DMARC brut selon la RFC 7489.
 *
 * Tags DMARC et leur rôle :
 *   - v=DMARC1 : version obligatoire, doit être exactement "DMARC1"
 *   - p=        : politique principale (none, quarantine, reject)
 *                   none      → surveillance seule, aucun blocage
 *                   quarantine → emails non authentifiés mis en spam
 *                   reject    → emails non authentifiés bloqués et supprimés
 *   - sp=       : politique pour les sous-domaines (même valeurs que p=)
 *   - pct=      : pourcentage d'emails auxquels la politique s'applique (1-100)
 *   - adkim=    : alignement DKIM (r=relaxed, s=strict)
 *   - aspf=     : alignement SPF  (r=relaxed, s=strict)
 *   - rua=      : adresse(s) e-mail pour les rapports agrégés quotidiens
 *   - ruf=      : adresse(s) e-mail pour les rapports forensiques (échecs individuels)
 *
 * @param string $record Enregistrement DMARC brut.
 * @return array         Tags, erreurs bloquantes et avertissements.
 */
function parseDmarc(string $record): array
{
    $tags     = [];
    $errors   = [];
    $warnings = [];

    // Découpe en paires clé=valeur séparées par des points-virgules.
    foreach (explode(';', $record) as $part) {
        $part = trim($part);
        if ($part === '' || strpos($part, '=') === false) {
            continue;
        }
        [$key, $value]              = explode('=', $part, 2);
        $tags[strtolower(trim($key))] = trim($value);
    }

    // Vérification de la version (v=DMARC1 est obligatoire et doit être exact).
    if (
        !isset($tags['v']) ||
        strtoupper($tags['v']) !== 'DMARC1'
    ) {
        $errors[] = 'v=DMARC1 est absent ou incorrect.';
    }

    // Vérification de la politique principale p= (obligatoire).
    if (!isset($tags['p'])) {
        $errors[] = 'La politique p= est absente.';
    } elseif (!in_array(
        strtolower($tags['p']),
        ['none', 'quarantine', 'reject'],
        true
    )) {
        $errors[] = 'La politique p= est invalide.';
    }

    // Vérification de la politique sous-domaine sp= (optionnelle mais si présente, doit être valide).
    if (isset($tags['sp']) &&
        !in_array(
            strtolower($tags['sp']),
            ['none', 'quarantine', 'reject'],
            true
        )
    ) {
        $errors[] = 'La politique sp= est invalide.';
    }

    // Vérification du pourcentage pct= (doit être entre 0 et 100).
    if (isset($tags['pct'])) {
        $pct = (int)$tags['pct'];
        if ($pct < 0 || $pct > 100) {
            $errors[] = 'pct= doit être compris entre 0 et 100.';
        } elseif ($pct < 100) {
            // Un pct< 100 signifie que la politique ne s'applique qu'à une fraction des emails.
            $warnings[] = "La politique ne s'applique qu'à $pct % des emails.";
        }
    }

    // Vérification de l'alignement DKIM adkim= (r=relaxed ou s=strict).
    if (
        isset($tags['adkim']) &&
        !in_array(strtolower($tags['adkim']), ['r', 's'], true)
    ) {
        $errors[] = 'adkim= doit être r ou s.';
    }

    // Vérification de l'alignement SPF aspf= (r=relaxed ou s=strict).
    if (
        isset($tags['aspf']) &&
        !in_array(strtolower($tags['aspf']), ['r', 's'], true)
    ) {
        $errors[] = 'aspf= doit être r ou s.';
    }

    // Avertissement si la politique est p=none (surveillance seule, aucune protection réelle).
    if (
        isset($tags['p']) &&
        strtolower($tags['p']) === 'none'
    ) {
        $warnings[] = 'La politique DMARC est actuellement en p=none (surveillance seule). Les emails non authentifiés ne sont pas bloqués.';
    }

    // Avertissement si aucune adresse de rapport agrégé n'est configurée.
    // Sans rua=, on ne peut pas savoir si des usurpateurs abusent du domaine.
    if (!isset($tags['rua'])) {
        $warnings[] = 'Aucune adresse de rapport agrégé rua= n’est configurée.';
    }

    return [
        'tags'     => $tags,
        'errors'   => $errors,
        'warnings' => $warnings
    ];
}


/**
 * Vérifie que les destinataires externes des rapports DMARC ont autorisé leur réception (RFC 7489).
 *
 * PROBLÈME RÉSOLU : Quand un enregistrement DMARC envoie des rapports vers un domaine tiers
 * (ex: un prestataire DMARC comme Postmark, Mailhardener, dmarcian), la RFC 7489 §7.1 exige
 * que ce domaine tiers publie un enregistrement DNS spécifique pour autoriser la réception.
 * Sans cet enregistrement, les serveurs récepteurs des emails ignorent silencieusement les
 * adresses de rapport → les rapports ne sont jamais envoyés malgré une configuration correcte.
 *
 * Format de l'enregistrement DNS d'autorisation requis :
 *   {domaine-audité}._report._dmarc.{domaine-destinataire}
 *   Valeur TXT attendue : "v=DMARC1" (suivi d'autres tags optionnels)
 *
 * Exemple : si exemple.fr envoie ses rapports à rapports@prestataire.com,
 * la vérification porte sur : exemple.fr._report._dmarc.prestataire.com
 *
 * Les adresses appartenant au même domaine de base que le domaine audité sont ignorées
 * (un domaine s'autorise lui-même implicitement).
 *
 * @param string $domain Domaine audité (ex: "exemple.fr").
 * @param string $rua    Valeur du tag rua= (peut contenir plusieurs adresses séparées par des virgules).
 * @param string $ruf    Valeur du tag ruf= (idem).
 * @return array         Tableau des vérifications externes, une entrée par domaine tiers unique.
 */
function checkExternalDmarcReports(string $domain, string $rua, string $ruf): array
{
    $externalChecks = [];

    // Fusion des listes rua= et ruf= en un seul tableau d'adresses à vérifier.
    $rawList = array_filter(array_merge(explode(',', $rua), explode(',', $ruf)));

    // Extraction du domaine de base (les 2 dernières parties) pour la comparaison.
    // Ex: "mail.exemple.fr" → "exemple.fr" pour ignorer les rapports vers son propre domaine.
    $domainParts = explode('.', strtolower($domain));
    $baseDomain  = count($domainParts) > 2 ? implode('.', array_slice($domainParts, -2)) : strtolower($domain);

    // Évite de vérifier deux fois le même domaine de destination.
    $checkedDomains = [];

    foreach ($rawList as $entry) {
        $entry = trim($entry);

        // Extraction du domaine de l'adresse mailto: (ex: "mailto:rapports@prestataire.com" → "prestataire.com").
        if (!preg_match('/mailto:\s*([^\s@]+)@([^\s!?,;]+)/i', $entry, $matches)) {
            continue; // Entrée malformée ou non-mailto → ignorée.
        }

        $destDomain     = strtolower(trim($matches[2]));
        $destParts      = explode('.', $destDomain);
        $baseDestDomain = count($destParts) > 2 ? implode('.', array_slice($destParts, -2)) : $destDomain;

        // On ignore les adresses appartenant au même domaine de base (auto-autorisation implicite).
        if ($baseDestDomain === $baseDomain) {
            continue;
        }

        // Ne vérifie qu'une seule fois par domaine de destination.
        if (isset($checkedDomains[$destDomain])) {
            continue;
        }
        $checkedDomains[$destDomain] = true;

        // Construction de l'hôte DNS à vérifier selon la RFC 7489 §7.1.
        $verifyHost   = $domain . '._report._dmarc.' . $destDomain;
        $txts         = txtRecords($verifyHost);
        $isAuthorized = false;

        // L'enregistrement d'autorisation doit contenir "v=DMARC1" en début de valeur.
        foreach ($txts as $txt) {
            if (preg_match('/^v=DMARC1(?:\s|;|$)/i', trim($txt))) {
                $isAuthorized = true;
                break;
            }
        }

        $externalChecks[] = [
            'destination_domain' => $destDomain,
            'verify_host'        => $verifyHost,
            'is_authorized'      => $isAuthorized
        ];
    }

    return $externalChecks;
}

/**
 * Vérifie la configuration DMARC complète d'un domaine.
 *
 * Étapes d'analyse :
 *   1. Recherche l'enregistrement DMARC sous _dmarc.{domaine}.
 *   2. Si absent sur un sous-domaine, cherche sur le domaine parent (héritage RFC 7489).
 *   3. Détecte les erreurs critiques (absent, multiples, p= invalide…).
 *   4. Analyse les tags avec parseDmarc().
 *   5. Vérifie les autorisations de rapports externes avec checkExternalDmarcReports().
 *   6. Propose une migration DNS si la politique est encore p=none.
 *
 * @param string $domain Domaine à vérifier.
 * @return array         Résultat structuré avec status, message, record, details incluant external_reports.
 */
function checkDmarc(string $domain): array
{
    $host        = '_dmarc.' . $domain;
    $records     = [];
    $isInherited = false;

    // Recherche de l'enregistrement DMARC du domaine.
    foreach (txtRecords($host) as $txt) {
        if (preg_match('/^v=DMARC1(?:\s|;|$)/i', trim($txt))) {
            $records[] = trim($txt);
        }
    }

    // Si le domaine est un sous-domaine (ex: blog.exemple.fr) et n'a pas de DMARC propre,
    // la RFC 7489 §6.6.3 autorise l'héritage depuis le domaine parent (exemple.fr).
    if (!$records) {
        $parts = explode('.', $domain);
        if (count($parts) > 2) {
            $parent     = implode('.', array_slice($parts, 1));
            $parentHost = '_dmarc.' . $parent;
            foreach (txtRecords($parentHost) as $txt) {
                if (preg_match('/^v=DMARC1(?:\s|;|$)/i', trim($txt))) {
                    $records[]   = trim($txt);
                    $isInherited = true;
                    $host        = $parentHost; // Mise à jour de l'hôte pour l'affichage.
                }
            }
        }
    }

    // Cas 1 : Aucun enregistrement DMARC (ni sur le domaine, ni sur le parent).
    if (!$records) {
        return [
            'status'        => 'error',
            'title'         => 'DMARC',
            'message'       => 'Aucun enregistrement DMARC n’a été trouvé.',
            'record'        => '',
            'suggested_dns' => [
                'name'  => '_dmarc.' . $domain,
                'type'  => 'TXT',
                'value' => 'v=DMARC1; p=none; rua=mailto:dmarc-reports@' . $domain . '; pct=100; sp=none',
                'note'  => 'Enregistrement DMARC recommandé pour démarrer en mode surveillance.'
            ],
            'details'       => []
        ];
    }

    // Cas 2 : Plusieurs enregistrements DMARC → erreur de configuration.
    if (count($records) > 1) {
        return [
            'status'        => 'error',
            'title'         => 'DMARC',
            'message'       => 'Plusieurs enregistrements DMARC ont été détectés sous ' . $host . '.',
            'record'        => implode("\n", $records),
            'suggested_dns' => null,
            'details'       => []
        ];
    }

    // Analyse complète des tags DMARC.
    $parsed = parseDmarc($records[0]);
    $status = 'ok';

    // Vérification des autorisations de rapports vers des domaines externes (RFC 7489 §7.1).
    // Si un rapport est configuré vers prestataire.com mais que l'enregistrement DNS
    // d'autorisation est absent, les serveurs récepteurs n'enverront pas les rapports.
    $externalReports = checkExternalDmarcReports(
        $domain,
        $parsed['tags']['rua'] ?? '',
        $parsed['tags']['ruf'] ?? ''
    );
    foreach ($externalReports as $ext) {
        if (!$ext['is_authorized']) {
            $parsed['warnings'][] = "L’adresse de rapport vers @" . $ext['destination_domain'] . " nécessite un enregistrement DNS d'autorisation RFC 7489 à l'hôte '" . $ext['verify_host'] . "' (non trouvé). Les serveurs récepteurs peuvent refuser d'y envoyer vos rapports.";
        }
    }

    if ($parsed['errors']) {
        $status = 'error';
    } elseif ($parsed['warnings']) {
        $status = 'warning';
    }

    // Si la politique est encore p=none, on propose de passer à p=quarantine.
    // p=none = surveillance seule, aucun email n'est bloqué ou mis en spam.
    $suggestedDns = null;
    $currentP     = strtolower($parsed['tags']['p'] ?? '');
    if ($currentP === 'none') {
        $suggestedDns = [
            'name'  => '_dmarc.' . $domain,
            'type'  => 'TXT',
            'value' => preg_replace('/p=none/', 'p=quarantine', $records[0]),
            'note'  => 'Passage recommandé vers p=quarantine pour protéger activement votre domaine.'
        ];
    }

    return [
        'status'        => $status,
        'title'         => 'DMARC',
        'message'       => $parsed['errors']
            ? implode(' ', $parsed['errors'])
            : ($parsed['warnings'] ? implode(' ', $parsed['warnings']) : "Configuration DMARC conforme et active (p=$currentP)."),
        'record'        => $records[0],
        'suggested_dns' => $suggestedDns,
        'details'       => [
            'inherited'        => $isInherited,
            'host'             => $host,
            'tags'             => $parsed['tags'],
            'errors'           => $parsed['errors'],
            'warnings'         => $parsed['warnings'],
            'external_reports' => $externalReports
        ]
    ];
}


/**
 * Vérifie la configuration MX, le Reverse DNS (PTR) et le FCrDNS d'un domaine.
 *
 * Étapes d'analyse pour chaque serveur MX :
 *   1. Résolution des IPs (IPv4 + IPv6) du nom d'hôte MX.
 *   2. Pour chaque IP, recherche du PTR (Reverse DNS) via gethostbyaddr().
 *   3. Pour chaque PTR trouvé, vérification FCrDNS : le nom PTR résout-il vers la même IP ?
 *      (Forward-Confirmed Reverse DNS = double vérification nom ↔ IP)
 *
 * Pourquoi le FCrDNS est important :
 *   Certains filtres anti-spam vérifient la cohérence PTR ↔ A.
 *   Un serveur qui ne valide pas le FCrDNS peut voir ses emails rejetés ou mis en spam.
 *
 * Après l'analyse MX, appelle detectMailProvider() pour identifier le fournisseur.
 *
 * @param string $domain Domaine à vérifier.
 * @return array         Résultat avec status, liste des serveurs, PTR, FCrDNS et fournisseur détecté.
 */
function checkMx(string $domain): array
{
    $records = mxRecords($domain);

    // Aucun serveur MX : le domaine ne peut pas recevoir d'emails.
    if (!$records) {
        return [
            'status'        => 'error',
            'title'         => 'MX et Reverse DNS',
            'message'       => 'Aucun serveur MX n’a été trouvé. Le domaine ne peut pas recevoir d’emails.',
            'record'        => '',
            'suggested_dns' => [
                'name'  => '@',
                'type'  => 'MX',
                'value' => '10 mail.' . $domain,
                'note'  => 'Configurez les serveurs MX fournis par votre messagerie.'
            ],
            'details'       => []
        ];
    }

    $servers        = [];
    $reverseWarning = false; // Vrai si au moins un PTR est absent.
    $fcrdnsWarning  = false; // Vrai si au moins un PTR ne résout pas vers la bonne IP.

    foreach ($records as $record) {
        $host      = rtrim((string)($record['target'] ?? ''), '.');
        $ips       = hostIPs($host);
        $addresses = [];

        foreach ($ips as $ip) {
            $ptr    = ptrRecord($ip);
            $hasPtr = ($ptr !== '');
            $fcrdns = false;

            if (!$hasPtr) {
                // IP sans PTR → problème potentiel de réputation e-mail.
                $reverseWarning = true;
            } else {
                // Test FCrDNS : le nom PTR résout-il bien vers cette même IP ?
                // Si non, la cohérence DNS est rompue (possible mauvaise configuration).
                $forwardIps = hostIPs($ptr);
                $fcrdns     = in_array($ip, $forwardIps, true);
                if (!$fcrdns) {
                    $fcrdnsWarning = true;
                }
            }

            $addresses[] = [
                'ip'      => $ip,
                'ptr'     => $ptr,
                'has_ptr' => $hasPtr,
                'fcrdns'  => $fcrdns
            ];
        }

        $servers[] = [
            'priority'  => (int)($record['pri'] ?? 0),
            'host'      => $host,
            'addresses' => $addresses
        ];
    }

    // Identification du fournisseur de messagerie basée sur les noms d'hôtes MX (et PTR en secours).
    $provider       = detectMailProvider($servers);
    $providerNotice = $provider ? ' (Messagerie : ' . $provider['name'] . ')' : '';

    // Détection d'un CNAME sur la racine (@) - RFC 1034 §3.6.2
    $rootCnames = dnsRecords($domain, DNS_CNAME);
    $cnameWarning = false;
    if (!empty($rootCnames)) {
        $cnameTarget = $rootCnames[0]['target'] ?? '';
        $cnameWarning = true;
    }

    $status  = 'ok';
    $message = count($servers) . ' serveur(s) MX configuré(s) avec Reverse DNS (PTR) opérationnel.' . $providerNotice;

    if ($cnameWarning) {
        $status  = 'error';
        $message = 'Anomalie critique RFC 1034 : un enregistrement CNAME a été détecté sur la racine (@). La norme interdit formellement les CNAME sur la racine car ils rendent inopérants vos MX et SPF !' . $providerNotice;
    } elseif ($reverseWarning) {
        $status  = 'warning';
        $message = 'Les MX sont présents, mais un ou plusieurs Reverse DNS (PTR) sont absents.' . $providerNotice;
    } elseif ($fcrdnsWarning) {
        $status  = 'warning';
        $message = 'Les PTR existent, mais certains ne valident pas le contrôle de réconciliation directe-inverse (FCrDNS).' . $providerNotice;
    }

    // Construction des lignes MX pour l'affichage de l'enregistrement brut.
    $mxLines = [];
    foreach ($servers as $s) {
        $mxLines[] = $s['priority'] . ' ' . $s['host'];
    }

    return [
        'status'        => $status,
        'title'         => 'MX et Reverse DNS',
        'message'       => $message,
        'record'        => implode("\n", $mxLines),
        'suggested_dns' => null,
        'provider'      => $provider,
        'details'       => [
            'servers'       => $servers,
            'provider'      => $provider,
            'cname_on_apex' => $cnameWarning
        ]
    ];
}


/**
 * Identifie le fournisseur de messagerie utilisé par un domaine.
 *
 * Algorithme en deux passes :
 *
 *   Passe 1 — Correspondance sur les noms d'hôtes MX :
 *     Vérifie si le nom d'hôte MX correspond exactement à un domaine connu,
 *     ou s'il se termine par ".domaine-connu" (sous-domaine).
 *     Exemple : "mx1.mail.protection.outlook.com" → Microsoft 365
 *
 *   Passe 2 — Correspondance sur le PTR (Reverse DNS) en secours :
 *     Si le MX utilise un nom d'hôte personnalisé (ex: "mail.mondomaine.com"),
 *     la passe 1 échoue. On vérifie alors le PTR de l'IP du serveur MX.
 *     Exemple : "mail.thierrylaval.dev" → IP → PTR "109-234-161-215.reverse.odns.fr" → o2switch
 *
 * 17 fournisseurs reconnus : Google Workspace, Microsoft 365, OVHcloud, Infomaniak,
 * Proton Mail, Fastmail, Zoho, Brevo, Mailjet, Mailgun, SendGrid, Apple iCloud,
 * Yahoo, Gandi, o2switch, Hostinger/Titan, IONOS.
 *
 * @param array $servers Tableau des serveurs MX avec leurs adresses IP et PTR (issu de checkMx).
 * @return array|null    Tableau ['slug' => ..., 'name' => ...] ou null si non identifié.
 */
function detectMailProvider(array $servers): ?array
{
    // Table de correspondance : slug → nom affiché + liste de domaines reconnus.
    $patterns = [
        'google'     => [
            'name'    => 'Google Workspace (Gmail Pro)',
            'domains' => ['google.com', 'googlemail.com', 'aspmx.l.google.com', 'l.google.com']
        ],
        'microsoft'  => [
            'name'    => 'Microsoft 365 / Exchange Online',
            'domains' => ['outlook.com', 'mail.protection.outlook.com', 'office365.com']
        ],
        'ovh'        => [
            'name'    => 'OVHcloud Mail',
            'domains' => ['ovh.net', 'ovh.ca', 'mail.ovh.net']
        ],
        'infomaniak' => [
            'name'    => 'Infomaniak Network',
            'domains' => ['infomaniak.ch', 'infomaniak.com']
        ],
        'proton'     => [
            'name'    => 'Proton Mail',
            'domains' => ['protonmail.ch', 'proton.me']
        ],
        'fastmail'   => [
            'name'    => 'Fastmail',
            'domains' => ['messagingengine.com', 'fastmail.com']
        ],
        'zoho'       => [
            'name'    => 'Zoho Mail',
            'domains' => ['zoho.com', 'zoho.eu']
        ],
        'brevo'      => [
            'name'    => 'Brevo (ex-Sendinblue)',
            'domains' => ['brevo.com', 'mailin-sms.com', 'sendinblue.com']
        ],
        'mailjet'    => [
            'name'    => 'Mailjet',
            'domains' => ['mailjet.com']
        ],
        'mailgun'    => [
            'name'    => 'Mailgun',
            'domains' => ['mailgun.org']
        ],
        'sendgrid'   => [
            'name'    => 'SendGrid (Twilio)',
            'domains' => ['sendgrid.net']
        ],
        'icloud'     => [
            'name'    => 'Apple iCloud Mail',
            'domains' => ['icloud.com']
        ],
        'yahoo'      => [
            'name'    => 'Yahoo Mail',
            'domains' => ['yahoodns.net', 'yahoo.com']
        ],
        'gandi'      => [
            'name'    => 'Gandi Mail',
            'domains' => ['gandi.net']
        ],
        'o2switch'   => [
            'name'    => 'o2switch Mail',
            'domains' => ['o2switch.net', 'odns.fr']
        ],
        'hostinger'  => [
            'name'    => 'Hostinger / Titan Mail',
            'domains' => ['hostinger.com', 'titan.email']
        ],
        'ionos'      => [
            'name'    => 'IONOS (1&1)',
            'domains' => ['kundenserver.de', 'ionos.com', '1and1.com', '1and1.fr']
        ]
    ];

    // Passe 1 : correspondance directe sur le nom d'hôte MX.
    foreach ($servers as $s) {
        $host = strtolower($s['host'] ?? '');
        foreach ($patterns as $slug => $def) {
            foreach ($def['domains'] as $d) {
                // Correspondance exacte OU sous-domaine (ex: "mx1.ovh.net" correspond à "ovh.net").
                if ($host === $d || (strlen($host) > strlen($d) && substr($host, -strlen('.' . $d)) === '.' . $d)) {
                    return ['slug' => $slug, 'name' => $def['name']];
                }
            }
        }
    }

    // Passe 2 : correspondance sur le PTR de l'IP (pour les MX avec nom d'hôte personnalisé).
    // Ex: "mail.thierrylaval.dev" n'est pas dans la table, mais son PTR "*.odns.fr" l'est.
    foreach ($servers as $s) {
        foreach ($s['addresses'] ?? [] as $addr) {
            $ptr = strtolower($addr['ptr'] ?? '');
            if ($ptr === '') {
                continue;
            }
            foreach ($patterns as $slug => $def) {
                foreach ($def['domains'] as $d) {
                    if ($ptr === $d || (strlen($ptr) > strlen($d) && substr($ptr, -strlen('.' . $d)) === '.' . $d)) {
                        return ['slug' => $slug, 'name' => $def['name']];
                    }
                }
            }
        }
    }

    // Fournisseur non identifié parmi les 17 connus.
    return null;
}


/**
 * Effectue une requête HTTP GET avec cURL (ou file_get_contents en secours).
 *
 * Utilisée uniquement pour vérifier le fichier de politique MTA-STS via HTTPS.
 * Le certificat SSL est vérifié (CURLOPT_SSL_VERIFYPEER = true) pour garantir
 * qu'on se connecte bien au bon serveur et non à un imposteur.
 *
 * Gestion de la compatibilité PHP 8.5+ :
 *   curl_close() est dépréciée en PHP 8.5. On utilise unset($ch) à la place,
 *   et on n'appelle curl_close() que si la version PHP est < 8.0 pour éviter
 *   un avertissement de dépréciation dans les logs serveur.
 *
 * Fallback sans cURL :
 *   Si l'extension cURL n'est pas disponible (rare mais possible sur certains hébergements),
 *   file_get_contents() est utilisé à la place avec un contexte de flux SSL.
 *
 * @param string $url URL HTTPS à récupérer.
 * @return array      Tableau avec 'ok' (bool), 'code' (int HTTP), 'body' (string), 'error' (string).
 */
function curlGet(string $url): array
{
    // Fallback si cURL n'est pas disponible : utilise file_get_contents avec contexte SSL.
    if (!function_exists('curl_init')) {
        $ctx  = stream_context_create([
            'http' => [
                'timeout'         => HTTP_TIMEOUT,
                'follow_location' => 1,
                'max_redirects'   => 3,
                'user_agent'      => 'DNS-Mail-Checker/2.0',
                'ignore_errors'   => true
            ],
            'ssl'  => [
                'verify_peer'      => true,
                'verify_peer_name' => true
            ]
        ]);
        $body = @file_get_contents($url, false, $ctx);
        return [
            'ok'    => ($body !== false),
            'code'  => ($body !== false ? 200 : 0),
            'body'  => ($body !== false ? (string)$body : ''),
            'error' => ($body === false ? 'Échec de connexion HTTPS.' : '')
        ];
    }

    // Requête cURL standard avec vérification SSL et timeout court.
    $ch = curl_init($url);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_CONNECTTIMEOUT => HTTP_TIMEOUT,
        CURLOPT_TIMEOUT        => HTTP_TIMEOUT,
        CURLOPT_USERAGENT      => 'DNS-Mail-Checker/2.0',
        CURLOPT_SSL_VERIFYPEER => true,  // Vérifie le certificat SSL de la cible.
        CURLOPT_SSL_VERIFYHOST => 2      // Vérifie que le nom d'hôte correspond au certificat.
    ]);

    $body  = curl_exec($ch);
    $error = curl_error($ch);
    $code  = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

    // PHP < 8.0 : curl_close() était recommandé pour libérer les ressources.
    // PHP >= 8.0 : les ressources cURL sont des objets gérés automatiquement par le GC.
    // PHP >= 8.5 : curl_close() est explicitement dépréciée.
    if (PHP_VERSION_ID < 80000) {
        @curl_close($ch);
    }
    unset($ch); // Libère la référence à l'objet cURL (déclenche le GC si PHP >= 8.0).

    return [
        'ok'    => ($body !== false && $code >= 200 && $code < 300),
        'code'  => $code,
        'body'  => ($body !== false) ? (string)$body : '',
        'error' => $error ?: ($code >= 400 ? "Code HTTP $code" : '')
    ];
}

/**
 * Vérifie la configuration MTA-STS d'un domaine.
 *
 * MTA-STS (RFC 8461) est un mécanisme qui force les serveurs qui vous envoient des emails
 * à utiliser une connexion TLS chiffrée. Sans MTA-STS, si le chiffrement TLS échoue,
 * certains serveurs anciens basculent en clair (non chiffré).
 *
 * MTA-STS nécessite DEUX éléments :
 *   1. Un enregistrement DNS TXT à "_mta-sts.{domaine}" (ex: "v=STSv1; id=202409301349")
 *   2. Un fichier de politique accessible en HTTPS à :
 *      "https://mta-sts.{domaine}/.well-known/mta-sts.txt"
 *      Ce fichier contient les directives mode, max_age et mx.
 *
 * Directives du fichier de politique :
 *   - mode: enforce  → TLS obligatoire, les emails non chiffrés sont rejetés
 *   - mode: testing  → TLS recommandé mais pas obligatoire, mode de transition
 *   - mode: none     → désactive MTA-STS
 *   - max_age: N     → durée de validité de la politique en secondes (ex: 604800 = 1 semaine)
 *   - mx: ...        → liste des noms de serveurs MX autorisés
 *
 * Note importante : ce test effectue une vraie requête HTTPS sortante depuis le serveur PHP.
 * Sur certains hébergements mutualisés restrictifs, cURL sortant peut être bloqué.
 * Dans ce cas, le test retournera un avertissement même si MTA-STS est correctement configuré.
 *
 * @param string $domain Domaine à vérifier.
 * @return array         Résultat avec status, message, record et détails de la politique.
 */
function checkMtaSts(string $domain): array
{
    $host    = '_mta-sts.' . $domain;
    $records = [];

    // Filtre les enregistrements TXT pour ne garder que ceux qui commencent par "v=STSv1".
    foreach (txtRecords($host) as $txt) {
        if (stripos(trim($txt), 'v=STSv1') === 0) {
            $records[] = trim($txt);
        }
    }

    // Cas 1 : Aucun DNS MTA-STS → non configuré (normal pour la grande majorité des domaines).
    if (!$records) {
        return [
            'status'        => 'warning',
            'title'         => 'MTA-STS',
            'message'       => 'MTA-STS n’est pas configuré. Il s’agit d’une protection complémentaire facultative qui renforce le chiffrement entre serveurs.',
            'record'        => '',
            'suggested_dns' => null, // Pas de suggestion DNS : sans le serveur HTTPS, le DNS seul serait inutile.
            'details'       => []
        ];
    }

    // Cas 2 : DNS MTA-STS présent → vérification du fichier de politique HTTPS.
    $url  = 'https://mta-sts.' . $domain . '/.well-known/mta-sts.txt';
    $http = curlGet($url);

    // Le DNS existe mais la politique HTTPS est inaccessible → configuration incomplète.
    if (!$http['ok']) {
        return [
            'status'        => 'warning',
            'title'         => 'MTA-STS',
            'message'       => 'Le DNS MTA-STS existe mais la politique HTTPS n’a pas pu être récupérée (' . $url . ').',
            'record'        => $records[0],
            'suggested_dns' => null,
            'details'       => [
                'url'   => $url,
                'code'  => $http['code'],
                'error' => $http['error']
            ]
        ];
    }

    // Analyse ligne par ligne du fichier de politique mta-sts.txt.
    $mode   = '';
    $maxAge = '';
    $mx     = [];

    foreach (preg_split('/\R/', $http['body']) as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, ':') === false) {
            continue;
        }
        [$key, $value] = explode(':', $line, 2);
        $key           = strtolower(trim($key));
        $value         = trim($value);

        if ($key === 'mode') {
            $mode = strtolower($value);
        } elseif ($key === 'max_age') {
            $maxAge = $value;
        } elseif ($key === 'mx') {
            $mx[] = $value;
        }
    }

    // Validation des directives obligatoires du fichier de politique.
    $errors = [];
    if ($mode === '') {
        $errors[] = 'Directive mode absente.';
    } elseif (!in_array($mode, ['enforce', 'testing', 'none'], true)) {
        $errors[] = "Mode '$mode' invalide (doit être enforce, testing ou none).";
    }

    if ($maxAge === '') {
        $errors[] = 'Directive max_age absente.';
    }

    if (!$mx) {
        $errors[] = 'Aucune directive mx trouvée.';
    }

    return [
        'status'        => $errors ? 'error' : 'ok',
        'title'         => 'MTA-STS',
        'message'       => $errors ? implode(' ', $errors) : "La politique MTA-STS est accessible et valide (mode: $mode, max_age: $maxAge s).",
        'record'        => $records[0],
        'suggested_dns' => null,
        'details'       => [
            'url'     => $url,
            'mode'    => $mode,
            'max_age' => $maxAge,
            'mx'      => $mx,
            'policy'  => trim($http['body']) // Corps complet du fichier de politique pour affichage.
        ]
    ];
}


/**
 * Vérifie la configuration TLS-RPT d'un domaine.
 *
 * TLS-RPT (RFC 8460) est un mécanisme de reporting qui permet de recevoir automatiquement
 * des rapports quotidiens sur les connexions TLS échouées lors des échanges e-mail.
 * Ces rapports sont envoyés par les grands serveurs de messagerie (Gmail, Outlook…)
 * et aident à détecter des problèmes de certificats ou de compatibilité TLS.
 *
 * L'enregistrement DNS se trouve à : "_smtp._tls.{domaine}"
 * Format : "v=TLSRPTv1; rua=mailto:tls-reports@exemple.fr"
 *
 * Le tag rua= désigne l'adresse (ou URL HTTPS) où les rapports sont envoyés.
 * Sans rua=, l'enregistrement TLS-RPT est présent mais inutile (aucun rapport ne sera envoyé).
 *
 * Pourquoi aucune suggestion DNS n'est proposée :
 *   Suggérer "rua=mailto:tls-reports@exemple.fr" serait dangereux si cette boîte mail
 *   n'existe pas réellement. Les rapports TLS génèrent du trafic e-mail entrant significatif.
 *   L'utilisateur doit d'abord créer la boîte mail, puis configurer l'enregistrement.
 *
 * @param string $domain Domaine à vérifier.
 * @return array         Résultat avec status, message, record et tags analysés.
 */
function checkTlsRpt(string $domain): array
{
    $host    = '_smtp._tls.' . $domain;
    $records = [];

    // Filtre les enregistrements TXT pour ne garder que ceux qui commencent par "v=TLSRPTv1".
    foreach (txtRecords($host) as $txt) {
        if (stripos(trim($txt), 'v=TLSRPTv1') === 0) {
            $records[] = trim($txt);
        }
    }

    // Aucun enregistrement TLS-RPT : non configuré (très courant, ce n'est pas une erreur critique).
    if (!$records) {
        return [
            'status'        => 'warning',
            'title'         => 'TLS-RPT',
            'message'       => 'TLS-RPT n’est pas configuré. Il s’agit d’un service optionnel permettant de recevoir des bilans sur les connexions sécurisées.',
            'record'        => '',
            'suggested_dns' => null, // Pas de suggestion : l'adresse e-mail doit exister avant de la publier.
            'details'       => []
        ];
    }

    // Analyse des tags de l'enregistrement TLS-RPT.
    $tags = [];
    foreach (explode(';', $records[0]) as $part) {
        $part = trim($part);
        if ($part === '' || strpos($part, '=') === false) {
            continue;
        }
        [$key, $value]              = explode('=', $part, 2);
        $tags[strtolower(trim($key))] = trim($value);
    }

    // Le tag rua= est obligatoire pour que les rapports soient effectivement envoyés.
    $status = isset($tags['rua']) ? 'ok' : 'warning';

    return [
        'status'        => $status,
        'title'         => 'TLS-RPT',
        'message'       => isset($tags['rua'])
            ? 'TLS-RPT est configuré avec destination des rapports.'
            : 'TLS-RPT existe mais le paramètre rua= est absent.',
        'record'        => $records[0],
        'suggested_dns' => null,
        'details'       => [
            'tags' => $tags
        ]
    ];
}


/**
 * Vérifie la configuration BIMI d'un domaine.
 *
 * BIMI (Brand Indicators for Message Identification) est un standard qui permet
 * aux entreprises d'afficher leur logo officiel à côté de leurs emails dans
 * la boîte de réception des destinataires (Gmail, Apple Mail, Yahoo Mail).
 *
 * L'enregistrement DNS se trouve à : "default._bimi.{domaine}"
 * Format : "v=BIMI1; l=https://exemple.fr/logo.svg; a=https://exemple.fr/cert.pem"
 *
 * Tags BIMI :
 *   - v=BIMI1 : version obligatoire
 *   - l=      : URL HTTPS du logo SVG (format SVG Tiny P.S. requis par Gmail/Yahoo)
 *   - a=      : URL HTTPS du certificat VMC (optionnel, requis pour affichage garanti sur Gmail)
 *
 * Conditions requises pour que BIMI fonctionne sur Gmail et Yahoo :
 *   - DMARC doit être en p=quarantine avec pct=100, OU en p=reject
 *   - Le logo doit être en format SVG Tiny P.S. (pas un SVG ordinaire)
 *   - Pour Gmail : un certificat VMC payant (~300$/an) chez Entrust ou DigiCert
 *
 * Statut "info" (pas "warning") :
 *   Si BIMI n'est pas configuré, ce n'est PAS une erreur ni un avertissement.
 *   C'est une fonctionnalité optionnelle purement marketing. Le statut "info"
 *   est utilisé pour l'afficher sans le comptabiliser dans le score de sécurité.
 *
 * @param string $domain      Domaine à vérifier.
 * @param array  $dmarcResult Résultat DMARC pré-calculé (pour vérifier la compatibilité DMARC).
 * @return array              Résultat avec status ('info', 'ok', 'warning', 'error'), record et details.
 */
function checkBimi(string $domain, array $dmarcResult): array
{
    $host    = 'default._bimi.' . $domain;
    $records = [];

    // Filtre les enregistrements TXT pour ne garder que ceux qui commencent par "v=BIMI1".
    foreach (txtRecords($host) as $txt) {
        if (stripos(trim($txt), 'v=BIMI1') === 0) {
            $records[] = trim($txt);
        }
    }

    // BIMI non configuré : statut "info" (informatif, pas une erreur, ne pénalise pas le score).
    if (!$records) {
        return [
            'status'        => 'info',
            'title'         => 'BIMI (Logo de marque)',
            'message'       => 'BIMI n’est pas configuré. C’est une option marketing permettant d’afficher le logo officiel de votre marque dans les boîtes de réception (Gmail, Apple Mail, Yahoo).',
            'record'        => '',
            'suggested_dns' => null,
            'details'       => [
                'configured' => false
            ]
        ];
    }

    // BIMI trouvé : analyse complète des tags.
    $record = $records[0];
    $tags   = [];
    foreach (explode(';', $record) as $part) {
        $part = trim($part);
        if ($part === '' || strpos($part, '=') === false) {
            continue;
        }
        [$key, $value]              = explode('=', $part, 2);
        $tags[strtolower(trim($key))] = trim($value);
    }

    $errors   = [];
    $warnings = [];

    // Vérification de la version BIMI (v=BIMI1 obligatoire).
    if (!isset($tags['v']) || strtoupper($tags['v']) !== 'BIMI1') {
        $errors[] = 'La version v=BIMI1 est absente ou incorrecte.';
    }

    // Vérification de l'URL du logo SVG (tag l=).
    $logoUrl = $tags['l'] ?? '';
    if ($logoUrl === '') {
        $errors[] = 'Le tag l= (URL du logo SVG) est manquant.';
    } elseif (!filter_var($logoUrl, FILTER_VALIDATE_URL) || stripos($logoUrl, 'https://') !== 0) {
        // L'URL du logo doit être en HTTPS pour des raisons de sécurité.
        $errors[] = 'L’URL du logo (l=) doit être en HTTPS.';
    } elseif (!preg_match('/\.svg(\?.*)?$/i', $logoUrl)) {
        // Le format SVG Tiny P.S. est requis (un fichier PNG ou JPG ne fonctionnera pas).
        $warnings[] = 'Le fichier logo (l=) doit être un fichier vectoriel .svg (recommandé SVG Tiny P.S.).';
    }

    // Vérification du certificat VMC optionnel (tag a=).
    // Le VMC (Verified Mark Certificate) est requis par Gmail pour afficher le logo de façon certifiée.
    $certUrl = $tags['a'] ?? '';
    if ($certUrl !== '' && (!filter_var($certUrl, FILTER_VALIDATE_URL) || stripos($certUrl, 'https://') !== 0)) {
        $warnings[] = 'L’URL du certificat VMC (a=) doit être en HTTPS.';
    }

    // Vérification de la compatibilité DMARC pour BIMI.
    // Gmail et Yahoo n'activent BIMI que si DMARC est en p=reject OU p=quarantine avec pct=100.
    // Un DMARC en p=none ou pct<100 = BIMI visible dans le DNS mais ignoré par les messageries.
    $dmarcTags      = $dmarcResult['details']['tags'] ?? [];
    $dmarcPolicy    = strtolower($dmarcTags['p'] ?? '');
    $dmarcPct       = isset($dmarcTags['pct']) ? (int)$dmarcTags['pct'] : 100;
    $dmarcCompatible = false;

    if ($dmarcPolicy === 'reject' || ($dmarcPolicy === 'quarantine' && $dmarcPct === 100)) {
        $dmarcCompatible = true;
    } else {
        $warnings[] = 'BIMI est détecté mais sera ignoré par Gmail et Yahoo : DMARC doit être configuré en p=quarantine (avec pct=100) ou p=reject.';
    }

    $status  = $errors ? 'error' : ($warnings ? 'warning' : 'ok');
    $message = $errors
        ? implode(' ', $errors)
        : ($warnings ? implode(' ', $warnings) : 'Enregistrement BIMI valide et conforme aux exigences DMARC.');

    return [
        'status'        => $status,
        'title'         => 'BIMI (Logo de marque)',
        'message'       => $message,
        'record'        => $record,
        'suggested_dns' => null,
        'details'       => [
            'configured'       => true,
            'host'             => $host,
            'tags'             => $tags,
            'logo_url'         => $logoUrl,
            'cert_url'         => $certUrl,
            'dmarc_compatible' => $dmarcCompatible,
            'errors'           => $errors,
            'warnings'         => $warnings
        ]
    ];
}


/**
 * Vérifie la réputation des serveurs MX sur les principales listes noires (RBL / DNSBL).
 *
 * Les Real-time Blackhole Lists (RBL) sont des bases de données réputées qui répertorient
 * les adresses IP identifiées comme émettrices de spam ou compromises.
 * Les grands services de messagerie (Gmail, Microsoft 365, Yahoo) consultent ces listes
 * en temps réel pour décider d'accepter, de rejeter ou de classer en spam les emails.
 *
 * Fonctionnement par requête DNS inverse :
 *   Pour l'adresse IP A.B.C.D, on interroge en DNS de type A :
 *   D.C.B.A.{rbl-host}
 *   Si la réponse DNS est vide (NXDOMAIN) : l'IP est saine (non listée).
 *   Si la réponse renvoie une IP 127.0.0.x : l'IP est inscrite sur la liste noire.
 *
 * Listes noires publiques interrogées :
 *   - Spamcop (bl.spamcop.net)
 *   - Barracuda (b.barracudacentral.org)
 *   - SURRIEL PSBL (psbl.surriel.com)
 *   - UCEPROTECT Niveau 1 (dnsbl-1.uceprotect.net)
 *
 * @param array $mxServers Tableau des serveurs MX retourné par checkMx.
 * @return array           Résultat structuré avec status ('ok', 'warning', 'error'), message et détails.
 */
function checkRbl(array $mxServers): array
{
    $rbls = [
        'Spamcop'      => 'bl.spamcop.net',
        'Barracuda'    => 'b.barracudacentral.org',
        'SURRIEL PSBL' => 'psbl.surriel.com',
        'UCEPROTECT 1' => 'dnsbl-1.uceprotect.net'
    ];

    $testedIps = [];
    $listedResults = [];

    // Récupérer toutes les adresses IPv4 distinctes des serveurs MX (max 4 pour la rapidité)
    foreach ($mxServers as $server) {
        foreach ($server['addresses'] ?? [] as $addr) {
            $ip = $addr['ip'] ?? '';
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $testedIps[$ip] = true;
            }
        }
    }

    $ipList = array_slice(array_keys($testedIps), 0, 4);

    if (empty($ipList)) {
        return [
            'status'        => 'info',
            'title'         => 'Listes Noires (RBL)',
            'message'       => 'Aucune adresse IPv4 de serveur MX disponible pour tester la réputation.',
            'record'        => '',
            'suggested_dns' => null,
            'details'       => [
                'checked_ips' => [],
                'listed'      => []
            ]
        ];
    }

    $detailedChecks = [];

    foreach ($ipList as $ip) {
        $parts = explode('.', $ip);
        $revIp = implode('.', array_reverse($parts));

        foreach ($rbls as $rblName => $rblHost) {
            $query = $revIp . '.' . $rblHost;
            $res = @dns_get_record($query, DNS_A);
            $isListed = false;
            $returnIp = '';

            if (!empty($res)) {
                $returnIp = $res[0]['ip'] ?? '';
                // 127.0.0.x = listé ; ignorer les codes d'erreur de résolveur comme 127.255.255.x
                if (strpos($returnIp, '127.0.0.') === 0) {
                    $isListed = true;
                    $listedResults[] = [
                        'ip'  => $ip,
                        'rbl' => $rblName
                    ];
                }
            }

            $detailedChecks[] = [
                'ip'        => $ip,
                'rbl'       => $rblName,
                'is_listed' => $isListed,
                'return_ip' => $returnIp
            ];
        }
    }

    if (count($listedResults) > 0) {
        $warnings = [];
        foreach ($listedResults as $l) {
            $warnings[] = "L’adresse IP {$l['ip']} est répertoriée sur {$l['rbl']}.";
        }
        return [
            'status'        => 'error',
            'title'         => 'Listes Noires (RBL)',
            'message'       => 'Alerte réputation : ' . implode(' ', $warnings) . ' Vos emails risquent d’être refusés ou classés en spam.',
            'record'        => implode(', ', array_unique(array_column($listedResults, 'ip'))),
            'suggested_dns' => null,
            'details'       => [
                'checked_ips' => $ipList,
                'checks'      => $detailedChecks,
                'listed'      => $listedResults
            ]
        ];
    }

    return [
        'status'        => 'ok',
        'title'         => 'Listes Noires (RBL)',
        'message'       => 'Excellente réputation : vos serveurs MX ne figurent sur aucune des listes noires testées (' . implode(', ', array_keys($rbls)) . ').',
        'record'        => implode(', ', $ipList),
        'suggested_dns' => null,
        'details'       => [
            'checked_ips' => $ipList,
            'checks'      => $detailedChecks,
            'listed'      => []
        ]
    ];
}


/**
 * Vérifie l'activation de DNSSEC pour le domaine.
 *
 * DNSSEC (Domain Name System Security Extensions) ajoute une couche de signatures
 * cryptographiques à la zone DNS. Il empêche les attaques par empoisonnement de cache
 * (DNS cache poisoning) et garantit que les enregistrements MX, SPF et DKIM reçus
 * n'ont pas été falsifiés ou détournés par un pirate sur le réseau.
 *
 * Détection via l'API DNS-over-HTTPS (DoH) Google :
 *   Interroge les enregistrements DS (Delegation Signer, type RFC 43) publiés dans la zone parente.
 *   Si un enregistrement DS est présent et valide, DNSSEC est actif.
 *
 * @param string $domain Domaine à vérifier.
 * @return array         Résultat structuré ('ok' si actif, 'info' si non configuré).
 */
function checkDnssec(string $domain): array
{
    $url = 'https://dns.google/resolve?name=' . urlencode($domain) . '&type=DS';
    $http = curlGet($url);

    if (!$http['ok']) {
        return [
            'status'        => 'info',
            'title'         => 'DNSSEC (Signature DNS)',
            'message'       => 'Impossible de vérifier DNSSEC (accès réseau DoH non disponible).',
            'record'        => '',
            'suggested_dns' => null,
            'details'       => ['enabled' => false]
        ];
    }

    $data = @json_decode($http['body'], true);
    $answers = $data['Answer'] ?? [];
    $dsRecords = [];

    foreach ($answers as $ans) {
        if (($ans['type'] ?? 0) === 43 && !empty($ans['data'])) {
            $dsRecords[] = (string)$ans['data'];
        }
    }

    if (!empty($dsRecords)) {
        return [
            'status'        => 'ok',
            'title'         => 'DNSSEC (Signature DNS)',
            'message'       => 'DNSSEC est activé. Votre zone DNS est protégée par signature cryptographique contre l’usurpation et le détournement.',
            'record'        => implode("\n", $dsRecords),
            'suggested_dns' => null,
            'details'       => [
                'enabled'    => true,
                'ds_records' => $dsRecords
            ]
        ];
    }

    return [
        'status'        => 'info',
        'title'         => 'DNSSEC (Signature DNS)',
        'message'       => 'DNSSEC n’est pas activé. Il s’agit d’une sécurité avancée facultative qui s’active généralement chez votre bureau d’enregistrement (Registrar).',
        'record'        => '',
        'suggested_dns' => null,
        'details'       => [
            'enabled' => false
        ]
    ];
}


/**
 * Vérifie la configuration DANE / TLSA sur les serveurs de messagerie MX.
 *
 * DANE (RFC 7672) permet de lier directement le certificat SSL/TLS d'un serveur de messagerie
 * à un enregistrement DNS de type TLSA (sur le port 25 : _25._tcp.mx-host).
 * Il complète MTA-STS en assurant un chiffrement TLS garanti sans risque d'attaque par
 * substitution de certificat intermédiaire.
 *
 * @param array $mxServers Serveurs MX retournés par checkMx.
 * @return array           Résultat structuré ('ok' si présent, 'info' si absent).
 */
function checkDane(array $mxServers): array
{
    $foundDane = [];

    foreach (array_slice($mxServers, 0, 3) as $s) {
        $host = $s['host'] ?? '';
        if ($host === '') continue;

        $tlsaHost = '_25._tcp.' . $host;
        $url = 'https://dns.google/resolve?name=' . urlencode($tlsaHost) . '&type=TLSA';
        $http = curlGet($url);

        if ($http['ok']) {
            $data = @json_decode($http['body'], true);
            $answers = $data['Answer'] ?? [];
            foreach ($answers as $ans) {
                if (($ans['type'] ?? 0) === 52 && !empty($ans['data'])) {
                    $foundDane[] = [
                        'host'   => $host,
                        'record' => (string)$ans['data']
                    ];
                }
            }
        }
    }

    if (!empty($foundDane)) {
        $lines = [];
        foreach ($foundDane as $d) {
            $lines[] = $d['host'] . ' : ' . $d['record'];
        }
        return [
            'status'        => 'ok',
            'title'         => 'DANE / TLSA',
            'message'       => 'DANE / TLSA est configuré sur vos serveurs MX. Vos certificats de messagerie sont authentifiés par le DNS.',
            'record'        => implode("\n", $lines),
            'suggested_dns' => null,
            'details'       => [
                'enabled' => true,
                'records' => $foundDane
            ]
        ];
    }

    return [
        'status'        => 'info',
        'title'         => 'DANE / TLSA',
        'message'       => 'DANE / TLSA n’est pas configuré. C’est une protection avancée facultative qui renforce l’authenticité des certificats de messagerie.',
        'record'        => '',
        'suggested_dns' => null,
        'details'       => [
            'enabled' => false
        ]
    ];
}


/**
 * Calcule le score de sécurité e-mail global sur 100 points.
 *
 * Barème équilibré sur 100 points :
 *   MX & Reverse DNS : ok=20, warning=10, error=0  (réception + PTR/FCrDNS)
 *   SPF              : ok=20, warning=10, error=0  (autorisation des expéditeurs)
 *   DKIM             : ok=20, warning=10, error=0  (signature cryptographique)
 *   DMARC            : reject=20, quarantine=16, none=10, warning=8, error=0 (politique anti-usurpation)
 *   Listes Noires RBL: ok=10, error=0              (réputation anti-spam des IPs)
 *   DNSSEC           : ok=5                        (sécurité de la zone DNS)
 *   MTA-STS ou DANE  : ok=5                        (chiffrement garanti inter-serveurs)
 *
 * Total maximal : 20 + 20 + 20 + 20 + 10 + 5 + 5 = 100 points.
 *
 * @param array $results Tableau des résultats de tous les tests.
 * @return int           Score de 0 à 100.
 */
function calculateScore(array $results): int
{
    $score = 0;

    // MX (20 pts max) : présence et qualité des serveurs de réception.
    if ($results['mx']['status'] === 'ok') {
        $score += 20;
    } elseif ($results['mx']['status'] === 'warning') {
        $score += 10;
    }

    // SPF (20 pts max) : protection contre l'usurpation d'identité des expéditeurs.
    if ($results['spf']['status'] === 'ok') {
        $score += 20;
    } elseif ($results['spf']['status'] === 'warning') {
        $score += 10;
    }

    // DKIM (20 pts max) : signature cryptographique des emails sortants.
    if ($results['dkim']['status'] === 'ok') {
        $score += 20;
    } elseif ($results['dkim']['status'] === 'warning') {
        $score += 10;
    }

    // DMARC (20 pts max) : politique de traitement des emails non authentifiés.
    if ($results['dmarc']['status'] === 'ok') {
        $policy = $results['dmarc']['details']['tags']['p'] ?? '';
        if ($policy === 'reject') {
            $score += 20;
        } elseif ($policy === 'quarantine') {
            $score += 16;
        } else {
            $score += 10; // p=none
        }
    } elseif ($results['dmarc']['status'] === 'warning') {
        $score += 8;
    }

    // Listes Noires / RBL (10 pts max) : réputation des IPs des serveurs MX.
    if (isset($results['rbl']) && $results['rbl']['status'] === 'ok') {
        $score += 10;
    }

    // DNSSEC (5 pts max) : protection cryptographique de la zone DNS.
    if (isset($results['dnssec']) && $results['dnssec']['status'] === 'ok') {
        $score += 5;
    }

    // Chiffrement garanti (MTA-STS ou DANE) (5 pts max).
    $hasMtaSts = isset($results['mtasts']) && $results['mtasts']['status'] === 'ok';
    $hasDane   = isset($results['dane']) && $results['dane']['status'] === 'ok';
    if ($hasMtaSts || $hasDane) {
        $score += 5;
    }

    return $score;
}


/**
 * EXÉCUTION PRINCIPALE — Lance tous les tests et retourne le rapport JSON complet.
 */



// -----------------------------------------------------------------------------
// ROUTAGE : TRAITEMENT POST / AJAX OU AFFICHAGE DU FORMULAIRE HTML
// -----------------------------------------------------------------------------
$isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');
if ($isPost) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');

    // Honeypot anti-bot
    if (!empty($_POST['website_url_hp'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Requête invalide.']);
        exit;
    }

    $domain   = sanitizeDomain((string)($_POST['domain'] ?? ''));
    $selector = sanitizeSelector((string)($_POST['selector'] ?? ''));

    if ($domain === '' || strlen($domain) > 253 || !preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $domain)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Le domaine saisi n’est pas valide.']);
        exit;
    }

    $dmarcResult = checkDmarc($domain);
    $mxResult    = checkMx($domain);
    $mxServers   = $mxResult['details']['servers'] ?? [];

    $results = [
        'mx'     => $mxResult,
        'spf'    => checkSpf($domain),
        'dkim'   => checkDkim($domain, $selector),
        'dmarc'  => $dmarcResult,
        'rbl'    => checkRbl($mxServers),
        'dnssec' => checkDnssec($domain),
        'bimi'   => checkBimi($domain, $dmarcResult),
        'dane'   => checkDane($mxServers),
        'mtasts' => checkMtaSts($domain),
        'tlsrpt' => checkTlsRpt($domain)
    ];

    $errors       = 0;
    $warnings     = 0;
    $suggestedDns = [];

    foreach ($results as $k => $result) {
        if ($result['status'] === 'error') {
            $errors++;
        } elseif ($result['status'] === 'warning') {
            $warnings++;
        }
        if (!empty($result['suggested_dns'])) {
            $suggestedDns[$k] = array_merge($result['suggested_dns'], [
                'category' => $result['title']
            ]);
        }
    }

    $globalStatus = $errors > 0 ? 'error' : ($warnings > 0 ? 'warning' : 'ok');
    $score        = calculateScore($results);

    echo json_encode([
        'success'       => true,
        'domain'        => $domain,
        'score'         => $score,
        'status'        => $globalStatus,
        'summary'       => [
            'errors'   => $errors,
            'warnings' => $warnings
        ],
        'results'       => $results,
        'suggested_dns' => $suggestedDns
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
?><!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Sécurité E-mail & DNS (MX, SPF, DKIM, DMARC, RBL, DNSSEC, BIMI, DANE, MTA-STS, TLS-RPT) — Thierry Laval</title>
    <meta name="description" content="Audit complet et analyse approfondie de la configuration email DNS : MX, SPF, DKIM, DMARC, RBL, DNSSEC, BIMI, DANE, MTA-STS et TLS-RPT.">
    <style>
        body {
            margin: 0;
            padding: 30px 15px;
            background: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            color: #0f172a;
        }
        .dmc-standalone-wrapper {
            max-width: 1040px;
            margin: 0 auto;
        }
        .dmc-standalone-brand {
            text-align: center;
            margin-bottom: 25px;
        }
        .dmc-standalone-brand h1 {
            font-size: 28px;
            font-weight: 800;
            color: #1e3a8a;
            margin: 0 0 8px 0;
        }
        .dmc-standalone-brand p {
            font-size: 15px;
            color: #64748b;
            margin: 0;
        }
    </style>
</head>
<body>
<div class="dmc-standalone-wrapper">
    <div class="dmc-standalone-brand">
        <h1>🛡️ Audit de Sécurité E-mail & DNS</h1>
        <p>Vérifiez la configuration, la délivrabilité et la conformité DNS de votre nom de domaine.</p>
    </div>
<div id="dns-mail-checker">

    <div class="dmc-header">

        <p>
            Vérifiez simplement la configuration email de votre domaine :
            MX, SPF, DKIM, DMARC, Reverse DNS, MTA-STS et TLS-RPT.
        </p>

        <div class="dmc-intro">
            <strong>À quoi sert ce test ?</strong>
            <p>
                Lorsque vous envoyez un email, plusieurs mécanismes permettent
                de vérifier que le message vient bien de votre domaine et
                d'améliorer sa délivrabilité.
            </p>
            <p>
                Ce test lit uniquement les informations DNS publiques de votre
                domaine. Il n'envoie aucun email.
            </p>
        </div>
    </div>

    <form id="dmc-form">

        <div style="display:none;" aria-hidden="true">
            <input type="text" name="website_url_hp" tabindex="-1" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">
        </div>

        <div class="dmc-fields">

            <div class="dmc-field">
                <label for="dmc-domain">
                    Domaine
                </label>

                <input
                    type="text"
                    id="dmc-domain"
                    name="domain"
                    placeholder="exemple.fr"
                    autocomplete="off"
                    required
                >
            </div>

            <div class="dmc-field">
                <label for="dmc-selector">
                    Sélecteur DKIM
                    <span>(facultatif)</span>
                </label>

                <input
                    type="text"
                    id="dmc-selector"
                    name="selector"
                    placeholder="selector1"
                    autocomplete="off"
                >

                <small>
                    Si vous connaissez le sélecteur DKIM utilisé par votre
                    messagerie, indiquez-le ici.
                </small>
            </div>

            <button
                type="submit"
                id="dmc-submit"
            >
                Tester
            </button>

        </div>

    </form>

    <div
        id="dmc-loading"
        style="display:none;"
    >
        Analyse de la configuration DNS en cours…
    </div>

    <div
        id="dmc-error"
        class="dmc-error"
        style="display:none;"
    ></div>

    <div
        id="dmc-results"
        style="display:none;"
    ></div>

    <div
        id="dmc-glossary"
        style="display:none;"
    >

        <div class="dmc-glossary-title">
            Comprendre les principaux termes
        </div>

        <div class="dmc-glossary-grid">

            <div>
                <strong>DNS</strong>
                <p>
                    Le DNS est l'annuaire d'Internet. Il permet notamment
                    d'indiquer quels serveurs sont responsables des emails
                    d'un domaine.
                </p>
            </div>

            <div>
                <strong>MX</strong>
                <p>
                    Les enregistrements MX indiquent quels serveurs doivent
                    recevoir les emails destinés à votre domaine.
                </p>
            </div>

            <div>
                <strong>SPF</strong>
                <p>
                    SPF indique quels serveurs ou services sont autorisés
                    à envoyer des emails pour votre domaine.
                </p>
            </div>

            <div>
                <strong>DKIM</strong>
                <p>
                    DKIM ajoute une signature cryptographique aux emails
                    afin que le serveur destinataire puisse vérifier
                    qu'ils n'ont pas été modifiés.
                </p>
            </div>

            <div>
                <strong>DMARC</strong>
                <p>
                    DMARC indique aux serveurs destinataires quoi faire
                    lorsqu'un email ne passe pas correctement les contrôles
                    SPF et DKIM.
                </p>
            </div>

            <div>
                <strong>Reverse DNS</strong>
                <p>
                    Le reverse DNS permet de retrouver le nom associé à
                    une adresse IP. Il est notamment utilisé dans la
                    réputation des serveurs email.
                </p>
            </div>

            <div>
                <strong>MTA-STS</strong>
                <p>
                    MTA-STS permet de demander aux serveurs email d'utiliser
                    une connexion TLS sécurisée lorsqu'ils communiquent
                    avec votre domaine.
                </p>
            </div>

            <div>
                <strong>TLS-RPT</strong>
                <p>
                    TLS-RPT permet de recevoir des rapports concernant
                    les problèmes rencontrés lors des connexions TLS
                    entre serveurs email.
                </p>
            </div>

        </div>

    </div>

</div>


<style>

#dns-mail-checker {
    max-width: 100%;
    font-family: inherit;
    color: #1f2937;
}

#dns-mail-checker * {
    box-sizing: border-box;
}

.dmc-header {
    margin-bottom: 28px;
}

.dmc-header h2 {
    margin: 0 0 10px;
    font-size: 30px;
    line-height: 1.2;
}

.dmc-header > p {
    margin: 0;
    opacity: .75;
    line-height: 1.6;
}

.dmc-intro {
    margin-top: 22px;
    padding: 20px;
    border-radius: 10px;
    background: #eafff9;
    border: 1px solid #e2e8f0;
    line-height: 1.6;
}

.dmc-intro p {
    margin: 8px 0 0;
}

.dmc-fields {
    display: grid;
    grid-template-columns: 1fr 1fr auto;
    gap: 15px;
    align-items: start;
}

.dmc-field label {
    display: block;
    margin-bottom: 7px;
    font-weight: 600;
}

.dmc-field {
    display: flex;
    flex-direction: column;
}

.dmc-field label span {
    font-weight: 400;
    opacity: .6;
    font-size: .9em;
}

.dmc-field small {
    display: block;
    margin-top: 6px;
    font-size: 12px;
    line-height: 1.4;
    opacity: .65;
}

.dmc-field input {
    width: 100%;
    height: 48px;
    padding: 0 14px;
    border: 1px solid #d6dbe1;
    border-radius: 7px;
    background: #fff;
    font-size: 16px;
}

.dmc-field input:focus {
    outline: none;
    border-color: #2271b1;
    box-shadow: 0 0 0 2px rgba(34,113,177,.10);
}

#dmc-submit {
    height: 48px;
    padding: 0 28px;
    border: 0;
    border-radius: 7px;
    background: #2271b1;
    color: #fff;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
}

#dmc-submit {
    height: 48px;
    align-self: start;
    margin-top: 25px;
    padding: 0 28px;
    border: 0;
    border-radius: 7px;
    background: #2271b1;
    color: #fff;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
}

#dmc-submit:hover {
    opacity: .9;
}

#dmc-submit:disabled {
    opacity: .5;
    cursor: wait;
}

#dmc-loading {
    margin-top: 25px;
    padding: 18px;
    border-radius: 8px;
    background: #f1f5f9;
    text-align: center;
}

.dmc-error {
    margin-top: 25px;
    padding: 15px;
    border-radius: 8px;
    background: #fef2f2;
    border: 1px solid #fecaca;
    color: #b91c1c;
    line-height: 1.5;
}

.dmc-summary {
    margin-top: 30px;
    padding: 24px;
    border-radius: 12px;
    border: 1px solid;
}

.dmc-summary-ok {
    background: #ecfdf3;
    border-color: #bbf7d0;
}

.dmc-summary-warning {
    background: #fff7ed;
    border-color: #fed7aa;
}

.dmc-summary-error {
    background: #fef2f2;
    border-color: #fecaca;
}

.dmc-summary-title {
    font-size: 22px;
    font-weight: 700;
    margin-bottom: 8px;
}

.dmc-summary-text {
    line-height: 1.6;
}

.dmc-summary-domain {
    margin-top: 8px;
    font-family: monospace;
    font-weight: 600;
}

.dmc-summary-counts {
    margin-top: 15px;
    font-size: 14px;
}

.dmc-summary-explanation {
    margin-top: 18px;
    padding-top: 18px;
    border-top: 1px solid rgba(0,0,0,.10);
    line-height: 1.6;
}

.dmc-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 18px;
    margin-top: 20px;
}

.dmc-card {
    border: 1px solid #dfe4ea;
    border-radius: 12px;
    overflow: hidden;
    background: #fff;
}

.dmc-card-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 16px;
    border-bottom: 1px solid #e5e7eb;
    font-weight: 700;
}

.dmc-icon {
    flex: 0 0 30px;
    width: 30px;
    height: 30px;
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
}

.dmc-icon-ok {
    background: #dcfce7;
    color: #15803d;
}

.dmc-icon-warning {
    background: #ffedd5;
    color: #c2410c;
}

.dmc-icon-error {
    background: #fee2e2;
    color: #b91c1c;
}

.dmc-card-title {
    flex: 1;
}

.dmc-badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 5px;
    font-size: 12px;
    font-weight: 600;
    white-space: nowrap;
}

.dmc-badge-ok {
    background: #dcfce7;
    color: #15803d;
}

.dmc-badge-warning {
    background: #ffedd5;
    color: #c2410c;
}

.dmc-badge-error {
    background: #fee2e2;
    color: #b91c1c;
}

.dmc-card-body {
    padding: 18px;
}

.dmc-simple-explanation {
    margin-bottom: 18px;
    line-height: 1.6;
}

.dmc-simple-explanation strong {
    display: block;
    margin-bottom: 5px;
}

.dmc-why {
    margin: 15px 0;
    padding: 14px;
    border-radius: 8px;
    background: #f8fafc;
    border: 1px solid #e5e7eb;
    line-height: 1.55;
}

.dmc-meaning {
    margin: 15px 0;
    padding: 14px;
    border-radius: 8px;
    line-height: 1.55;
}

.dmc-meaning-ok {
    background: #f0fdf4;
}

.dmc-meaning-warning {
    background: #fff7ed;
}

.dmc-meaning-error {
    background: #fef2f2;
}

.dmc-recommendation {
    margin: 15px 0;
    padding: 14px;
    border-left: 4px solid #2271b1;
    background: #f8fafc;
    line-height: 1.55;
}

.dmc-record-title {
    margin-top: 18px;
    margin-bottom: 7px;
    font-size: 13px;
    font-weight: 600;
}

.dmc-record-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 18px;
    margin-bottom: 7px;
}

.dmc-btn-copy {
    padding: 3px 8px;
    border-radius: 4px;
    border: 1px solid #d1d5db;
    background: #f3f4f6;
    color: #374151;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s ease;
}

.dmc-btn-copy:hover {
    background: #e5e7eb;
}

.dmc-btn-copy.copied {
    background: #dcfce7;
    border-color: #86efac;
    color: #15803d;
}

.dmc-record {
    padding: 12px;
    border-radius: 6px;
    background: #111827;
    color: #e5e7eb;
    font-family: monospace;
    font-size: 13px;
    line-height: 1.5;
    word-break: break-all;
}

.dmc-suggested-box {
    margin-top: 25px;
    padding: 20px;
    border-radius: 10px;
    background: #f0fdfa;
    border: 1px solid #ccfbf1;
}

.dmc-suggested-title {
    font-size: 17px;
    font-weight: 700;
    color: #0f766e;
    margin-bottom: 12px;
}

.dmc-suggested-item {
    background: #fff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 14px;
    margin-bottom: 10px;
}

.dmc-suggested-meta {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
    font-size: 13px;
    font-weight: 600;
}

.dmc-suggested-badge {
    background: #0f766e;
    color: #fff;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
}

.dmc-suggested-note {
    margin-top: 6px;
    font-size: 12px;
    color: #64748b;
}

.dmc-summary-score {
    margin-top: 10px;
    font-weight: 700;
    font-size: 15px;
    color: #1e293b;
}

.dmc-details {
    margin-top: 18px;
    border-top: 1px solid #e5e7eb;
    padding-top: 15px;
}

.dmc-details summary {
    cursor: pointer;
    font-weight: 600;
}

.dmc-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
    margin-top: 12px;
}

.dmc-table th,
.dmc-table td {
    padding: 9px 7px;
    border-bottom: 1px solid #e5e7eb;
    text-align: left;
    vertical-align: top;
}

.dmc-table th {
    font-weight: 600;
    width: 42%;
}

.dmc-list {
    margin: 10px 0 0;
    padding-left: 20px;
}

.dmc-list li {
    margin-bottom: 5px;
}

.dmc-dkim-selector {
    margin-top: 12px;
    padding: 12px;
    border-radius: 7px;
    background: #f8fafc;
    border: 1px solid #e5e7eb;
}

.dmc-glossary {
    margin-top: 35px;
    padding: 25px;
    border-radius: 12px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
}

.dmc-glossary-title {
    font-size: 21px;
    font-weight: 700;
    margin-bottom: 20px;
}

.dmc-glossary-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
}

.dmc-glossary-grid > div {
    padding-bottom: 15px;
}

.dmc-glossary-grid strong {
    display: block;
    margin-bottom: 5px;
}

.dmc-glossary-grid p {
    margin: 0;
    line-height: 1.55;
    opacity: .8;
}

@media (max-width: 800px) {

    .dmc-fields {
        grid-template-columns: 1fr;
    }

    #dmc-submit {
        width: 100%;
    }

    .dmc-grid,
    .dmc-glossary-grid {
        grid-template-columns: 1fr;
    }

    .dmc-card-header {
        flex-wrap: wrap;
    }

}

.dmc-icon-info {
    background: #e0f2fe;
    color: #0369a1;
}

.dmc-badge-info {
    background: #e0f2fe;
    color: #0369a1;
}

.dmc-meaning-info {
    background: #f0f9ff;
    border-left: 4px solid #0284c7;
}

.dmc-provider-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-radius: 6px;
    color: #166534;
    font-size: 13px;
    margin-bottom: 14px;
}

.dmc-btn-print {
    padding: 6px 14px;
    border-radius: 6px;
    border: 1px solid #cbd5e1;
    background: #fff;
    color: #334155;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: all 0.2s ease;
}

.dmc-btn-print:hover {
    background: #f8fafc;
    border-color: #94a3b8;
    color: #0f172a;
}

.dmc-bimi-preview {
    margin-top: 12px;
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 12px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
}

.dmc-print-header {
    display: none;
}

@media print {
    body {
        background: #fff !important;
        color: #000 !important;
        font-size: 10pt !important;
        line-height: 1.4 !important;
    }

    /* Éléments masqués à l'impression */
    #dmc-form,
    .dmc-header,
    .dmc-intro,
    .dmc-btn-copy,
    .dmc-btn-print,
    #dmc-loading,
    #dmc-error,
    #dmc-glossary,
    header, footer, nav,
    .elementor-location-header,
    .elementor-location-footer {
        display: none !important;
    }

    /* En-tête du rapport imprimé */
    .dmc-print-header {
        display: block !important;
        margin-bottom: 16px;
        padding-bottom: 10px;
        border-bottom: 2px solid #0284c7;
    }
    .dmc-print-header h1,
    .dmc-print-header h2 {
        font-size: 14pt !important;
        margin: 0 0 3px 0 !important;
    }
    .dmc-print-header p,
    .dmc-print-header small {
        font-size: 9pt !important;
        color: #555 !important;
        margin: 0 !important;
    }

    /* Taille du score */
    .dmc-score-wrap { font-size: 11pt !important; }
    .dmc-score-circle,
    .dmc-score-wrap strong { font-size: 13pt !important; }

    /* Cartes résultats */
    .dmc-card {
        page-break-inside: avoid;
        break-inside: avoid;
        border: 1px solid #cbd5e1 !important;
        box-shadow: none !important;
        margin-bottom: 12px !important;
        padding: 10px !important;
    }
    .dmc-card h2,
    .dmc-card h3,
    .dmc-card-title {
        font-size: 11pt !important;
        margin: 0 0 4px 0 !important;
    }
    .dmc-card p,
    .dmc-card li,
    .dmc-card td,
    .dmc-card th {
        font-size: 9pt !important;
        line-height: 1.3 !important;
    }

    /* Blocs de code et enregistrements DNS — réduits et word-wrap forcé */
    .dmc-record,
    .dmc-code,
    pre, code {
        font-size: 7.5pt !important;
        font-family: 'Courier New', Courier, monospace !important;
        white-space: pre-wrap !important;
        word-break: break-all !important;
        overflow-wrap: break-word !important;
        background: #f1f5f9 !important;
        border: 1px solid #e2e8f0 !important;
        padding: 4px 6px !important;
        display: block !important;
        border-radius: 3px !important;
        max-width: 100% !important;
    }

    /* Tableaux */
    table { width: 100% !important; border-collapse: collapse !important; font-size: 8.5pt !important; }
    th, td { border: 1px solid #cbd5e1 !important; padding: 3px 5px !important; font-size: 8.5pt !important; }

    /* Détails techniques ouverts */
    .dmc-details { display: block !important; }
    .dmc-details summary { display: none !important; }
    .dmc-details > *:not(summary) { display: block !important; }

    /* Grille : colonne unique */
    .dmc-grid { display: block !important; }

    /* Badges (gardent la couleur) */
    .dmc-badge,
    .dmc-badge-ok,
    .dmc-badge-warning,
    .dmc-badge-error,
    .dmc-badge-info,
    .dmc-provider-badge {
        font-size: 8pt !important;
        padding: 1px 4px !important;
        print-color-adjust: exact !important;
        -webkit-print-color-adjust: exact !important;
    }

    /* Suggestions DNS */
    .dmc-suggested-dns {
        background: #f0fdf4 !important;
        border: 1px solid #bbf7d0 !important;
        padding: 6px !important;
        font-size: 8.5pt !important;
    }

    /* Dimensions de la page A4 */
    @page {
        margin: 1.5cm 1.8cm;
        size: A4 portrait;
    }
}

</style>


<script>

(function () {

    const ENDPOINT = window.location.href.split('?')[0];

    const form =
        document.getElementById('dmc-form');

    const domainInput =
        document.getElementById('dmc-domain');

    const selectorInput =
        document.getElementById('dmc-selector');

    const submit =
        document.getElementById('dmc-submit');

    const loading =
        document.getElementById('dmc-loading');

    const errorBox =
        document.getElementById('dmc-error');

    const resultsBox =
        document.getElementById('dmc-results');

    const glossary =
        document.getElementById('dmc-glossary');


    window.dmcCopy = function (btn, text) {
        if (!navigator.clipboard) {
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        } else {
            navigator.clipboard.writeText(text);
        }
        const oldText = btn.textContent;
        btn.textContent = 'Copié !';
        btn.classList.add('copied');
        setTimeout(function () {
            btn.textContent = oldText;
            btn.classList.remove('copied');
        }, 2000);
    };

    window.dmcPrintReport = function () {
        const resultsEl = document.getElementById('dmc-results');
        if (!resultsEl) return;

        const clone = resultsEl.cloneNode(true);

        const buttons = clone.querySelectorAll('.dmc-btn-print, .dmc-btn-copy');
        for (let i = 0; i < buttons.length; i++) {
            buttons[i].remove();
        }

        const details = clone.querySelectorAll('details');
        for (let i = 0; i < details.length; i++) {
            details[i].setAttribute('open', 'open');
        }

        const domainVal = domainInput && domainInput.value ? domainInput.value.trim() : 'rapport';

        const printStyles = `
            @page {
                size: A4 portrait;
                margin: 12mm 15mm;
            }
            * {
                box-sizing: border-box;
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
            }
            body {
                margin: 0;
                padding: 0;
                background: #ffffff;
                color: #1e293b;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                font-size: 11px;
                line-height: 1.45;
            }
            .dmc-print-header {
                display: block !important;
                margin-bottom: 14px;
                padding-bottom: 8px;
                border-bottom: 2px solid #0284c7;
            }
            .dmc-summary {
                padding: 12px;
                border-radius: 6px;
                margin-bottom: 14px;
                border: 1px solid #cbd5e1;
                page-break-inside: avoid;
                break-inside: avoid;
            }
            .dmc-summary-ok { background: #f0fdf4; border-color: #86efac; }
            .dmc-summary-warning { background: #fffbeb; border-color: #fde68a; }
            .dmc-summary-error { background: #fef2f2; border-color: #fecaca; }
            .dmc-summary-title { font-size: 14px; font-weight: 700; margin-bottom: 3px; }
            .dmc-summary-domain { font-size: 12px; font-weight: 600; color: #0f172a; margin-bottom: 4px; }
            .dmc-summary-counts { font-size: 10.5px; color: #475569; margin-bottom: 4px; }
            .dmc-summary-score { font-size: 12.5px; font-weight: 700; color: #1e3a8a; }
            .dmc-summary-explanation { font-size: 10.5px; line-height: 1.4; color: #334155; margin-top: 8px; padding-top: 6px; border-top: 1px dashed #cbd5e1; }

            .dmc-suggested-box {
                padding: 10px 12px;
                background: #f0fdf4;
                border: 1px solid #86efac;
                border-radius: 6px;
                margin-bottom: 14px;
                page-break-inside: avoid;
                break-inside: avoid;
            }
            .dmc-suggested-title { font-size: 12px; font-weight: 700; color: #166534; margin-bottom: 4px; }
            .dmc-suggested-item { margin-bottom: 8px; }
            .dmc-suggested-item:last-child { margin-bottom: 0; }
            .dmc-suggested-meta { font-size: 10px; font-weight: 600; color: #334155; margin-bottom: 3px; }
            .dmc-suggested-badge { display: inline-block; padding: 1px 4px; font-size: 9px; background: #0f766e; color: #fff; border-radius: 3px; }
            .dmc-suggested-note { font-size: 9.5px; color: #15803d; margin-top: 2px; font-style: italic; }

            .dmc-grid { display: block; }
            .dmc-card {
                background: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 10px 12px;
                margin-bottom: 12px;
                page-break-inside: avoid;
                break-inside: avoid;
            }
            .dmc-card-header {
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 6px;
                padding-bottom: 4px;
                border-bottom: 1px solid #f1f5f9;
            }
            .dmc-icon {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 18px;
                height: 18px;
                border-radius: 50%;
                font-size: 10px;
                font-weight: 700;
            }
            .dmc-icon-ok { background: #dcfce7; color: #15803d; }
            .dmc-icon-warning { background: #fef3c7; color: #b45309; }
            .dmc-icon-error { background: #fee2e2; color: #b91c1c; }
            .dmc-icon-info { background: #e0f2fe; color: #0369a1; }

            .dmc-card-title { font-size: 12px; font-weight: 700; color: #0f172a; flex: 1; }
            .dmc-badge {
                padding: 1px 6px;
                font-size: 9px;
                font-weight: 600;
                border-radius: 4px;
            }
            .dmc-badge-ok { background: #dcfce7; color: #166534; }
            .dmc-badge-warning { background: #fef3c7; color: #92400e; }
            .dmc-badge-error { background: #fee2e2; color: #991b1b; }
            .dmc-badge-info { background: #e0f2fe; color: #075985; }

            .dmc-simple-explanation { margin-bottom: 5px; }
            .dmc-simple-explanation strong { font-size: 10px; color: #334155; }
            .dmc-simple-explanation div { font-size: 9.5px; color: #475569; margin-top: 1px; }

            .dmc-why {
                background: #f8fafc;
                border-left: 3px solid #94a3b8;
                padding: 4px 6px;
                margin-bottom: 5px;
                font-size: 9.5px;
                color: #475569;
            }
            .dmc-why strong { color: #1e293b; font-size: 10px; }

            .dmc-meaning {
                padding: 4px 6px;
                border-radius: 3px;
                margin-bottom: 5px;
                font-size: 9.5px;
            }
            .dmc-meaning strong { font-size: 10px; }
            .dmc-meaning-ok { background: #f0fdf4; border-left: 3px solid #22c55e; color: #166534; }
            .dmc-meaning-warning { background: #fffbeb; border-left: 3px solid #f59e0b; color: #854d0e; }
            .dmc-meaning-error { background: #fef2f2; border-left: 3px solid #ef4444; color: #991b1b; }
            .dmc-meaning-info { background: #f0f9ff; border-left: 3px solid #0284c7; color: #0369a1; }

            .dmc-recommendation {
                background: #eff6ff;
                border-left: 3px solid #3b82f6;
                padding: 4px 6px;
                margin-bottom: 5px;
                font-size: 9.5px;
                color: #1e40af;
            }
            .dmc-recommendation strong { font-size: 10px; }

            .dmc-record-header {
                margin-top: 6px;
                margin-bottom: 2px;
            }
            .dmc-record-title { font-size: 9.5px; font-weight: 600; color: #475569; }
            .dmc-record, pre, code {
                font-family: Consolas, "Courier New", monospace;
                font-size: 8px;
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 3px;
                padding: 4px 6px;
                color: #0f172a;
                word-break: break-all;
                white-space: pre-wrap;
                overflow-wrap: break-word;
                display: block;
                margin-bottom: 5px;
            }

            .dmc-provider-badge {
                display: inline-block;
                padding: 2px 6px;
                background: #f0fdf4;
                border: 1px solid #bbf7d0;
                border-radius: 3px;
                color: #166534;
                font-size: 9.5px;
                margin-bottom: 5px;
            }

            .dmc-details { display: block !important; margin-top: 6px; }
            .dmc-details summary { display: none !important; }
            .dmc-details > *:not(summary) { display: block !important; }

            .dmc-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 3px;
                margin-bottom: 5px;
                font-size: 9px;
            }
            .dmc-table th {
                background: #f1f5f9;
                border: 1px solid #cbd5e1;
                padding: 3px 5px;
                text-align: left;
                font-weight: 600;
            }
            .dmc-table td {
                border: 1px solid #e2e8f0;
                padding: 3px 5px;
            }
            .dmc-list {
                margin: 3px 0;
                padding-left: 16px;
                font-size: 9px;
            }
            .dmc-list li { margin-bottom: 2px; }
            .dmc-bimi-preview {
                margin-top: 8px;
                padding: 8px;
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .dmc-bimi-preview img {
                max-width: 48px;
                max-height: 48px;
            }
        `;

        let frame = document.getElementById('dmc-hidden-print-frame');
        if (frame) {
            frame.remove();
        }
        frame = document.createElement('iframe');
        frame.id = 'dmc-hidden-print-frame';
        frame.style.position = 'fixed';
        frame.style.right = '0';
        frame.style.bottom = '0';
        frame.style.width = '0';
        frame.style.height = '0';
        frame.style.border = '0';
        frame.style.visibility = 'hidden';
        document.body.appendChild(frame);

        const frameDoc = frame.contentWindow.document;
        frameDoc.open();
        frameDoc.write('<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">');
        frameDoc.write('<title>Audit Sécurité E-mail - ' + escapeHtml(domainVal) + '</title>');
        frameDoc.write('<style>' + printStyles + '</style>');
        frameDoc.write('</head><body>');
        frameDoc.write(clone.innerHTML);
        frameDoc.write('</body></html>');
        frameDoc.close();

        setTimeout(function () {
            try {
                frame.contentWindow.focus();
                frame.contentWindow.print();
            } catch (err) {
                window.print();
            }
            setTimeout(function () {
                if (frame && frame.parentNode) {
                    frame.parentNode.removeChild(frame);
                }
            }, 3000);
        }, 400);
    };

    function escapeHtml(value) {

        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }


    function statusIcon(status) {

        if (status === 'ok') {
            return '✓';
        }

        if (status === 'warning') {
            return '!';
        }

        if (status === 'info') {
            return 'ℹ';
        }

        return '×';
    }


    function statusLabel(status) {

        if (status === 'ok') {
            return 'OK';
        }

        if (status === 'warning') {
            return 'À surveiller';
        }

        if (status === 'info') {
            return 'Optionnel';
        }

        return 'Erreur';
    }


    function explanation(key) {

        const data = {

            mx: {
                importance: 'Indispensable',
                title: 'À quoi servent les MX ?',
                text:
                    'C’est l’adresse officielle de votre boîte aux lettres sur Internet. Les enregistrements MX indiquent aux autres serveurs où remettre les emails qui vous sont envoyés.',
                why:
                    'Sans MX, vous ne pouvez recevoir aucun email. Et si le nom du serveur MX ne correspond pas à son adresse IP (Reverse DNS / PTR), certains services comme Gmail ou Yahoo peuvent refuser de vous faire confiance.'
            },

            spf: {
                importance: 'Indispensable',
                title: 'À quoi sert le SPF ?',
                text:
                    'C’est la liste officielle des facteurs autorisés à distribuer des courriers pour votre domaine (par exemple : votre messagerie Google, Microsoft 365, ou votre serveur web).',
                why:
                    'Si un pirate tente d’envoyer des emails en usurpant votre nom, les serveurs destinataires vérifient votre SPF. S’il n’est pas dans la liste, le faux message est rejeté ou envoyé en spam. Attention : la norme limite le SPF à 10 recherches DNS maximum.'
            },

            dkim: {
                importance: 'Indispensable',
                title: 'À quoi sert DKIM ?',
                text:
                    'C’est comme un cachet de cire ou une signature manuscrite infalsifiable apposée sur chaque email que vous envoyez. Elle prouve que le message vient bien de vous et n’a pas été modifié en cours de route.',
                why:
                    'Les grands services de messagerie (Google, Yahoo, Outlook) exigent désormais une signature DKIM pour accepter vos emails directement dans la boîte de réception principale.'
            },

            dmarc: {
                importance: 'Indispensable',
                title: 'À quoi sert DMARC ?',
                text:
                    'C’est le chef d’orchestre de votre sécurité email. Il indique aux boîtes de réception la conduite à tenir si un email prétendant venir de vous échoue aux contrôles SPF et DKIM : le surveiller (p=none), l’isoler en spam (p=quarantine), ou le bloquer totalement (p=reject).',
                why:
                    'C’est la seule protection qui bloque net les escrocs voulant utiliser votre nom de domaine pour arnaquer vos clients ou vos proches.'
            },

            bimi: {
                importance: 'Optionnel / Marque',
                title: 'À quoi sert BIMI ?',
                text:
                    'BIMI permet d’afficher le logo officiel et vérifié de votre entreprise directement à côté de vos emails dans la boîte de réception de vos destinataires (Gmail, Apple Mail, Yahoo).',
                why:
                    'Cela améliore considérablement le taux d’ouverture de vos messages, rassure vos destinataires contre les faux courriers et renforce la visibilité de votre marque. Pour être actif, BIMI exige impérativement que votre politique DMARC soit en quarantaine (à 100%) ou en rejet.'
            },

            rbl: {
                importance: 'Indispensable',
                title: 'À quoi servent les Listes Noires (RBL) ?',
                text:
                    'Les RBL (Real-time Blackhole Lists) surveillent en temps réel les serveurs de messagerie émetteurs de spam ou compromis par des logiciels malveillants.',
                why:
                    'Si l’adresse IP de votre serveur de messagerie est inscrite sur une liste noire, vos emails légitimes seront systématiquement refusés ou dirigés vers le dossier spam par Gmail, Outlook et Yahoo.'
            },

            dnssec: {
                importance: 'Sécurité DNS',
                title: 'À quoi sert DNSSEC ?',
                text:
                    'DNSSEC ajoute une signature cryptographique infalsifiable à l’annuaire DNS de votre domaine.',
                why:
                    'Il empêche les cyberattaquants de détourner secrètement l’aiguillage de vos emails ou de falsifier vos règles de sécurité SPF et DMARC par empoisonnement de cache DNS.'
            },

            dane: {
                importance: 'Optionnel / Avancé',
                title: 'À quoi sert DANE / TLSA ?',
                text:
                    'DANE lie directement le certificat de chiffrement TLS de vos serveurs de messagerie à vos enregistrements DNS officiels.',
                why:
                    'C’est une alternative et un complément de haute sécurité à MTA-STS qui empêche tout piratage ou interception de vos échanges d’emails sécurisés.'
            },

            mtasts: {
                importance: 'Optionnel / Avancé',
                title: 'À quoi sert MTA-STS ?',
                text:
                    'C’est un cadenas blindé qui force le chiffrement sécurisé (TLS) entre les serveurs de messagerie pour empêcher toute interception d’emails sur le réseau.',
                why:
                    'C’est une protection très poussée utilisée par les grandes banques et institutions. Elle n’est PAS obligatoire pour le fonctionnement normal de vos emails et nécessite un serveur web dédié avec certificat SSL.'
            },

            tlsrpt: {
                importance: 'Optionnel / Avancé',
                title: 'À quoi sert TLS-RPT ?',
                text:
                    'C’est un carnet de bord automatisé qui vous prévient par email si un serveur distant a rencontré des difficultés de chiffrement lors d’un échange d’emails avec votre domaine.',
                why:
                    'Tout comme MTA-STS, c’est un outil facultatif de surveillance réservé aux administrateurs de très gros réseaux pour détecter des pannes techniques de chiffrement.'
            }

        };

        return data[key] || {
            importance: 'Contrôle DNS',
            title: 'À quoi sert ce contrôle ?',
            text: 'Ce contrôle analyse une partie de la configuration DNS de votre domaine.',
            why: 'Une configuration correcte contribue au bon fonctionnement et à la fiabilité de votre messagerie.'
        };
    }


    function resultMeaning(key, status) {

        const meanings = {

            mx: {
                ok:
                    'Vos serveurs de réception et leur adresse inverse (Reverse DNS) sont bien configurés. Votre messagerie est prête à recevoir les courriers.',
                warning:
                    'Les serveurs de réception existent, mais un problème a été détecté sur leur adresse inverse (Reverse DNS / PTR), ce qui peut impacter la réputation de votre domaine.',
                error:
                    'Aucun serveur MX n’a été trouvé, ou un conflit d’enregistrement CNAME sur la racine a été détecté.'
            },

            spf: {
                ok:
                    'Votre enregistrement SPF est unique, bien configuré et respecte la limite de requêtes DNS.',
                warning:
                    'Votre SPF existe, mais certains éléments méritent une attention (par exemple : limite des 10 recherches DNS qui approche, mécanisme déconseillé, ou politique neutre).',
                error:
                    'Le SPF est absent, en doublon ou mal configuré (par exemple avec +all qui autorise tout le monde à envoyer pour vous).'
            },

            dkim: {
                ok:
                    'Une ou plusieurs clés DKIM valides ont été trouvées pour signer vos messages.',
                warning:
                    'Aucun sélecteur DKIM courant n’a été détecté automatiquement. Si votre messagerie utilise un sélecteur sur mesure, saisissez-le dans le champ ci-dessus pour tester votre clé.',
                error:
                    'Le sélecteur DKIM demandé n’a pas permis de trouver une clé publique valide.'
            },

            dmarc: {
                ok:
                    'Un enregistrement DMARC protecteur est actif sur votre domaine.',
                warning:
                    'DMARC est présent mais est en mode surveillance (p=none) ou ne transmet pas de rapports (rua=). Vos emails ne sont pas encore bloqués en cas d’usurpation.',
                error:
                    'Aucun enregistrement DMARC n’est configuré. Votre domaine n’a aucune consigne de protection contre l’usurpation.'
            },

            bimi: {
                ok:
                    'Votre enregistrement BIMI est configuré et valide, et votre politique DMARC respecte les critères requis pour afficher votre logo.',
                warning:
                    'Un enregistrement BIMI est publié mais nécessite des ajustements (par exemple : politique DMARC trop souple, format du logo, ou absence de certificat VMC).',
                info:
                    'BIMI n’est pas configuré. C’est une option facultative réservée aux entreprises souhaitant afficher leur logo officiel dans les messageries.',
                error:
                    'L’enregistrement BIMI comporte une erreur de syntaxe.'
            },

            rbl: {
                ok:
                    'Excellente réputation : l’adresse IP de vos serveurs de messagerie est saine et ne figure sur aucune des listes noires réputées testées.',
                warning:
                    'Attention : une ou plusieurs adresses IP de vos serveurs de messagerie apparaissent sur une liste noire anti-spam.',
                error:
                    'Alerte réputation : vos serveurs de messagerie sont répertoriés sur une liste noire. Vos emails risquent fortement d’être rejetés ou mis en spam.',
                info:
                    'Aucune adresse IP de serveur de messagerie n’a pu être testée.'
            },

            dnssec: {
                ok:
                    'DNSSEC est actif : votre zone DNS est signée et protégée cryptographiquement contre les attaques d’usurpation et d’empoisonnement DNS.',
                info:
                    'DNSSEC n’est pas activé. Ce n’est pas bloquant pour vos envois d’emails, mais son activation chez votre Registrar renforce la sécurité de votre domaine.'
            },

            dane: {
                ok:
                    'DANE / TLSA est configuré : vos certificats de messagerie sont authentifiés directement par le DNS pour un chiffrement garanti.',
                info:
                    'DANE / TLSA n’est pas configuré. Il s’agit d’une sécurité avancée facultative utilisée par les institutions et infrastructures sensibles.'
            },

            mtasts: {
                ok:
                    'MTA-STS est actif et valide : vos connexions email sont protégées par un chiffrement strict forcé.',
                warning:
                    'MTA-STS n’est pas configuré. C’est tout à fait normal pour l’immense majorité des sites : ce n’est pas une panne et vos emails fonctionnent parfaitement sans lui.',
                error:
                    'La politique MTA-STS existe mais comporte des erreurs techniques dans sa déclaration HTTPS.'
            },

            tlsrpt: {
                ok:
                    'TLS-RPT est configuré et prêt à recevoir les rapports de chiffrement.',
                warning:
                    'TLS-RPT n’est pas configuré. C’est une option facultative qui n’a aucun impact négatif sur vos envois d’emails du quotidien.',
                error:
                    'La configuration TLS-RPT comporte une erreur.'
            }

        };

        return meanings[key] &&
               meanings[key][status]
            ? meanings[key][status]
            : 'Le test a terminé son analyse de cet élément.';
    }


    function recommendation(key, status) {

        if (status === 'ok' || status === 'info') {

            return {
                show: false,
                text: ''
            };
        }

        const recommendations = {

            mx:
                'Vérifiez dans la zone DNS de votre domaine que les serveurs MX correspondent bien au service de messagerie que vous utilisez, et assurez-vous qu’aucun CNAME n’est configuré sur la racine (@).',

            spf:
                'Vérifiez la liste des services autorisés à envoyer vos emails et assurez-vous qu’un seul enregistrement SPF est publié.',

            dkim:
                'Si votre messagerie utilise DKIM, récupérez le sélecteur dans la console d’administration de votre messagerie (Google, Microsoft 365, etc.) puis relancez le test avec ce sélecteur.',

            dmarc:
                'Publiez un enregistrement DMARC pour surveiller puis bloquer les faux emails envoyés avec votre nom de domaine.',

            bimi:
                'Si vous souhaitez afficher votre logo dans Gmail et Yahoo, publiez un enregistrement default._bimi avec votre logo au format SVG Tiny P.S. et assurez-vous que DMARC est au minimum en p=quarantine (pct=100) ou p=reject.',

            rbl:
                'Contactez votre hébergeur ou prestataire de messagerie pour demander le délistage de votre adresse IP ou pour qu’une nouvelle adresse IP saine vous soit attribuée.',

            dnssec:
                'Activez DNSSEC depuis l’espace client de votre bureau d’enregistrement de domaine (Registrar) pour sécuriser l’authenticité de votre zone DNS.',

            dane:
                'Aucune action requise. DANE est une sécurité facultative requérant DNSSEC et la publication d’enregistrements TLSA.',

            mtasts:
                'Aucune action requise. MTA-STS est une sécurité complémentaire réservée aux structures ayant des besoins de très haute sécurité (nécessite d’héberger un sous-domaine https://mta-sts avec un certificat SSL valide).',

            tlsrpt:
                'Aucune action requise. Si vous n’avez pas d’équipe dédiée pour analyser quotidiennement des rapports techniques de chiffrement, vous pouvez ignorer cet élément.'
        };

        return {
            show: true,
            text:
                recommendations[key] ||
                'Vérifiez la configuration DNS correspondante.'
        };
    }


    function renderCard(key, result) {

        const info =
            explanation(key);

        const meaning =
            resultMeaning(
                key,
                result.status
            );

        const advice =
            recommendation(
                key,
                result.status
            );

        let html = '';

        html +=
            '<div class="dmc-card">';

        html +=
            '<div class="dmc-card-header">';

        html +=
            '<span class="dmc-icon dmc-icon-' +
            escapeHtml(result.status) +
            '">' +
            statusIcon(result.status) +
            '</span>';

        html +=
            '<span class="dmc-card-title">' +
            escapeHtml(result.title) +
            (info.importance
                ? ' <span style="font-size:11px;font-weight:normal;opacity:0.65;margin-left:4px;">(' +
                  escapeHtml(info.importance) +
                  ')</span>'
                : '') +
            '</span>';

        html +=
            '<span class="dmc-badge dmc-badge-' +
            escapeHtml(result.status) +
            '">' +
            escapeHtml(statusLabel(result.status)) +
            '</span>';

        html += '</div>';

        html += '<div class="dmc-card-body">';


        /*
         * Explication débutant
         */

        html +=
            '<div class="dmc-simple-explanation">';

        html +=
            '<strong>' +
            escapeHtml(info.title) +
            '</strong>';

        html +=
            '<div>' +
            escapeHtml(info.text) +
            '</div>';

        html += '</div>';


        /*
         * Pourquoi
         */

        html +=
            '<div class="dmc-why">' +
            '<strong>Pourquoi est-ce important ?</strong><br>' +
            escapeHtml(info.why) +
            '</div>';


        /*
         * Interprétation du résultat
         */

        html +=
            '<div class="dmc-meaning dmc-meaning-' +
            escapeHtml(result.status) +
            '">' +

            '<strong>Que signifie votre résultat ?</strong><br>' +

            escapeHtml(meaning) +

            '</div>';


        /*
         * Recommandation
         */

        if (advice.show) {

            html +=
                '<div class="dmc-recommendation">' +

                '<strong>Que faire ?</strong><br>' +

                escapeHtml(advice.text) +

                '</div>';
        }


        /*
         * Enregistrement DNS
         */

        if (result.record) {

            html +=
                '<div class="dmc-record-header">' +
                '<div class="dmc-record-title">' +
                'Enregistrement DNS détecté' +
                '</div>' +
                '<button type="button" class="dmc-btn-copy" onclick="dmcCopy(this, ' +
                JSON.stringify(result.record) +
                ')">Copier</button>' +
                '</div>';

            html +=
                '<div class="dmc-record">' +
                escapeHtml(result.record) +
                '</div>';
        }

        if (result.suggested_dns) {

            html +=
                '<div class="dmc-record-header" style="margin-top:14px;">' +
                '<div class="dmc-record-title" style="color:#0f766e;">⚡ Enregistrement recommandé à publier</div>' +
                '<button type="button" class="dmc-btn-copy" onclick="dmcCopy(this, ' +
                JSON.stringify(result.suggested_dns.value) +
                ')">Copier la valeur</button>' +
                '</div>';

            html +=
                '<div class="dmc-suggested-meta" style="font-size:12px;margin-bottom:4px;">' +
                '<span class="dmc-suggested-badge">' +
                escapeHtml(result.suggested_dns.type) +
                '</span> ' +
                '<span>Hôte : <code>' +
                escapeHtml(result.suggested_dns.name) +
                '</code></span>' +
                '</div>';

            html +=
                '<div class="dmc-record" style="background:#042f2e;color:#ccfbf1;">' +
                escapeHtml(result.suggested_dns.value) +
                '</div>';

            if (result.suggested_dns.note) {
                html +=
                    '<div class="dmc-suggested-note">💡 ' +
                    escapeHtml(result.suggested_dns.note) +
                    '</div>';
            }
        }


        /*
         * Détails techniques
         */

        html +=
            '<details class="dmc-details">';

        html +=
            '<summary>Afficher les détails techniques</summary>';


        /*
         * MX
         */

        if (
            key === 'mx' &&
            result.details &&
            result.details.servers
        ) {

            if (result.details.provider) {
                html +=
                    '<div class="dmc-provider-badge">' +
                    '📬 Messagerie détectée : <strong>' +
                    escapeHtml(result.details.provider.name) +
                    '</strong></div>';
            }

            html +=
                '<table class="dmc-table">';

            html +=
                '<tr>' +
                '<th>Priorité</th>' +
                '<th>Serveur</th>' +
                '<th>Reverse DNS</th>' +
                '</tr>';

            result.details.servers.forEach(
                function (server) {

                    let reverse = '';

                    if (server.addresses) {

                        server.addresses.forEach(
                            function (address) {

                                let fcrdnsBadge = '';
                                if (address.has_ptr && address.fcrdns !== undefined) {
                                    fcrdnsBadge = address.fcrdns
                                        ? ' <span class="dmc-badge dmc-badge-ok">✓ FCrDNS</span>'
                                        : ' <span class="dmc-badge dmc-badge-warning">! FCrDNS non confirmé</span>';
                                }

                                reverse +=
                                    '<div>' +
                                    escapeHtml(address.ip) +
                                    ' → ' +

                                    (
                                        address.ptr
                                            ? escapeHtml(address.ptr) + fcrdnsBadge
                                            : '<span class="dmc-badge dmc-badge-warning">PTR absent</span>'
                                    ) +

                                    '</div>';
                            }
                        );
                    }

                    html +=
                        '<tr>' +
                        '<td>' +
                        escapeHtml(
                            server.priority
                        ) +
                        '</td>' +

                        '<td>' +
                        escapeHtml(
                            server.host
                        ) +
                        '</td>' +

                        '<td>' +
                        reverse +
                        '</td>' +

                        '</tr>';
                }
            );

            html += '</table>';
        }


        /*
         * SPF
         */

        if (
            key === 'spf' &&
            result.details
        ) {

            html +=
                '<table class="dmc-table">';

            html +=
                '<tr>' +
                '<th>Recherches DNS estimées</th>' +
                '<td>' +
                escapeHtml(
                    result.details.lookups
                ) +
                ' / ' +
                escapeHtml(
                    result.details.limit
                ) +
                '</td>' +
                '</tr>';

            html +=
                '<tr>' +
                '<th>Directive finale</th>' +
                '<td>' +
                escapeHtml(
                    result.details.all ||
                    'non définie'
                ) +
                '</td>' +
                '</tr>';

            html += '</table>';

            if (
                result.details.mechanisms
            ) {

                html +=
                    '<details class="dmc-details">' +
                    '<summary>Voir les mécanismes SPF</summary>' +
                    '<ul class="dmc-list">';

                result.details.mechanisms.forEach(
                    function (item) {

                        html +=
                            '<li>' +
                            escapeHtml(
                                item.qualifier +
                                item.name +
                                (
                                    item.value
                                        ? ':' +
                                          item.value
                                        : ''
                                )
                            ) +
                            (item.lookups ? ' <span style="opacity:.7;font-size:11px;">(+1 DNS)</span>' : '') +
                            '</li>';
                    }
                );

                html +=
                    '</ul></details>';
            }

            if (
                result.details.includes_tree &&
                result.details.includes_tree.length > 0
            ) {

                html +=
                    '<details class="dmc-details" style="margin-top:8px;">' +
                    '<summary>Voir l’arborescence des inclusions (includes)</summary>' +
                    '<ul class="dmc-list">';

                result.details.includes_tree.forEach(
                    function (inc) {
                        html +=
                            '<li><strong>' +
                            escapeHtml(inc.parent) +
                            '</strong> &rarr; include:<strong>' +
                            escapeHtml(inc.include) +
                            '</strong> (' +
                            escapeHtml(inc.status) +
                            ')</li>';
                    }
                );

                html +=
                    '</ul></details>';
            }
        }


        /*
         * DKIM
         */

        if (
            key === 'dkim' &&
            result.details
        ) {

            if (
                result.details.selectors
            ) {

                html +=
                    '<table class="dmc-table">';

                html +=
                    '<tr>' +
                    '<th>Sélecteur</th>' +
                    '<th>Type</th>' +
                    '<th>Taille</th>' +
                    '<th>État</th>' +
                    '</tr>';

                result.details.selectors.forEach(
                    function (item) {

                        let bitsLabel = 'N/A';
                        if (item.key_bits) {
                            bitsLabel = escapeHtml(item.key_bits) + ' bits';
                            if (item.key_bits === 1024) {
                                bitsLabel += ' <span class="dmc-badge dmc-badge-warning" style="font-size:10px;">déprécié</span>';
                            }
                        }

                        html +=
                            '<tr>' +

                            '<td>' +
                            escapeHtml(
                                item.selector
                            ) +
                            '</td>' +

                            '<td>' +
                            escapeHtml(
                                item.tags &&
                                item.tags.k
                                    ? item.tags.k
                                    : 'rsa'
                            ) +
                            '</td>' +

                            '<td>' +
                            bitsLabel +
                            '</td>' +

                            '<td>' +

                            '<span class="dmc-badge dmc-badge-' +
                            escapeHtml(
                                item.status
                            ) +
                            '">' +

                            escapeHtml(
                                statusLabel(
                                    item.status
                                )
                            ) +

                            '</span>' +

                            '</td>' +

                            '</tr>';
                    }
                );

                html += '</table>';
            }

            if (
                result.details.selector
            ) {

                html +=
                    '<div class="dmc-dkim-selector">' +
                    '<strong>Sélecteur testé :</strong> ' +
                    escapeHtml(
                        result.details.selector
                    ) +
                    (result.details.key_bits
                        ? ' · <strong>Taille :</strong> ' + escapeHtml(result.details.key_bits) + ' bits'
                        : '') +
                    '</div>';
            }
        }


        /*
         * DMARC
         */

        if (
            key === 'dmarc' &&
            result.details &&
            result.details.tags
        ) {

            const tags =
                result.details.tags;

            html +=
                '<table class="dmc-table">';

            html +=
                '<tr>' +
                '<th>Politique</th>' +
                '<td>' +
                escapeHtml(
                    tags.p ||
                    'non définie'
                ) +
                '</td>' +
                '</tr>';

            html +=
                '<tr>' +
                '<th>Politique sous-domaines</th>' +
                '<td>' +
                escapeHtml(
                    tags.sp ||
                    'hérite de p'
                ) +
                '</td>' +
                '</tr>';

            html +=
                '<tr>' +
                '<th>Pourcentage</th>' +
                '<td>' +
                escapeHtml(
                    tags.pct ||
                    '100'
                ) +
                ' %</td>' +
                '</tr>';

            html +=
                '<tr>' +
                '<th>Alignement DKIM</th>' +
                '<td>' +
                escapeHtml(
                    tags.adkim ||
                    'r'
                ) +
                '</td>' +
                '</tr>';

            html +=
                '<tr>' +
                '<th>Alignement SPF</th>' +
                '<td>' +
                escapeHtml(
                    tags.aspf ||
                    'r'
                ) +
                '</td>' +
                '</tr>';

            html +=
                '<tr>' +
                '<th>Rapports agrégés</th>' +
                '<td>' +
                escapeHtml(
                    tags.rua ||
                    'non configuré'
                ) +
                '</td>' +
                '</tr>';

            html += '</table>';

            if (result.details.inherited) {
                html +=
                    '<div style="margin-top:8px;font-size:12px;color:#1e40af;">' +
                    'ℹ️ Cet enregistrement DMARC est hérité depuis le domaine parent <code>' +
                    escapeHtml(result.details.host) +
                    '</code>.' +
                    '</div>';
            }

            if (result.details.external_reports && result.details.external_reports.length > 0) {
                html +=
                    '<div style="margin-top:14px;padding:12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;">' +
                    '<div style="font-size:13px;font-weight:600;margin-bottom:6px;">Autorisation des rapports externes (RFC 7489) :</div>' +
                    '<ul class="dmc-list" style="margin-top:0;">';
                result.details.external_reports.forEach(function (ext) {
                    html +=
                        '<li>Domaine <code>@' +
                        escapeHtml(ext.destination_domain) +
                        '</code> : ' +
                        (ext.is_authorized
                            ? '<span class="dmc-badge dmc-badge-ok">✓ Autorisé</span>'
                            : '<span class="dmc-badge dmc-badge-warning">! Non autorisé (hôte <code>' + escapeHtml(ext.verify_host) + '</code> manquant)</span>') +
                        '</li>';
                });
                html += '</ul></div>';
            }
        }


        /*
         * BIMI
         */

        if (
            key === 'bimi' &&
            result.details
        ) {

            if (result.details.configured && result.details.logo_url) {
                html +=
                    '<div class="dmc-bimi-preview">' +
                    '<img src="' + escapeHtml(result.details.logo_url) + '" alt="Logo BIMI" style="max-height:48px;max-width:80px;object-fit:contain;background:#fff;border-radius:4px;padding:4px;border:1px solid #cbd5e1;" onerror="this.style.display=\'none\'">' +
                    '<div>' +
                    '<div><strong>Logo de marque détecté :</strong> <a href="' + escapeHtml(result.details.logo_url) + '" target="_blank" rel="noopener noreferrer" style="color:#0284c7;text-decoration:underline;">Voir le fichier SVG</a></div>' +
                    (result.details.cert_url
                        ? '<div style="font-size:12px;color:#64748b;margin-top:2px;">Certificat VMC : <code>' + escapeHtml(result.details.cert_url) + '</code></div>'
                        : '<div style="font-size:12px;color:#94a3b8;margin-top:2px;">Aucun certificat VMC associé (nécessaire pour un affichage garanti sur Gmail/Yahoo)</div>') +
                    '<div style="font-size:12px;margin-top:4px;">Compatibilité DMARC : ' +
                    (result.details.dmarc_compatible
                        ? '<span class="dmc-badge dmc-badge-ok">✓ Compatible (DMARC strict)</span>'
                        : '<span class="dmc-badge dmc-badge-warning">! Incompatible (DMARC doit être en p=quarantine ou p=reject)</span>') +
                    '</div>' +
                    '</div>' +
                    '</div>';
            }
        }


        /*
         * MTA-STS
         */

        if (
            key === 'mtasts' &&
            result.details
        ) {

            if (result.details.url) {

                html +=
                    '<p>' +
                    '<strong>URL de la politique :</strong><br>' +
                    escapeHtml(
                        result.details.url
                    ) +
                    '</p>';
            }

            if (
                result.details.mode
            ) {

                html +=
                    '<table class="dmc-table">' +

                    '<tr>' +
                    '<th>Mode</th>' +
                    '<td>' +
                    escapeHtml(
                        result.details.mode
                    ) +
                    '</td>' +
                    '</tr>' +

                    '<tr>' +
                    '<th>Durée max_age</th>' +
                    '<td>' +
                    escapeHtml(
                        result.details.max_age
                    ) +
                    '</td>' +
                    '</tr>' +

                    '</table>';
            }

            if (
                result.details.policy
            ) {

                html +=
                    '<div class="dmc-record-title">' +
                    'Contenu de la politique' +
                    '</div>' +

                    '<div class="dmc-record">' +
                    escapeHtml(
                        result.details.policy
                    ) +
                    '</div>';
            }
        }


        /*
         * TLS-RPT
         */

        if (
            key === 'tlsrpt' &&
            result.details &&
            result.details.tags
        ) {

            html +=
                '<table class="dmc-table">';

            Object.keys(
                result.details.tags
            ).forEach(
                function (tag) {

                    html +=
                        '<tr>' +

                        '<th>' +
                        escapeHtml(tag) +
                        '</th>' +

                        '<td>' +
                        escapeHtml(
                            result.details.tags[tag]
                        ) +
                        '</td>' +

                        '</tr>';
                }
            );

            html += '</table>';
        }


        /*
         * Listes Noires (RBL)
         */

        if (
            key === 'rbl' &&
            result.details &&
            result.details.checks
        ) {
            html +=
                '<table class="dmc-table">' +
                '<tr>' +
                '<th>Adresse IP</th>' +
                '<th>Liste Noire</th>' +
                '<th>Statut</th>' +
                '</tr>';

            result.details.checks.forEach(function (c) {
                html +=
                    '<tr>' +
                    '<td><code>' + escapeHtml(c.ip) + '</code></td>' +
                    '<td>' + escapeHtml(c.rbl) + '</td>' +
                    '<td>' + (c.is_listed
                        ? '<span class="dmc-badge dmc-badge-error">❌ Listé (' + escapeHtml(c.return_ip) + ')</span>'
                        : '<span class="dmc-badge dmc-badge-ok">✓ Propre</span>') +
                    '</td>' +
                    '</tr>';
            });

            html += '</table>';
        }


        /*
         * DNSSEC
         */

        if (
            key === 'dnssec' &&
            result.details
        ) {
            html +=
                '<p style="margin-bottom:8px;">' +
                '<strong>Signature cryptographique DNSSEC : </strong>' +
                (result.details.enabled
                    ? '<span class="dmc-badge dmc-badge-ok">✓ Activé</span>'
                    : '<span class="dmc-badge dmc-badge-info">ℹ Non activé</span>') +
                '</p>';

            if (result.details.ds_records && result.details.ds_records.length > 0) {
                html +=
                    '<div class="dmc-record-title">Enregistrement(s) DS (Delegation Signer) :</div>';
                result.details.ds_records.forEach(function (ds) {
                    html +=
                        '<div class="dmc-record">' + escapeHtml(ds) + '</div>';
                });
            }
        }


        /*
         * DANE / TLSA
         */

        if (
            key === 'dane' &&
            result.details
        ) {
            html +=
                '<p style="margin-bottom:8px;">' +
                '<strong>Authentification DANE / TLSA : </strong>' +
                (result.details.enabled
                    ? '<span class="dmc-badge dmc-badge-ok">✓ Configuré</span>'
                    : '<span class="dmc-badge dmc-badge-info">ℹ Non configuré</span>') +
                '</p>';

            if (result.details.records && result.details.records.length > 0) {
                html +=
                    '<table class="dmc-table">' +
                    '<tr><th>Serveur MX</th><th>Enregistrement TLSA</th></tr>';
                result.details.records.forEach(function (rec) {
                    html +=
                        '<tr>' +
                        '<td>' + escapeHtml(rec.host) + '</td>' +
                        '<td><code>' + escapeHtml(rec.record) + '</code></td>' +
                        '</tr>';
                });
                html += '</table>';
            }
        }


        /*
         * Erreurs détectées
         */

        if (
            result.details &&
            result.details.errors &&
            result.details.errors.length
        ) {

            html +=
                '<div class="dmc-meaning dmc-meaning-error">' +

                '<strong>Problèmes détectés :</strong>' +

                '<ul class="dmc-list">';

            result.details.errors.forEach(
                function (item) {

                    html +=
                        '<li>' +
                        escapeHtml(item) +
                        '</li>';
                }
            );

            html +=
                '</ul></div>';
        }


        /*
         * Avertissements
         */

        if (
            result.details &&
            result.details.warnings &&
            result.details.warnings.length
        ) {

            html +=
                '<div class="dmc-meaning dmc-meaning-warning">' +

                '<strong>Points à surveiller :</strong>' +

                '<ul class="dmc-list">';

            result.details.warnings.forEach(
                function (item) {

                    html +=
                        '<li>' +
                        escapeHtml(item) +
                        '</li>';
                }
            );

            html +=
                '</ul></div>';
        }


        html += '</details>';

        html += '</div>';
        html += '</div>';

        return html;
    }


    form.addEventListener(
        'submit',
        async function (event) {

            event.preventDefault();

            errorBox.style.display =
                'none';

            resultsBox.style.display =
                'none';

            glossary.style.display =
                'none';

            loading.style.display =
                'block';

            submit.disabled =
                true;

            const data =
                new FormData(form);

            data.set(
                'domain',
                domainInput.value.trim()
            );

            data.set(
                'selector',
                selectorInput.value.trim()
            );

            try {

                const response =
                    await fetch(
                        ENDPOINT,
                        {
                            method: 'POST',
                            body: data,
                            credentials: 'same-origin'
                        }
                    );

                const result =
                    await response.json();

                if (
                    !response.ok ||
                    !result.success
                ) {

                    throw new Error(
                        result.error ||
                        'Une erreur est survenue.'
                    );
                }


                let html = '';

                const summaryClass =
                    'dmc-summary-' +
                    result.status;


                /*
                 * En-tête d'impression PDF
                 */

                const printDate = new Date().toLocaleDateString('fr-FR', {
                    day: 'numeric',
                    month: 'long',
                    year: 'numeric'
                });

                html +=
                    '<div class="dmc-print-header">' +
                    '<div style="font-size:22px;font-weight:700;color:#1e3a8a;">Audit de Sécurité E-mail & DNS</div>' +
                    '<div style="font-size:13px;color:#475569;margin-top:4px;">' +
                    'Domaine analysé : <strong>' + escapeHtml(result.domain) + '</strong> • Date : ' + escapeHtml(printDate) + ' • Rapport généré avec thierrylaval.dev' +
                    '</div></div>';

                /*
                 * Résumé général
                 */

                html +=
                    '<div class="dmc-summary ' +
                    summaryClass +
                    '">';

                html +=
                    '<div class="dmc-summary-title">';

                if (
                    result.status === 'ok'
                ) {

                    html +=
                        'Configuration correctement détectée';

                } else if (
                    result.status === 'warning'
                ) {

                    html +=
                        'Configuration en vérification';

                } else {

                    html +=
                        'Des problèmes ont été détectés';
                }

                html += '</div>';


                html +=
                    '<div class="dmc-summary-text">' +
                    'Analyse du domaine :' +
                    '</div>';


                html +=
                    '<div class="dmc-summary-domain">' +
                    escapeHtml(
                        result.domain
                    ) +
                    '</div>';


                html +=
                    '<div class="dmc-summary-counts">' +

                    escapeHtml(
                        result.summary.errors
                    ) +
                    ' erreur(s) · ' +

                    escapeHtml(
                        result.summary.warnings
                    ) +
                    ' avertissement(s)' +
                    '</div>';

                if (result.score !== undefined) {
                    html +=
                        '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:10px;">' +
                        '<div class="dmc-summary-score" style="margin-top:0;">' +
                        'Score de sécurité email : ' +
                        escapeHtml(result.score) + ' / 100' +
                        '</div>' +
                        '<button type="button" class="dmc-btn-print" onclick="dmcPrintReport()">' +
                        '🖨️ Imprimer / Exporter en PDF' +
                        '</button>' +
                        '</div>';
                }


                /*
                 * Explication globale
                 */

                html +=
                    '<div class="dmc-summary-explanation">';

                if (
                    result.status === 'ok'
                ) {

                    html +=
                        '<strong>En résumé :</strong><br>' +
                        'Les principaux enregistrements DNS liés à la messagerie ont été trouvés et ne présentent pas d’erreur détectée par ce test. Cela ne garantit toutefois pas à lui seul la délivrabilité de tous les emails.';

                } else if (
                    result.status === 'warning'
                ) {

                    html +=
                        '<strong>En résumé :</strong><br>' +
                        'La configuration contient des éléments fonctionnels mais certains points méritent une vérification. Ouvrez les résultats ci-dessous pour comprendre précisément lesquels.';

                } else {

                    html +=
                        '<strong>En résumé :</strong><br>' +
                        'Un ou plusieurs éléments importants de la configuration email présentent un problème. Les résultats ci-dessous expliquent ce qui a été détecté et indiquent les vérifications à effectuer.';
                }

                html += '</div>';

                html += '</div>';


                /*
                 * Suggestions globales d'enregistrements DNS
                 */
                if (result.suggested_dns && Object.keys(result.suggested_dns).length > 0) {
                    html +=
                        '<div class="dmc-suggested-box">' +
                        '<div class="dmc-suggested-title">⚡ Enregistrements DNS recommandés à publier / corriger</div>' +
                        '<p style="font-size:13px;color:#64748b;margin:0 0 14px;">Copiez-collez ces enregistrements directement dans la zone DNS de votre hébergeur :</p>';

                    Object.keys(result.suggested_dns).forEach(function(k) {
                        const sugg = result.suggested_dns[k];
                        html +=
                            '<div class="dmc-suggested-item">' +
                            '<div class="dmc-suggested-meta">' +
                            '<span class="dmc-suggested-badge">' + escapeHtml(sugg.type) + '</span> ' +
                            '<span>Hôte : <code>' + escapeHtml(sugg.name) + '</code></span> ' +
                            '<span style="margin-left:auto;color:#64748b;font-size:12px;">(' + escapeHtml(sugg.category || k) + ')</span>' +
                            '</div>' +
                            '<div class="dmc-record" style="background:#042f2e;color:#ccfbf1;display:flex;justify-content:space-between;align-items:center;gap:10px;">' +
                            '<span>' + escapeHtml(sugg.value) + '</span>' +
                            '<button type="button" class="dmc-btn-copy" onclick="dmcCopy(this, ' + JSON.stringify(sugg.value) + ')">Copier</button>' +
                            '</div>';
                        if (sugg.note) {
                            html +=
                                '<div class="dmc-suggested-note">💡 ' + escapeHtml(sugg.note) + '</div>';
                        }
                        html += '</div>';
                    });

                    html += '</div>';
                }


                /*
                 * Cartes
                 */

                html +=
                    '<div class="dmc-grid">';

                Object.keys(
                    result.results
                ).forEach(
                    function (key) {

                        html +=
                            renderCard(
                                key,
                                result.results[key]
                            );
                    }
                );

                html += '</div>';


                resultsBox.innerHTML =
                    html;

                resultsBox.style.display =
                    'block';

                glossary.style.display =
                    'block';


                resultsBox.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });


            } catch (error) {

                errorBox.textContent =
                    error.message ||
                    'Impossible d’effectuer le test.';

                errorBox.style.display =
                    'block';

            } finally {

                loading.style.display =
                    'none';

                submit.disabled =
                    false;
            }

        }
    );

    /*
     * Prise en compte automatique du paramètre d'URL (?domain=exemple.com)
     */
    (function checkUrlParams() {
        try {
            const urlParams = new URLSearchParams(window.location.search);
            const autoDomain = urlParams.get('domain') || urlParams.get('d') || urlParams.get('domaine');
            const autoSelector = urlParams.get('selector') || urlParams.get('s');
            if (autoDomain && domainInput) {
                domainInput.value = autoDomain.trim();
                if (autoSelector && selectorInput) {
                    selectorInput.value = autoSelector.trim();
                }
                setTimeout(function () {
                    form.dispatchEvent(new Event('submit', { cancelable: true }));
                }, 300);
            }
        } catch (e) {}
    })();

})();
</script>
</div>
</body>
</html>