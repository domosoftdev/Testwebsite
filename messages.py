# -*- coding: utf-8 -*-

MESSAGES = {
    'fr': {
        'scanning': "Analyse de l'hôte : {hostname}",
        'scan_error': "Erreur lors de l'analyse du serveur : {error}",
        'connectivity_error': "Impossible de se connecter à {hostname}: {error}",
        'certificate_chain': "\nChaîne de certification :",
        'partially_valid_chain': "  La chaîne de certification est PARTIELLEMENT VALIDE. Le certificat suivant n'a pas pu être vérifié : {unverified_issuer}",
        'valid_chain': "  La chaîne de certification est VALIDE.",
        'protocol_scan': "\nAnalyse des protocoles :",
        'supported': "  {protocol} : Pris en charge",
        'not_supported': "  {protocol} : Non pris en charge",
        'weak': " [FAIBLE]",
    },
    'en': {
        'scanning': "Scanning host: {hostname}",
        'scan_error': "Error while scanning server: {error}",
        'connectivity_error': "Could not connect to {hostname}: {error}",
        'certificate_chain': "\nCertificate Chain:",
        'partially_valid_chain': "  The certificate chain is PARTIALLY VALID. The following certificate could not be verified: {unverified_issuer}",
        'valid_chain': "  The certificate chain is VALID.",
        'protocol_scan': "\nProtocol Scan:",
        'supported': "  {protocol} : Supported",
        'not_supported': "  {protocol} : Not Supported",
        'weak': " [WEAK]",
    }
}
