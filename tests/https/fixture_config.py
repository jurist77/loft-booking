"""CI ONLY issuer override; never imported by production workflow/controller."""
import copy


def internal(config, lifetime='30m'):
    value=copy.deepcopy(config)
    value['apps']['tls']['automation']['policies'][0]['issuers']=[{'module':'internal','lifetime':lifetime}]
    value['apps']['tls']['automation']['renew_interval']='2s'
    value['apps']['pki']={'certificate_authorities':{'local':{'install_trust':False}}}
    return value
