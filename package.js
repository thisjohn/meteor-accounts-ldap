Package.describe({
    'summary': 'Meteor account login via LDAP using active directory',
    'version': '0.0.1',
    'git': 'https://github.com/kaneoh/meteor-accounts-ldap',
    'name': 'kaneoh:meteor-accounts-ldap',
});

Npm.depends({
    'activedirectory': '0.7.2',
    'winston': '2.3.1',
    'lodash': '4.17.4',
});

Package.onUse(function (api) {
    var client = 'client';
    var server = 'server';
    var both = [client, server];

    api.use(['accounts-base'], both);
    api.imply('accounts-base', both);

    api.addFiles('ldap_client.js', client);
    api.addFiles('ldap_server.js', server);
});
