'use strict';

const _ = Npm.require('lodash');

const defaultLdapSettings = {
    userOption: {
        mappings: []
    }
};
const ldapSettings = _.merge({}, defaultLdapSettings,  Meteor.settings.ldap || {});
const ldapUserOption = ldapSettings.userOption;
if (!ldapSettings.enabled) {
    return;
}

const ActiveDirectory = Npm.require('activedirectory');
const Future = Npm.require('fibers/future');
const winston = Npm.require('winston');

// Logger
const logger = new (winston.Logger)({
    level: 'debug',
});
if (ldapSettings.debug) {
    logger.add(winston.transports.Console);
}

//
function findUniqueMapping() {
    const target = _.find(ldapUserOption.mappings, function (it) {
        return it.unique;
    });
    return target || {attr: 'uid', key: 'uid', unique: true};
}

function transformUserDoc(userEntry) {
    const doc = {};

    // TODO: default settings
    const site = Meteor.settings.public.site;
    if (!!site) {
        _.assign(doc, {profile: {teams: [site], site}});
    }

    _.forEach(ldapUserOption.mappings, function (it) {
        const value = !!it.attr ? _.get(userEntry, it.attr) : "";
        _.set(doc, it.key, value);
    });
    return doc;
}

//
class UserQuery {

    constructor(username) {
        this.ad = ActiveDirectory({
            url: ldapSettings.url,
            baseDN: ldapSettings.baseDn,
            username: ldapSettings.bindCn,
            password: ldapSettings.bindPassword,
            tlsOptions: ldapSettings.tlsOptions || {}
        });
        this.username = this.sanitizeForSearch(username);
    }

    sanitizeForSearch(s) {
        // Escape search string for LDAP according to RFC4515
        s = s.replace('\\', '\\5C');
        s = s.replace('\0', '\\00');
        s = s.replace('*','\\2A' );
        s = s.replace('(','\\28' );
        s = s.replace(')','\\29' );
        return s;
    }

    findUser() {
        logger.debug('Find user "%s"', this.username);

        const userFuture = new Future();

        const mapping = findUniqueMapping();
        const opts = {
            dn: ldapUserOption.dn || ldapSettings.baseDn,
            filter: `${mapping.attr}=${this.username}`
        };

        this.ad.findUser(opts, '', function(err, userEntry) {
            if (userFuture.isResolved()) {
                // If auth failed, this function may be executed twice!?
                return;
            }

            if (err) {
                logger.error('ad.findUser error', JSON.stringify(err));
                userFuture.return(false);
                return;
            }

            if (userEntry) {
                logger.debug('Found', JSON.stringify(userEntry));
                userFuture.return(userEntry);
                return;
            }
            else {
                logger.warn('User "%s" not found', this.username);
                userFuture.return(false);
                return;
            }
        }.bind(this));

        return this.userEntry = userFuture.wait();
    }

    authenticate(password) {
        logger.debug('Authenticate "%s"', this.userEntry.dn);

        const authenticateFuture = new Future();

        this.ad.authenticate(this.userEntry.dn, password, function(err, auth) {
            if (err) {
                logger.error('ad.authenticate error', JSON.stringify(err));
                authenticateFuture.return(false);
                return;
            }

            if (auth) {
                logger.debug('Authenticated');
                authenticateFuture.return(true);
            }
            else {
                logger.warn('Authentication failed');
                authenticateFuture.return(false); 
            }
        }.bind(this));

        return this.authenticated = authenticateFuture.wait();
    }

    isValid() {
        return !!this.userEntry && this.authenticated;
    }
}

// Register login handler
Accounts.registerLoginHandler('ldap', function(request) {
    if (!request.ldap) { return undefined; }
    logger.debug("Start to login with LDAP");

    // Find user from LDAP
    const userQuery = new UserQuery(request.username);
    const userEntry = userQuery.findUser();
    if (!userEntry) {
        throw new (Meteor.Error)(403, 'User not found');
    }

    // Authenticate user
    const authenticated = userQuery.authenticate(request.pass);
    if (!authenticated || (request.pass === '')) {
        throw new (Meteor.Error)(403, 'Invalid credentials');
    }

    // Update/Insert Meteor user
    const mapping = findUniqueMapping();
    const value = _.get(userEntry, mapping.attr);
    if (!value) {
        throw new (Meteor.Error)(403, 'Missing matched unique mapping');
    }

    let user = Meteor.users.findOne({[mapping.key]: value});
    if (user) {
        logger.debug('Updated user', JSON.stringify(user));
    }
    else {
        user = transformUserDoc(userEntry);
        user._id = Accounts.createUser(user);
        Accounts.setPassword(user._id, request.pass);

        logger.debug('Created user', JSON.stringify(user));
    }

    return {
        userId: user._id
    };
});
