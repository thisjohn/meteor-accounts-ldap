'use strict';

const _ = Npm.require('lodash');
const ActiveDirectory = Npm.require('activedirectory');
const Future = Npm.require('fibers/future');
const winston = Npm.require('winston');

/**
 * Logger
 */
const logger = new (winston.Logger)({
    level: 'debug',
});
if (Meteor.settings.ldap.debug) {
    logger.add(winston.transports.Console);
}

/**
 * Manage LDAP settings
 */
class LdapConfigLoader {

    constructor() {
        const defaultSettings = {
            user: {
                mappings: []
            }
        };

        this.settings = _.defaultsDeep(Meteor.settings.ldap || {}, defaultSettings);

        // TODO: Default user doc
        const site = Meteor.settings.public.site;
        this.defaultUserDoc = {
            profile: {
                teams: [site],
                site,
                firstName: "",
                lastName: "",
                picUrl: "",
            }
        };
    }

    findUniqueMapping() {
        const target = _.find(this.settings.user.mappings, function (it) {
            return it.unique;
        });
        return target || {attr: 'uid', key: 'uid', unique: true};
    }

    transformUserDoc(userEntry, isNew) {
        const doc = isNew ? _.cloneDeep(this.defaultUserDoc) : {};

        _.forEach(this.settings.user.mappings, function (it) {
            if (!isNew && it.unique) {
                return;
            }

            const value = !!it.attr ? _.get(userEntry, it.attr) : "";
            _.set(doc, it.key, value);
        });
        return doc;
    }
}
const ldapConfigLoader = new LdapConfigLoader();

/**
 * Find and authenticate user through LDAP
 */
class LdapAgent {

    constructor() {
        this.ad = ActiveDirectory({
            url: ldapConfigLoader.settings.url,
            baseDN: ldapConfigLoader.settings.baseDn,
            username: ldapConfigLoader.settings.bindCn,
            password: ldapConfigLoader.settings.bindPassword,
            tlsOptions: ldapConfigLoader.settings.tlsOptions || {}
        });
    }

    static sanitizeForSearch(s) {
        // Escape search string for LDAP according to RFC4515
        s = s.replace('\\', '\\5C');
        s = s.replace('\0', '\\00');
        s = s.replace('*','\\2A' );
        s = s.replace('(','\\28' );
        s = s.replace(')','\\29' );
        return s;
    }

    findUser(username) {
        username = LdapAgent.sanitizeForSearch(username);
        logger.debug('Find user "%s"', username);

        const userFuture = new Future();

        const mapping = ldapConfigLoader.findUniqueMapping();
        const opts = {
            dn: ldapConfigLoader.settings.user.dn || ldapConfigLoader.settings.baseDn,
            filter: `${mapping.attr}=${username}`
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
                logger.warn('User "%s" not found', username);
                userFuture.return(false);
                return;
            }
        }.bind(this));

        return userFuture.wait();
    }

    authenticate(userDn, password) {
        logger.debug('Authenticate "%s"', userDn);

        const authenticateFuture = new Future();

        this.ad.authenticate(userDn, password, function(err, auth) {
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

        return authenticateFuture.wait();
    }
}

/**
 * Main LDAP login handler
 */
Accounts.registerLoginHandler('ldap', function(request) {
    if (!request.ldap) { return undefined; }
    logger.info("Login with LDAP");

    // Find user from LDAP
    const ldapAgent = new LdapAgent();
    const userEntry = ldapAgent.findUser(request.username);
    if (!userEntry) {
        throw new Meteor.Error(403, 'User not found');
    }

    // Authenticate user
    const authenticated = ldapAgent.authenticate(userEntry.dn, request.pass);
    if (!authenticated || (request.pass === '')) {
        throw new Meteor.Error(403, 'Invalid credentials');
    }

    // Update/Insert Meteor user
    const mapping = ldapConfigLoader.findUniqueMapping();
    const value = _.get(userEntry, mapping.attr);
    if (!value) {
        throw new Meteor.Error(403, 'Missing matched unique mapping');
    }

    let user = Meteor.users.findOne({[mapping.key]: value});
    if (user) {
        const doc = ldapConfigLoader.transformUserDoc(userEntry);
        Meteor.users.update(user._id, {$set: doc});

        logger.debug('Updated user doc', JSON.stringify(doc));
    }
    else {
        user = ldapConfigLoader.transformUserDoc(userEntry, true);
        user._id = Accounts.createUser(user);

        logger.debug('Created user', JSON.stringify(user));
    }

    return {
        userId: user._id
    };
});
