'use strict';

if (!Meteor.settings.ldap) {
    return;
}

const ActiveDirectory = Npm.require('activedirectory');
const Future = Npm.require('fibers/future');
const winston = Npm.require('winston');

// Logger
var logger = new (winston.Logger)({
    level: 'debug',
});
if (Meteor.settings.ldap.debug) {
    logger.add(winston.transports.Console);
}

class UserQuery {

    constructor(username) {
        this.ad = ActiveDirectory({
            url: Meteor.settings.ldap.url,
            baseDN: Meteor.settings.ldap.baseDn,
            username: Meteor.settings.ldap.bindCn,
            password: Meteor.settings.ldap.bindPassword,
            tlsOptions: Meteor.settings.ldap.tlsOptions || {}
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

        const opts = {
            dn: Meteor.settings.ldap.usersDn || Meteor.settings.ldap.baseDn,
            filter: `uid=${this.username}`
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
                logger.debug(JSON.stringify(userEntry));
                userFuture.return(userEntry);
                return;
            }
            else {
                logger.warn('User "%s" not found', this.username);
                userFuture.return(false);
                return;
            }
        }.bind(this));

        const userEntry = userFuture.wait();
        if (!userEntry) {
            throw new (Meteor.Error)(403, 'User not found'); 
        }
        return this.userEntry = userEntry;
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
                logger.debug('Authenticated!');
                authenticateFuture.return(true);
            }
            else {
                logger.warn('Authentication failed!');
                authenticateFuture.return(false); 
            }
        }.bind(this));

        const success = authenticateFuture.wait(); 
        if (!success || (password === '')) {
            throw new (Meteor.Error)(403, 'Invalid credentials');
        }
        return this.authenticated = success;
    }
}

// Register login handler
Accounts.registerLoginHandler('ldap', function(request) {
    if (!request.ldap) { return undefined; }

    // 1. find user
    const userQuery = new UserQuery(request.username);
    const userEntry = userQuery.findUser();

    // 2. authenticate user
    userQuery.authenticate(request.pass);

    // 3. update database
    let userId = undefined;
    const user = Meteor.users.findOne({dn: userEntry.dn});
    if (user) {
        userId = user._id;
        //Meteor.users.update(userId, {$set: userEntry});
    }
    else {
        //userId = Meteor.users.insert(userEntry);
        throw new (Meteor.Error)(403, 'Meteor user not found');
    }

    /*
    const stampedToken = Accounts._generateStampedLoginToken();
    const hashStampedToken = Accounts._hashStampedToken(stampedToken);
    Meteor.users.update(userId, {$push: {'services.resume.loginTokens': hashStampedToken}});
    */

    return {
        userId,
        //token: stampedToken.token,
        //tokenExpires: Accounts._tokenExpiration(hashStampedToken.when)
    };
});
