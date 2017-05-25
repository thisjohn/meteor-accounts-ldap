Meteor.loginWithLdap = function (username, password, callback) {
    const requestArguments = {
        username: username,
        pass: password,  // Use pass instead password to prevent matching accounts-password
        ldap: true
    };

    // This will hook into our login handler for ldap
	Accounts.callLoginMethod({
        methodArguments: [requestArguments],
        userCallback: function (error, result) {
            callback && callback(error, result);
        }
    });
};
