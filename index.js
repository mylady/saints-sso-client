/* nodejs client for saints sso
 * dependency:
 * express
 * express-session
 */
'use strict';
var http = require('http')
    , url = require('url')
    , util = require('util')
    , querystring = require('querystring');

function SSOClient(config) {
    if (!(this instanceof SSOClient)) {
        return new SSOClient(config);
    }

    this.config = config || {};

    if (!this.config.authHost) throw new Error('Need auth server host');
    if (!this.config.authPort) throw new Error('Need auth port');
    if (typeof(this.config.authPort) !== 'number') throw new Error('Auth port must be number');
    if (!this.config.clientId) throw new Erro('Need register client id');
    if (!this.config.clientSecret) throw new Error('Need register client secret key');
    if (!this.config.redirectUri) throw new Error('Need uri after successfully login redirection');
    if (!this.config.filterPaths) throw new Error('Need filter pahts');
    if (!util.isArray(this.config.filterPaths)) throw new Error('Filter paths must be array');
    if (this.config.filterPaths.length == 0)  throw new Error('Need at least the one path to filter');
    this.authHost = this.config.authHost;
    this.authPort = this.config.authPort;
    this.clientId = this.config.clientId;
    this.clientSecret = this.config.clientSecret;
    this.redirectUri = this.config.redirectUri;
    this.filterPaths = this.config.filterPaths;
    this.authBase = 'http://' + this.authHost + ':' + this.authPort + '/oauth';
    this.authValidate = this.authBase + '/v';
    this.authResource = this.authBase + '/p';
    this.authService = this.authBase + '/s';
    this.authProxyLogin = this.authBase + '/proxylogin';
    this.authProxyToken = this.authBase + '/proxylogin/proxytoken';
    this.userInfo = this.authResource + '/userinfo';
    this.nativeLogin = this.config.loginUri ? true : false;
    this.loginUri = this.config.loginUri;
    this.ssoLoginUri = this.authBase + '/login' + '?client_id=' + this.clientId + '&redirect_uri=' + this.redirectUri;
    this.logoutUri = this.authBase + '/logout';
    this.loginPath = this.config.loginUri ? url.parse(this.config.loginUri).pathname : null;
}

SSOClient.prototype.hijackRequest = function () {
    var self = this;
    return function (req, res, next) {
        req.ssoClient = self;
        if (req.path === '/' && req.originalUrl.indexOf('&') === -1) {
            if (req.query.code && !req.query.error) {
                getToken(self, req, res);
            } else if (req.query.token) {
                req.session.token = req.query.token;
                res.redirect(self.redirectUri);
            } else {
                if (req.session.token) {
                    validateToken(self, req.session.token, function (err) {
                        if (err) {
                            req.session.token = null;
                            getCode(self, res, req.xhr);
                        } else {
                            next();
                        }
                    });
                } else {
                    getCode(self, res, req.xhr);
                }
            }
        } else if (self.loginPath && req.path == self.loginPath) {
            if (req.session.token) {
                validateToken(self, req.session.token, function (err) {
                    if (err) {
                        req.session.token = null;
                        if (self.nativeLogin) {
                            res.redirect(self.loginUri);
                        } else {
                            res.redirect(self.ssoLoginUri);
                        }
                    } else {
                        res.redirect(self.redirectUri);
                    }
                });
            } else {
                if (self.nativeLogin) {
                    next();
                } else {
                    res.redirect(self.ssoLoginUri);
                }
            }
        } else {
            var needFilter = false;
            self.filterPaths.forEach(function (path) {
                if (path === req.path) {
                    needFilter = true;
                }
            });

            if (needFilter) {
                if (req.session.token) {
                    validateToken(self, req.session.token, function (err) {
                        if (err) {
                            req.session.token = null;
                            getCode(self, res, req.xhr);
                        } else {
                            next();
                        }
                    });
                } else {
                    getCode(self, res, req.xhr);
                }
            } else {
                next();
            }
        }
    }
};


function getCode(ssoClient, res, isXhr) {
    if (isXhr) {
        res.status(403).json({
            error:'not authorized'
        });
    } else {
        res.redirect(ssoClient.authProxyLogin + '?client_id=' + ssoClient.clientId +
            '&redirect_uri=' + ssoClient.redirectUri +
            '&login_uri=' + (ssoClient.nativeLogin ? querystring.escape(ssoClient.loginUri) : querystring.escape(ssoClient.ssoLoginUri)));
    }
}

function getToken(ssoClient, req, res) {
    res.redirect(ssoClient.authProxyToken + '?grant_type=authorization_code&code=' + req.query.code +
        '&client_id=' + ssoClient.clientId +
        '&client_secret=' + ssoClient.clientSecret +
        '&redirect_uri=' + querystring.escape(ssoClient.redirectUri));
}

function validateToken(ssoClient, token, done) {
    httpHelper(ssoClient, ssoClient.authValidate + '?access_token=' + token, function (err) {
        if (err) {
            done(err);
        } else {
            done();
        }
    });
}

SSOClient.prototype.getUserInfo = function () {
    var self = this;
    return function (req, res, next) {
        if (!req.session.token) {
            var err = new Error('Not authorized');
            next(err);
        } else {
            httpHelper(self, self.userInfo + '?access_token=' + req.session.token, function (err, data) {
                if (err) {
                    if (err.code && err.code === 403) {
                        res.redirect(self.loginUri);
                    } else {
                        next(err);
                    }
                } else {
                    req.userInfo = data;
                    next();
                }
            });
        }
    }
};

SSOClient.prototype.logout = function (hasNext) {
    var self = this;
    return function (req, res, next) {
        if (req.session.token) {
            httpHelper(self, self.logoutUri + '?access_token=' + req.session.token, function (err) {
                if (err) {
                    next(err);
                } else {
                    req.session.token = null;
                    if (hasNext) {
                        next();
                    } else {
                        res.redirect(self.nativeLogin ? self.loginUri : self.ssoLoginUri);
                    }
                }
            })
        }
    }
};

function httpHelper(ssoClient, path, done) {
    var opt = {
        hostname: ssoClient.authHost,
        port: ssoClient.authPort,
        path: path,
        method: 'GET'
    };

    var req = http.request(opt, function (res) {
        if (res.statusCode >= 400) {
            var err = new Error();
            err.code = res.statusCode;
            done(err);
        } else {
            res.on('data', function (chunk) {
                var data = JSON.parse(chunk.toString());
                done(null, data);
            });
        }
    });
    req.end();
}

module.exports = SSOClient;

