/* nodejs client for saints sso
 * dependency:
 * express
 * express-session
 */
'use strict'
var http = require('http');
var url = require('url');
var util = require('util');

function SSOClient(config) {
    if (!(this instanceof SSOClient)) {
        return new SSOClient(config);
    }

    config = config || {};

    if (!config.authHost) throw new Error('Need auth server host');
    if (!config.authPort) throw new Error('Need auth port');
    if (typeof(config.authPort) !== 'number') throw new Error('Auth port must be number');
    if (!config.clientId) throw new Erro('Need register client id');
    if (!config.clientSecret) throw new Error('Need register client secret key');
    if (!config.redirectUri) throw new Error('Need uri after successfully login redirection');
    if (!config.filterPaths) throw new Error('Need filter pahts');
    if (!util.isArray(config.filterPaths)) throw new Error('Filter paths must be array');
    if (config.filterPaths.length == 0)  throw new Error('Need at least the login path to filter');
    this.authHost = config.authHost;
    this.authPort = config.authPort;
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
    this.filterPaths = config.filterPaths;
    this.authBase = 'http://' + this.authHost + ':' + this.authPort + '/oauth';
    this.authProtect = '/oauth/p';
    this.authProxyLogin = this.authBase + '/proxylogin';
    this.authProxyToken = this.authBase + '/proxylogin/proxytoken';
    this.userInfo = this.authProtect + '/userinfo';
    this.loginUri = config.loginUri || this.authBase+'/login';
    this.loginPath = config.loginUri?url.parse(config.loginUri).pathname:null;
}

SSOClient.prototype.hijackRequest = function () {
    var self = this;
    return function (req, res, next) {
        if (req.path === '/' && req.originalUrl.indexOf('&') === -1) {
            if (req.query.code) {
                res.redirect(self.authProxyToken + '?grant_type=authorization_code&code=' + req.query.code +
                    '&client_id=' + self.clientId +
                    '&client_secret=' + self.clientSecret +
                    '&redirect_uri=' + self.redirectUri);
            } else if (req.query.token) {
                req.session.token = req.query.token;
                res.redirect(self.redirectUri);
            } else {
                if (req.session.token) {
                    next();
                }else{
                    res.redirect(self.authProxyLogin+'?client_id='+self.clientId+
                        '&redirect_uri='+self.redirectUri+
                        '&login_uri='+self.loginUri);
                }
            }
        }else if(loginPath && req.path == loginPath){
            if(req.session.token){
                res.redirect(self.redirectUri);
            }else{
                next();
            }
        } else{
            var needFilter = false;
            self.filterPaths.forEach(function(path){
                if(path === req.path){
                    needFilter = true;
                }
            })

            if(needFilter){
                if (req.session.token) {
                    next();
                }else{
                    res.redirect(self.authProxyLogin+'?client_id='+self.clientId+
                        '&redirect_uri='+self.redirectUri+
                        '&login_uri='+self.loginUri);
                }
            }else{
                next();
            }
        }
    }
}

SSOClient.prototype.getUserInfo = function () {
    var self = this;
    return function (req, res, next) {
        if(!req.session.token){
            res.status(400).send('Not authorized');
        }else{
            httpHelper(self,self.userInfo+'?access_token='+req.session.token,function(err,data){
                if(err){
                    next(err);
                }else{
                    req.userInfo = data;
                    next();
                }
            });
        }
    }
}

function httpHelper(ssoClient,path,callback){
    var opt = {
        hostname:ssoClient.authHost,
        port:ssoClient.authPort,
        path:path,
        method:'GET'
    };

    var req = http.request(opt,function(res){
       res.on('data',function(chunk){
           var data = JSON.parse(chunk.toString());
           callback(null,data);
       });

       res.on('error',function(err){
           callback(err);
       })
    });
    req.end();
}

module.exports = SSOClient;

