// 初始化配置文件
const mongoClient = require("mongodb").MongoClient;
const config = require("./utils/config").readConfigSync();
const mongoPath = "mongodb://" + config["db"]["user"] + ":" + config["db"]["pwd"] + "@" + config["db"]["ip"] + ":" + config["db"]["port"] + "/" + config["db"]["db"]["business"];
const {ObjectID} = require("mongodb");

const crypto = require("crypto");

let token = require("./token/jar");

// 初始化Express服务器
const express= require("express");
let app = express();

// 使用bodyparser处理POST请求
const bodyparser = require("body-parser");
app.use(bodyparser.urlencoded({extended: true}));
app.use(bodyparser.json());

// 允许跨域请求
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cache-Control","no-cache");
    res.header("Access-Control-Allow-Methods","POST,GET,DELETE,OPTIONS");
    if (req.method.toLowerCase() === 'options') {
        res.sendStatus(200);  // 让options尝试请求快速结束
    } else {
        next();
    }
});

app.use((req, res, next) => {
    if(req.query.token && !req.headers.authorization) req.headers.authorization = req.query.token;
    if(!req.headers.referer) req.headers.referer = "/";
    next();
});

/**
 * 使验证服务器满足RESTful-JSONP规范
 */

let sha256 = (context) => {
    return crypto.createHash("sha256").update(context + config.auth.salt).digest("base64");
};

async function auth(ip, username, password, long = false) {
    let db = await mongoClient.connect(mongoPath, {useUnifiedTopology: true});
    let userCol = db.db(config["db"]["db"]["business"]).collection("user");
    let counter = await userCol.find({username: username, password: sha256(password)}).toArray();
    if(counter.length > 0) {
         return await token.generate(ip, counter[0]._id, counter[0].authority, long);
    } else {
        return {token: ""};
    }
}

app.use("/auth", async (req, res) => {
    let result = {};
    let ip =  req.headers['x-forwarded-for'] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        req.connection.socket.remoteAddress;
    if(req.method.toLowerCase() === "delete") {
        if(req.headers.authorization) {
            let result = await token.expire(req.query.origin || ip, req.headers.authorization);
        }
        result.token = "";
    }
    else if(req.headers.authorization) { // 带有token
        if(req.query.update) { // 更新token
            let info = await token.update(req.query.origin || ip, req.headers.authorization);
            if(info.nModified === 1) { // 更新成功
                result.token = info.token;
                result.expires = info.expires;
                result.needUpdate = false;
            } else if(info.ok === 1) { // 不需要更新
                result.token = req.headers.authorization;
                result.expires = info.expires;
                result.needUpdate = false;
            } else { // token无效
                result.token = "";
            }
        }
        else {
            let info = await token.verify(req.query.origin || ip, req.headers.authorization, parseInt(req.query.authority || "0"));
            if(info.valid) { // token有效
                result.token = req.headers.authorization;
                result.expires = info.expires;
                result.uid = info.uid;
                result.authority = info.authority;
                result.needUpdate = info.needUpdate;
            } else { // token无效
                result.token = "";
            }
        }
    }
    else { // 不带有token
        if(req.query.username && req.query.password) { // 用户名密码在query中
            result = await auth(req.query.origin || ip, req.query.username, req.query.password, req.query.long);
        }
        else if(req.body.username && req.body.password) {
            result = await auth(req.query.origin || ip, req.body.username, req.body.password, req.body.long);
        }
        else { // 进入登陆页面
            res.end("login page");
            return;
        }
    }
    if(req.query.json) { // JSONP返回
        res.end(JSON.stringify(result));
    }
    else { // 重定向返回
        if(result.token) {
            if(req.query.success) {
                res.setHeader("location", req.query.success + "?token=" + result.token + "&expires=" + result.expires + "&needUpdate=" + result.needUpdate);
            } else {
                res.setHeader("location", req.headers.referer + "?token=" + result.token + "&expires=" + result.expires + "&needUpdate=" + result.needUpdate);
            }
        } else {
            if(req.query.fail) {
                res.setHeader("location", req.query.fail);
            } else {
                res.setHeader("location", "auth");
            }
        }
        res.sendStatus(301);
    }
});



// 未经过任何路由，返回404同时返回错误信息

app.use((req, res) => {
    res.status(404);
    res.end(JSON.stringify({
        error: "No Matching API."
    }));
});

// 监听
app.listen(config.auth.port);
