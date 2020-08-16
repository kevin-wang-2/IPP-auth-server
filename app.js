// 初始化配置文件
const config = require("./utils/config");

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
    res.header("Access-Control-Allow-Methods","PUT,PATCH,POST,GET,DELETE,OPTIONS");
    if (req.method.toLowerCase() === 'options') {
        res.sendStatus(200);  // 让options尝试请求快速结束
    } else {
        next();
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
app.listen(config.readConfigSync().port);
