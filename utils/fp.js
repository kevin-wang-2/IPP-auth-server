/**
 * 函数柯里化
 * @param fn
 * @params 变长参数，函数的已知参数
 * @returns {Function}
 */
function curry(fn) {
    // 1. 取出原argument, 避免域混淆
    let arg = [];
    for(let i = 0; i < arguments.length; i++) arg.push(arguments[i]);

    // 2. 构造返回函数
    return function() {
        for(let i = 0; i < arguments.length; i++) arg.push(arguments[i]);

        // TODO: 解决函数上下文问题
        return fn.apply(this, arg);
    }
}