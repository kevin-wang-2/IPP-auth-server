const fs = require("fs");

module.exports = {
    readConfigSync: () => {
        return JSON.parse(fs.readFileSync("config/config.json").toString());
    },
    writeConfigSync: (input) => {
        let JSONOriginal = JSON.parse(fs.readFileSync("config/config.json").toString());
        for (const key in input) {
            if(input.hasOwnProperty(key))
                JSONOriginal[key] = input[key];
        }
        fs.writeFileSync("config/config.json", JSON.stringify(JSONOriginal));
    }
};