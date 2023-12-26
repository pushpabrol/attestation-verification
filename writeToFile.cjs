// fileWriter.js
const fs = require('fs');
const path = require('path');

function writeToFile(fileName, content, callback) {
    const filePath = path.join(__dirname, fileName);
    try {
        fs.writeFileSync(filePath, content);
    } catch (error) {
        console.log(error);
        throw error;
    }
    
}

module.exports = writeToFile;