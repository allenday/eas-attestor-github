const fs = require('fs');
const path = require('path');

const serverIndexPath = path.join(__dirname, '../../../src/generated/server/index.js');

// Read the current index.js file
const content = fs.readFileSync(serverIndexPath, 'utf8');

// Add dotenv require at the beginning if it's not already there
if (!content.includes("require('dotenv').config()")) {
  const newContent = "require('dotenv').config();\n" + content;
  fs.writeFileSync(serverIndexPath, newContent, 'utf8');
  console.log('✅ Added dotenv.config() to server index.js');
} else {
  console.log('✅ dotenv.config() already present in server index.js');
}